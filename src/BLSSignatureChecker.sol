// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {BitmapUtils} from "./libraries/BitmapUtils.sol";
import {BN254} from "./libraries/BN254.sol";

import "./BLSSignatureCheckerStorage.sol";

/**
 * @title BLS 聚合签名检查器 - 用于验证来自 BLSRegistry 操作员的 BLS 聚合签名
 * @author Layr Labs, Inc.
 * @notice Terms of Service: https://docs.eigenlayer.xyz/overview/terms-of-service
 *
 * === 合约功能概述 ===
 * 本合约是 EigenLayer 中间件的核心组件，负责验证多个操作员对消息的 BLS 聚合签名。
 * 它支持跨多个 Quorum（法定人数组）的签名验证，并计算签名者的质押权重。
 *
 * === 核心创新：非签名者模型 ===
 * 传统方法需要提供所有签名者的信息（可能有数百个操作员），gas 消耗巨大。
 * 本合约采用"非签名者模型"：
 * 1. 从链上获取每个 quorum 的总聚合公钥（APK，包含所有注册操作员）
 * 2. 减去未签名操作员的公钥
 * 3. 得到签名者的聚合公钥：签名者 APK = 总 APK - 非签名者 APK
 * 这样只需提交少数未签名者的信息，大幅降低 gas 成本。
 *
 * === BLS 签名聚合原理 ===
 * BLS 签名支持聚合：如果操作员 1 的签名是 σ1，操作员 2 的签名是 σ2，
 * 则聚合签名 σ = σ1 + σ2 可以用聚合公钥 apk = pk1 + pk2 一次性验证。
 * 验证等式：e(σ, G2) = e(H(m), apk_G2)
 * 其中 e 是双线性配对，H 是哈希到曲线点的函数。
 *
 * === 关键安全机制 ===
 * - 使用 referenceBlockNumber 查询历史状态，防止状态变更攻击
 * - 要求非签名者公钥严格升序排序，防止重复计算
 * - 验证所有历史索引指向的数据与链上存储匹配，防止篡改
 * - 使用 Fiat-Shamir 启发式生成挑战值，防止恶意构造攻击
 */
contract BLSSignatureChecker is BLSSignatureCheckerStorage {
    using BN254 for BN254.G1Point;

    /// MODIFIERS

    /**
     * @notice 仅允许注册协调器的所有者调用
     * @dev 用于保护只有 AVS 管理员才能执行的敏感操作
     */
    modifier onlyCoordinatorOwner() {
        require(
            msg.sender == Ownable(address(registryCoordinator)).owner(),
            OnlyRegistryCoordinatorOwner()
        );
        _;
    }

    /// CONSTRUCTION

    /**
     * @notice 构造函数 - 初始化 BLS 签名检查器
     * @param _registryCoordinator 注册协调器合约地址
     *
     * @dev 通过继承 BLSSignatureCheckerStorage 来初始化所有依赖合约的引用：
     *      - registryCoordinator: 管理操作员注册和 quorum 成员关系
     *      - blsApkRegistry: 存储每个 quorum 的 BLS 聚合公钥（APK）
     *      - stakeRegistry: 跟踪操作员在各 quorum 的质押权重
     *      - delegation: EigenLayer 核心合约，管理委托关系
     *      这些引用在合约部署后不可变更（immutable）
     */
    constructor(
        ISlashingRegistryCoordinator _registryCoordinator
    ) BLSSignatureCheckerStorage(_registryCoordinator) {}

    /// VIEW

    /// @inheritdoc IBLSSignatureChecker
    /**
     * @notice 核心功能 - 检查 BLS 聚合签名的有效性
     * @param msgHash 被签名的消息哈希（32 字节）
     * @param quorumNumbers 参与签名的 quorum 编号列表（字节数组，如 [0, 1, 5]）
     * @param referenceBlockNumber 参考区块号 - 用于查询该区块时的操作员集合和质押状态
     * @param params 非签名者信息和聚合签名数据结构
     * @return stakeTotals 各 quorum 的总质押和签名质押统计
     * @return signatoryRecordHash 签名者记录哈希（用于欺诈证明）
     *
     * === 函数工作流程概览 ===
     * 阶段 1: 参数验证 - 检查输入数据的完整性和合法性
     * 阶段 2: 处理非签名者 - 累加所有非签名者的公钥（稍后取反）
     * 阶段 3: 构建签名者 APK - 加上各 quorum 的总 APK，并计算签名质押
     * 阶段 4: BLS 签名验证 - 使用双线性配对验证聚合签名
     * 阶段 5: 生成签名者记录 - 返回用于欺诈证明的哈希
     *
     * === 关键术语解释 ===
     * - APK (Aggregate Public Key): 聚合公钥，多个公钥相加的结果
     * - Quorum: 法定人数组，一组具有特定质押要求的操作员集合
     * - operatorId: 操作员唯一标识符，等于其 BLS 公钥的哈希值
     * - referenceBlockNumber: 必须是历史区块，用于确保验证的是某个特定时刻的状态
     *
     * === Gas 优化设计 ===
     * 本函数采用"非签名者模型"而非"签名者模型"，原因：
     * - 典型场景：200 个注册操作员，195 个签名，5 个未签名
     * - 签名者模型需提供 195 个操作员的数据（~3.9M gas）
     * - 非签名者模型仅需提供 5 个操作员的数据（~100K gas）
     * - Gas 节省：约 97.5%
     */
    function checkSignatures(
        bytes32 msgHash,
        bytes calldata quorumNumbers,
        uint32 referenceBlockNumber,
        NonSignerStakesAndSignature memory params
    ) public view returns (QuorumStakeTotals memory, bytes32) {
        // ===================================================================
        // 阶段 1: 参数验证
        // ===================================================================

        // 1.1 验证至少有一个 quorum 参与签名
        require(quorumNumbers.length != 0, InputEmptyQuorumNumbers());

        // 1.2 验证所有与 quorum 相关的数组长度一致
        // 确保为每个 quorum 都提供了对应的 APK、索引和质押信息
        require(
            (quorumNumbers.length == params.quorumApks.length)
                && (quorumNumbers.length == params.quorumApkIndices.length)
                && (quorumNumbers.length == params.totalStakeIndices.length)
                && (quorumNumbers.length == params.nonSignerStakeIndices.length),
            InputArrayLengthMismatch()
        );

        // 1.3 验证非签名者数据的一致性
        // nonSignerPubkeys 和 nonSignerQuorumBitmapIndices 必须一一对应
        require(
            params.nonSignerPubkeys.length == params.nonSignerQuorumBitmapIndices.length,
            InputNonSignerLengthMismatch()
        );

        // 1.4 验证 referenceBlockNumber 是历史区块（必须小于当前区块号）
        // 这是关键安全检查：防止使用"未来"状态进行验证
        require(referenceBlockNumber < uint32(block.number), InvalidReferenceBlocknumber());

        // ===================================================================
        // 阶段 2: 初始化数据结构并处理非签名者
        // ===================================================================

        /**
         * 算法核心思想：计算签名者的聚合公钥 (APK)
         *
         * 我们需要计算跨所有签名 quorum 的签名操作员的聚合公钥。实现方式：
         * 1. 查询每个 quorum 的总聚合公钥（包含该 quorum 所有注册操作员）
         * 2. 减去每个未签名操作员在该 quorum 的公钥
         *
         * 实践中，我们反向操作以提高效率：
         * 步骤 A：先计算所有非签名者的聚合公钥
         * 步骤 B：对该公钥取反（相当于准备减法）
         * 步骤 C：然后加上每个 quorum 的总聚合公钥
         * 结果：签名者 APK = -非签名者 APK + Σ(quorum 总 APK)
         */
        BN254.G1Point memory apk = BN254.G1Point(0, 0);

        /**
         * 质押统计：记录每个 quorum 的总质押和签名质押
         * - totalStakeForQuorum[i]: quorum i 在 referenceBlockNumber 的总质押
         * - signedStakeForQuorum[i]: quorum i 中签名者的质押（总质押 - 非签名者质押）
         */
        QuorumStakeTotals memory stakeTotals;
        stakeTotals.totalStakeForQuorum = new uint96[](quorumNumbers.length);
        stakeTotals.signedStakeForQuorum = new uint96[](quorumNumbers.length);

        /**
         * 非签名者信息存储
         * - quorumBitmaps[i]: 非签名者 i 在 referenceBlockNumber 注册的 quorum 位图
         * - pubkeyHashes[i]: 非签名者 i 的公钥哈希（即 operatorId）
         */
        NonSignerInfo memory nonSigners;
        nonSigners.quorumBitmaps = new uint256[](params.nonSignerPubkeys.length);
        nonSigners.pubkeyHashes = new bytes32[](params.nonSignerPubkeys.length);

        {
            /**
             * 2.1 将 quorumNumbers 字节数组转换为位图
             * 例如：[0, 1, 5] → 二进制 0b100011 → 十进制 35
             *
             * orderedBytesArrayToBitmap 函数同时验证：
             * - quorumNumbers 严格升序排序（防止重复）
             * - 所有 quorum 编号有效（< quorumCount）
             */
            uint256 signingQuorumBitmap = BitmapUtils.orderedBytesArrayToBitmap(
                quorumNumbers, registryCoordinator.quorumCount()
            );

            /**
             * 2.2 遍历所有非签名者，累加其公钥到 apk
             *
             * 关键概念：如果一个操作员在多个 quorum 注册，其公钥会在每个 quorum 的
             * 聚合公钥中出现一次。因此我们需要将其公钥乘以"重复次数"再累加。
             *
             * 重复次数 = 非签名者注册的 quorum 与签名 quorum 的交集中的元素个数
             * 通过位运算高效计算：countNumOnes(nonSignerQuorumBitmap & signingQuorumBitmap)
             */
            for (uint256 j = 0; j < params.nonSignerPubkeys.length; j++) {
                /**
                 * 2.2.1 计算非签名者的 operatorId（公钥哈希）
                 * 在 EigenLayer 中，operatorId 就是 BLS 公钥的哈希值
                 */
                nonSigners.pubkeyHashes[j] = params.nonSignerPubkeys[j].hashG1Point();

                /**
                 * 2.2.2 验证 operatorId 严格升序排序
                 * 这是关键安全检查：
                 * - 防止同一个操作员被重复计算（DOS 攻击）
                 * - 确保调用者诚实提供数据
                 */
                if (j != 0) {
                    require(
                        uint256(nonSigners.pubkeyHashes[j])
                            > uint256(nonSigners.pubkeyHashes[j - 1]),
                        NonSignerPubkeysNotSorted()
                    );
                }

                /**
                 * 2.2.3 查询非签名者在 referenceBlockNumber 时注册的 quorum 位图
                 * 使用历史索引 (nonSignerQuorumBitmapIndices[j]) 高效查询
                 *
                 * 例如：如果返回 0b00000111，表示该操作员注册了 quorum 0, 1, 2
                 */
                nonSigners.quorumBitmaps[j] = registryCoordinator
                    .getQuorumBitmapAtBlockNumberByIndex({
                    operatorId: nonSigners.pubkeyHashes[j],
                    blockNumber: referenceBlockNumber,
                    index: params.nonSignerQuorumBitmapIndices[j]
                });

                /**
                 * 2.2.4 计算重复次数并累加公钥
                 *
                 * 数学原理：
                 * - signingQuorumBitmap = 0b100011（签名 quorum 0, 1, 5）
                 * - nonSigners.quorumBitmaps[j] = 0b000111（操作员注册了 quorum 0, 1, 2）
                 * - 交集：0b100011 & 0b000111 = 0b000011（quorum 0, 1）
                 * - countNumOnes(0b000011) = 2（该操作员在 2 个签名 quorum 中）
                 *
                 * Gas 优化：scalar_mul_tiny 针对小数值（<512）优化，时间复杂度 O(log n)
                 */
                apk = apk.plus(
                    params.nonSignerPubkeys[j].scalar_mul_tiny(
                        BitmapUtils.countNumOnes(nonSigners.quorumBitmaps[j] & signingQuorumBitmap)
                    )
                );
            }
        }

        /**
         * 2.3 对非签名者聚合公钥取反
         *
         * 此时 apk = 所有非签名者公钥的和（考虑了多 quorum 重复）
         * 取反操作：apk = -apk（在椭圆曲线上，取反就是 Y 坐标取负）
         *
         * 接下来将加上各 quorum 的总 APK，非签名者的公钥将被自动抵消：
         * 最终 APK = -非签名者APK + Σ(quorum总APK) = 签名者APK
         */
        apk = apk.negate();

        // ===================================================================
        // 阶段 3: 构建最终签名者 APK 并计算签名质押
        // ===================================================================

        /**
         * 对于每个 quorum（在 referenceBlockNumber 时）：
         * 1. 验证并加上该 quorum 所有注册操作员的聚合公钥
         * 2. 查询该 quorum 的总质押量
         * 3. 减去所有非签名者的质押，得到签名者的质押量
         */
        {
            for (uint256 i = 0; i < quorumNumbers.length; i++) {
                /**
                 * 3.1 验证 quorum 聚合公钥的正确性
                 *
                 * 安全检查：确保调用者提供的 quorumApks[i] 确实是该 quorum 在
                 * referenceBlockNumber 时的聚合公钥，防止恶意篡改。
                 *
                 * 验证方法：比对公钥哈希是否与链上 blsApkRegistry 存储的匹配
                 * 使用 bytes24 截断哈希以节省存储（碰撞概率可忽略不计）
                 */
                require(
                    bytes24(params.quorumApks[i].hashG1Point())
                        == blsApkRegistry.getApkHashAtBlockNumberAndIndex({
                            quorumNumber: uint8(quorumNumbers[i]),
                            blockNumber: referenceBlockNumber,
                            index: params.quorumApkIndices[i]
                        }),
                    InvalidQuorumApkHash()
                );

                /**
                 * 3.2 将该 quorum 的总 APK 加到最终 APK
                 *
                 * 此时的运算：apk = -非签名者APK + quorum_0_APK + quorum_1_APK + ...
                 * 最终得到的 apk 就是所有签名者的聚合公钥
                 */
                apk = apk.plus(params.quorumApks[i]);

                /**
                 * 3.3 查询并记录该 quorum 在 referenceBlockNumber 的总质押量
                 *
                 * 使用历史索引 (totalStakeIndices[i]) 高效查询特定区块的质押状态
                 * 质押量以 uint96 存储（最大约 7.9e28，足够表示任何现实质押量）
                 */
                stakeTotals.totalStakeForQuorum[i] = stakeRegistry
                    .getTotalStakeAtBlockNumberFromIndex({
                    quorumNumber: uint8(quorumNumbers[i]),
                    blockNumber: referenceBlockNumber,
                    index: params.totalStakeIndices[i]
                });

                /**
                 * 3.4 初始化签名质押为总质押
                 * 接下来将遍历非签名者，逐个减去其质押
                 */
                stakeTotals.signedStakeForQuorum[i] = stakeTotals.totalStakeForQuorum[i];

                /**
                 * 3.5 处理该 quorum 的非签名者质押
                 *
                 * nonSignerForQuorumIndex: 跟踪当前 quorum 中第几个非签名者
                 * 用于索引 nonSignerStakeIndices[i][nonSignerForQuorumIndex]
                 */
                uint256 nonSignerForQuorumIndex = 0;

                /**
                 * 3.6 遍历所有非签名者，检查其是否在当前 quorum 注册
                 * 如果是，则从签名质押中减去其质押量
                 */
                for (uint256 j = 0; j < params.nonSignerPubkeys.length; j++) {
                    /**
                     * 使用位运算检查非签名者 j 是否在当前 quorum 注册
                     * isSet(quorumBitmap, quorumNumber) 检查位图中对应位是否为 1
                     *
                     * 例如：
                     * - quorumBitmaps[j] = 0b00000111（注册了 quorum 0, 1, 2）
                     * - quorumNumbers[i] = 1
                     * - isSet(0b00000111, 1) = true（位 1 被设置）
                     */
                    if (BitmapUtils.isSet(nonSigners.quorumBitmaps[j], uint8(quorumNumbers[i]))) {
                        /**
                         * 从签名质押中减去非签名者的质押
                         *
                         * 使用历史索引查询非签名者在 referenceBlockNumber 的质押
                         * nonSignerStakeIndices[i][nonSignerForQuorumIndex] 是二维数组：
                         * - 第一维 [i]: quorum 索引
                         * - 第二维 [nonSignerForQuorumIndex]: 该 quorum 中的第几个非签名者
                         */
                        stakeTotals.signedStakeForQuorum[i] -= stakeRegistry
                            .getStakeAtBlockNumberAndIndex({
                            quorumNumber: uint8(quorumNumbers[i]),
                            blockNumber: referenceBlockNumber,
                            operatorId: nonSigners.pubkeyHashes[j],
                            index: params.nonSignerStakeIndices[i][nonSignerForQuorumIndex]
                        });

                        /**
                         * 移动到该 quorum 的下一个非签名者
                         * unchecked: 索引不会溢出（已通过数组长度验证）
                         */
                        unchecked {
                            ++nonSignerForQuorumIndex;
                        }
                    }
                }
            }
        }

        // ===================================================================
        // 阶段 4: BLS 签名验证
        // ===================================================================

        {
            /**
             * 4.1 执行 BLS 签名验证
             *
             * 输入：
             * - msgHash: 原始消息哈希
             * - apk: 签名者的聚合公钥（G1 群）
             * - params.apkG2: 签名者的聚合公钥（G2 群）
             * - params.sigma: 聚合签名
             *
             * 输出：
             * - pairingSuccessful: 双线性配对计算是否成功（预编译合约是否正常）
             * - signatureIsValid: 签名是否有效
             *
             * 注意：apk 和 apkG2 必须对应同一组签名者的公钥，但在不同的群上
             */
            (bool pairingSuccessful, bool signatureIsValid) =
                trySignatureAndApkVerification(msgHash, apk, params.apkG2, params.sigma);

            /**
             * 4.2 验证双线性配对计算成功
             * 如果失败，可能原因：
             * - G2 点不在曲线上（恶意输入）
             * - Gas 不足
             * - 预编译合约异常
             */
            require(pairingSuccessful, InvalidBLSPairingKey());

            /**
             * 4.3 验证签名有效
             * 如果失败，说明：
             * - 签名确实无效（操作员未正确签名）
             * - 提供的 apkG2 与 apk 不对应
             * - 非签名者信息不正确
             */
            require(signatureIsValid, InvalidBLSSignature());
        }

        // ===================================================================
        // 阶段 5: 生成签名者记录哈希（用于欺诈证明）
        // ===================================================================

        /**
         * 签名者记录哈希 = keccak256(referenceBlockNumber || nonSignerPubkeyHashes)
         *
         * 用途：欺诈证明系统
         * - 链上只存储这个哈希，节省存储成本
         * - 如果发生争议，可以提交完整的非签名者列表进行验证
         * - 通过 referenceBlockNumber 确保验证的是特定历史状态
         *
         * 注意：pubkeyHashes 已按升序排列（前面已验证），确保哈希唯一性
         */
        bytes32 signatoryRecordHash =
            keccak256(abi.encodePacked(referenceBlockNumber, nonSigners.pubkeyHashes));

        /**
         * 返回结果：
         * 1. stakeTotals: 包含每个 quorum 的总质押和签名质押
         *    - AVS 可据此判断是否达到安全阈值（如 67% 质押签名）
         * 2. signatoryRecordHash: 签名者记录哈希
         *    - 可用于链上存储和后续的欺诈证明
         */
        return (stakeTotals, signatoryRecordHash);
    }

    /// @inheritdoc IBLSSignatureChecker
    /**
     * @notice 尝试验证 BLS 签名和聚合公钥的有效性
     * @param msgHash 被签名的消息哈希
     * @param apk 聚合公钥（G1 群）
     * @param apkG2 聚合公钥（G2 群）
     * @param sigma 聚合签名（G1 群）
     * @return pairingSuccessful 配对计算是否成功执行
     * @return siganatureIsValid 签名是否有效（注意：返回值名称拼写错误是原始代码）
     *
     * ========================================================================
     * === BLS 签名验证的密码学原理 ===
     * ========================================================================
     *
     * BLS 签名基于双线性配对（Bilinear Pairing）的数学性质。
     * 使用 BN254（alt_bn128）椭圆曲线，支持高效的配对运算。
     *
     * --- 基本 BLS 签名验证等式 ---
     * 标准 BLS 签名验证：e(σ, G2) = e(H(m), pk_G2)
     * 其中：
     * - σ: 签名（在 G1 群上）
     * - G2: G2 群的生成元
     * - H(m): 消息哈希映射到 G1 曲线点
     * - pk_G2: 公钥（在 G2 群上）
     * - e: 双线性配对函数 e: G1 × G2 → GT
     *
     * --- 为什么需要 Fiat-Shamir 挑战 ---
     * 问题：恶意攻击者可能构造特殊的 (σ, pk) 对使等式成立，即使他们实际上
     * 没有对应的私钥。这称为"公钥替换攻击"。
     *
     * 解决方案：引入 Fiat-Shamir 启发式变换
     * 1. 计算挑战值 γ = H(msgHash || apk || apkG2 || σ) mod r
     * 2. 修改验证等式，将挑战值混入：
     *    e(σ + apk·γ, -G2) · e(H(m) + G1·γ, apkG2) = 1
     *
     * --- 数学等价性证明 ---
     * 如果签名有效，则 σ = H(m) · sk（sk 是私钥）
     * 且 apk = G1 · sk, apkG2 = G2 · sk
     *
     * 左边：e(σ + apk·γ, -G2)
     *     = e(H(m)·sk + G1·sk·γ, -G2)
     *     = e(H(m)·sk, -G2) · e(G1·sk·γ, -G2)
     *     = e(H(m), -G2)^sk · e(G1, -G2)^(sk·γ)
     *
     * 右边：e(H(m) + G1·γ, apkG2)
     *     = e(H(m) + G1·γ, G2·sk)
     *     = e(H(m), G2·sk) · e(G1·γ, G2·sk)
     *     = e(H(m), G2)^sk · e(G1, G2)^(γ·sk)
     *
     * 两边相乘：
     * e(H(m), -G2)^sk · e(G1, -G2)^(sk·γ) · e(H(m), G2)^sk · e(G1, G2)^(γ·sk)
     * = e(H(m), G2)^0 · e(G1, G2)^0  （因为 -G2 抵消 G2）
     * = 1 · 1 = 1 ✓
     *
     * --- 安全性 ---
     * 攻击者必须找到满足修改后等式的 (σ, apk, apkG2)，但由于 γ 依赖于
     * 所有这些值的哈希，攻击者无法自由构造。这基于 Random Oracle Model
     * 假设下的 Fiat-Shamir 变换的安全性。
     *
     * --- Gas 优化 ---
     * - 使用 safePairing 而非 pairing：指定 gas 上限，防止 DoS 攻击
     * - PAIRING_EQUALITY_CHECK_GAS = 120000: 经验值，足够完成配对检查
     * - 如果 gas 不足，pairingSuccessful = false，不会 revert
     *
     * ========================================================================
     */
    function trySignatureAndApkVerification(
        bytes32 msgHash,
        BN254.G1Point memory apk,
        BN254.G2Point memory apkG2,
        BN254.G1Point memory sigma
    ) public view returns (bool pairingSuccessful, bool siganatureIsValid) {
        /**
         * 计算 Fiat-Shamir 挑战值
         *
         * γ = keccak256(msgHash || apk.X || apk.Y || apkG2.X[0] || apkG2.X[1]
         *               || apkG2.Y[0] || apkG2.Y[1] || σ.X || σ.Y) mod FR_MODULUS
         *
         * FR_MODULUS: BN254 曲线的标量域模数，约为 2^254
         * 确保 γ 在有效的标量范围内（可以用于标量乘法）
         */
        uint256 gamma = uint256(
            keccak256(
                abi.encodePacked(
                    msgHash,
                    apk.X,
                    apk.Y,
                    apkG2.X[0],
                    apkG2.X[1],
                    apkG2.Y[0],
                    apkG2.Y[1],
                    sigma.X,
                    sigma.Y
                )
            )
        ) % BN254.FR_MODULUS;

        /**
         * 执行双线性配对验证
         *
         * 验证等式：e(σ + apk·γ, -G2) · e(H(m) + G1·γ, apkG2) = 1
         *
         * safePairing 参数：
         * 1. σ + apk·γ: 签名加上公钥的 γ 倍（G1 群）
         * 2. -G2: 负的 G2 生成元（用于反向配对）
         * 3. H(m) + G1·γ: 消息哈希点加上 G1 的 γ 倍（G1 群）
         * 4. apkG2: 聚合公钥（G2 群）
         * 5. PAIRING_EQUALITY_CHECK_GAS: Gas 上限（120000）
         *
         * 返回：
         * - pairingSuccessful: true 如果配对计算成功（即使签名无效）
         * - siganatureIsValid: true 如果且仅如果等式成立
         *
         * 注意：使用以太坊预编译合约 0x08 (ecPairing) 执行配对检查
         */
        (pairingSuccessful, siganatureIsValid) = BN254.safePairing(
            sigma.plus(apk.scalar_mul(gamma)),
            BN254.negGeneratorG2(),
            BN254.hashToG1(msgHash).plus(BN254.generatorG1().scalar_mul(gamma)),
            apkG2,
            PAIRING_EQUALITY_CHECK_GAS
        );
    }
}

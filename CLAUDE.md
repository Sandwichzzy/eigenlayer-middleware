# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

EigenLayer Middleware 是一套智能合约，用于构建 AVS（Actively Validated Services）。这些合约为 AVS 提供与 EigenLayer 核心协议的接口，支持操作员注册、质押管理、签名验证和惩罚机制。

**核心仓库依赖**: [eigenlayer-contracts](https://github.com/Layr-Labs/eigenlayer-contracts) - 核心 EigenLayer 合约

## 构建和测试命令

### 基础命令
```bash
# 更新 Foundry 工具链
foundryup

# 构建项目
forge build

# 显示合约大小
forge build --sizes

# 格式化代码
forge fmt

# 检查格式（不修改）
forge fmt --check

# 运行所有本地测试（单元测试 + 集成测试）
forge test

# 运行测试并显示详细输出
forge test -vvv          # 显示日志
forge test -vvvv         # 显示失败测试的堆栈跟踪
forge test -vvvvv        # 显示所有测试的堆栈跟踪

# 运行特定测试文件
forge test --match-path test/unit/AVSRegistrar.t.sol

# 运行特定测试函数
forge test --match-test testRegisterOperator

# 运行特定合约的测试
forge test --match-contract BLSApkRegistryUnit

# 运行集成测试（使用主网分叉）
FOUNDRY_PROFILE=forktest forge test --match-contract Integration -vvv

# 运行密集型模糊测试
FOUNDRY_PROFILE=intense forge test
```

### 测试覆盖率
```bash
# 生成覆盖率报告（排除 test 和 script 目录）
FOUNDRY_DENY_WARNINGS=false FOUNDRY_PROFILE=ci forge coverage --report lcov --report summary --no-match-coverage "script|test"

# 生成 HTML 覆盖率报告
genhtml -q -o report ./lcov.info

# 注意：本项目要求测试覆盖率至少达到 90%（行覆盖和函数覆盖）
```

### Go FFI 相关
```bash
# 项目包含 Go FFI 代码用于 BLS 密码学运算
cd test/ffi/go
go build
```

## 代码架构

### 目录结构
```
src/
├── middlewareV2/              # 新版中间件架构（推荐使用）
│   ├── registrar/             # AVS 注册器
│   │   ├── AVSRegistrar.sol   # 基础注册器
│   │   └── presets/           # 预设变体（带 Socket、Allowlist 等）
│   └── tableCalculator/       # 操作员权重计算
│       ├── BN254TableCalculator.sol    # BLS 签名方案
│       └── ECDSATableCalculator.sol    # ECDSA 签名方案
├── slashers/                  # 惩罚机制实现
│   ├── InstantSlasher.sol     # 即时惩罚
│   └── VetoableSlasher.sol    # 可否决惩罚
├── RegistryCoordinator.sol    # 操作员注册协调器（旧版）
├── SlashingRegistryCoordinator.sol  # 支持惩罚的注册协调器
├── BLSApkRegistry.sol         # BLS 聚合公钥注册表
├── StakeRegistry.sol          # 质押权重注册表
├── IndexRegistry.sol          # 操作员索引注册表
├── ServiceManagerBase.sol     # AVS 服务管理基类
├── BLSSignatureChecker.sol    # BLS 签名验证器
└── interfaces/                # 接口定义

test/
├── integration/               # 集成测试（模拟完整流程）
│   ├── tests/                 # 主要测试场景
│   ├── utils/                 # 测试工具
│   └── mocks/                 # 模拟合约
├── unit/                      # 单元测试
│   ├── middlewareV2/          # MiddlewareV2 单元测试
│   └── libraries/             # 库函数测试
└── ffi/                       # FFI 测试（Go 互操作）

docs/
├── middlewareV2/              # MiddlewareV2 文档
│   ├── README.md
│   ├── AVSRegistrar.md
│   └── OperatorTableCalculator.md
├── slashing/                  # 惩罚机制文档
├── registries/                # 注册表文档
└── quick-start.md             # 快速开始指南
```

### 核心概念

**Quorum（法定人数组）**
- AVS 定义的特定质押类型分组
- 操作员注册时选择加入一个或多个 quorum
- 每个 quorum 评估操作员的特定权重子集
- 用于确定 AVS 是否达成共识

**Strategies and Stake（策略和质押）**
- 每个 quorum 关联一组 `StrategyParams`（策略参数）
- Strategy 是对底层代币（LST 或原生 ETH）的包装
- Multiplier 决定对应策略的相对权重
- `StakeRegistry` 从核心合约的 `DelegationManager` 查询操作员份额

**Operator Sets and Churn（操作员集和轮换）**
- Quorum 定义最大操作员数量
- 达到最大值时，新操作员可替换现有操作员（需 Churn Approver 签名）
- `OperatorSetParam` 配置最大数量和质押阈值

**State Histories（状态历史）**
- 多数合约保存状态历史记录
- 用于查询特定区块的状态
- 链下代码用于验证链上操作

### 架构模式

**MiddlewareV2 架构（推荐）**
AVS 仅需部署以下合约：
1. `AVSRegistrar` - 操作员注册管理
2. `OperatorTableCalculator` - 自定义质押权重计算（BN254 或 ECDSA）
3. `Slasher` - 惩罚机制（InstantSlasher 或 VetoableSlasher）
4. Admin 功能 - 奖励提交、驱逐等

核心协议集成：
- `KeyRegistrar` - 操作员密钥存储
- `AllocationManager` - 操作员集成员管理、质押分配
- `CertificateVerifier` - 任务验证（BN254 或 ECDSA）

**旧版架构（维护中）**
使用 `RegistryCoordinator` + 三个注册表：
- `BLSApkRegistry` - 跟踪每个 quorum 的聚合 BLS 公钥哈希
- `StakeRegistry` - 根据质押和 quorum 配置确定操作员权重
- `IndexRegistry` - 为 quorum 内的操作员分配索引

### 关键合约交互流程

**操作员注册流程（MiddlewareV2）**:
1. 操作员通过 `AllocationManager.registerForOperatorSets()` 注册
2. `AllocationManager` 调用 `AVSRegistrar.registerOperator()`
3. `AVSRegistrar` 验证密钥是否在 `KeyRegistrar` 中注册
4. 更新本地状态并触发 hooks（如 Socket 注册）

**惩罚流程**:
1. AVS 通过 `Slasher.submitEvidence()` 提交证据
2. 根据类型调用 `AllocationManager.slashOperator()`
3. 更新操作员的可惩罚质押
4. 可选触发操作员驱逐

## Foundry 配置要点

**Solidity 版本**: 0.8.27

**优化器**: 启用，运行次数 200

**FFI**: 已启用（警告：允许任意程序执行）

**重映射**:
```
forge-std/=lib/forge-std/src/
@openzeppelin/=lib/openzeppelin-contracts/
@openzeppelin-upgrades/=lib/openzeppelin-contracts-upgradeable/
eigenlayer-contracts/=lib/eigenlayer-contracts/
```

**测试配置文件**:
- `default` - 标准测试
- `ci` - CI 环境（100 次模糊测试运行）
- `intense` - 密集模糊测试（5000 次运行）
- `forktest` - 分叉测试（16 次模糊测试运行）

**RPC 端点**（需要环境变量）:
- `RPC_MAINNET` - 主网 RPC
- `HOLESKY_RPC_URL` - Holesky 测试网 RPC

## 分支策略

- `dev` (默认) - 最新开发代码，用于即将发布的版本
- `testnet-holesky` - 当前测试网部署
- `mainnet` - 当前主网部署

## 代码风格

**Solidity 格式化配置**:
- 行长度: 100 字符
- 缩进: 4 个空格
- 引号: 双引号
- 括号间距: 无空格
- 整数类型: 显式类型（uint256 而非 uint）

**命名约定**:
- 合约名: 大驼峰（PascalCase）
- 函数和变量: 小驼峰（camelCase）
- 常量: 大写下划线（UPPER_SNAKE_CASE）
- 私有/内部变量: 下划线前缀（`_variableName`）

**安全要求**:
- 所有关键函数必须包含权限检查
- 使用 Solidity 0.8+ 的内置溢出检查
- 重入保护: 遵循 Checks-Effects-Interactions 模式
- 事件记录: 所有状态变更必须触发事件

## 开发注意事项

1. **测试优先**: 新功能必须包含单元测试和集成测试，覆盖率要求 ≥90%
2. **Gas 优化**: 注意存储布局和内存使用
3. **升级模式**: 大多数合约使用透明代理（OpenZeppelin TransparentUpgradeableProxy 4.7.1）
4. **文档**: 公共函数必须包含 NatSpec 注释
5. **依赖管理**: 使用 Git 子模块管理库依赖
6. **Commit 规范**: 使用 Conventional Commits（项目配置了 commitlint）

## 常见陷阱

1. **Quorum 编号处理**: Quorum 号在不同上下文以字节数组或位图形式传递（参见 `BitmapUtils` 库）
2. **状态历史查询**: 确保使用正确的区块号查询历史状态
3. **BLS 签名验证**: 非签名者列表长度影响 gas 成本，需注意最坏情况
4. **FFI 测试**: 运行涉及 Go FFI 的测试前需先编译 Go 代码
5. **Fork 测试**: 需要配置有效的 RPC 端点环境变量

## 参考资源

- [EigenLayer 核心合约文档](https://github.com/Layr-Labs/eigenlayer-contracts/tree/dev/docs)
- [MiddlewareV2 文档](./docs/middlewareV2/README.md)
- [快速开始指南](./docs/quick-start.md)
- [Slashing 文档](./docs/slashing/SlasherBase.md)
- [Restaking 用户指南](https://docs.eigenlayer.xyz/restaking-guides/restaking-user-guide)
- [操作员指南](https://docs.eigenlayer.xyz/operator-guides/operator-introduction)

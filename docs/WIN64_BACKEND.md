# Windows x64 实验后端

## 范围

目标是 Unity IL2CPP 的 Windows PE32+ AMD64 输入。机器码经 SLEIGH 解码为 P-code，再转换到公共机器 IR；Win64 ABI、运行时辅助函数及经过证明的惯用法在公共恢复前提供调用和类型依据。

运行时偏移只启用经目标导出代码及匹配配置核实的部分。当前包含元数据 v31 的受限 Win64 配置，不能将其推广到所有 Unity 版本、编译器、平台或加密输入。映像可读取也不代表能完整恢复。

## 构建

需要 .NET 10 SDK、Git、CMake、MSVC x64 C++ 工具链与 Windows SDK。原生桥使用固定版本的 standalone SLEIGH 和 zlib，下载及构建缓存位于 `.cpp2cs/`。

```powershell
git submodule update --init
powershell -ExecutionPolicy Bypass -File native/sleigh-bridge/build.ps1 -Jobs 4
dotnet build Cpp2CS.slnx -c Release
```

构建脚本核对固定源码修订；不匹配时停止，不自行切换其他版本。桥和处理器规格必须来自匹配版本。当前托管桥要求原生 ABI 版本 3。

## 使用

在仓库根目录运行，将输入和输出参数替换为自己的匹配文件：

```powershell
$env:CPP2CS_SLEIGH_BRIDGE = "$PWD/.cpp2cs/build/sleighbridge/Release/cpp2cs_sleigh_bridge.dll"
$sla = "$PWD/.cpp2cs/sleigh/install/share/sleigh/specfiles/Ghidra/Processors/x86/data/languages/x86-64.sla"
dotnet run --project src/Cpp2CS.X64.Cli -c Release -- recover <binary> <metadata> $sla <output> <assembly.dll> all --jobs 4
```

`all` 选择指定程序集的完整定义范围。依赖按输出所需补齐，不应与所选程序集混为同一成功率分母。诊断入口还包括 `facts`、`methods`、`pcode`、`ir`、`cfg` 和 `scan`，无参数运行可查看当前用法。

输入和恢复结果建议放在 `ref/`、`artifacts/` 或其他本地忽略目录；不要提交游戏二进制和业务方法清单。

## 主要实现

| 模块 | 职责 |
|---|---|
| `native/sleigh-bridge/` | SLEIGH 原生桥、寄存器/地址空间及用户操作传递 |
| `src/Cpp2CS.X64/` | 解码器、P-code 提升、Win64 运行时与原生契约识别 |
| `src/Cpp2CS.X64.Cli/` | PE 输入事实建立、恢复及只读诊断入口 |
| `src/Cpp2CS.Core/Image/` | PE 映像、展开记录、FH3/FH4 元数据读取及运行库证明 |
| `src/Cpp2CS.Core/Facts/` | Win64 参数位置、隐藏 MethodInfo、返回缓冲区与调用身份 |
| `src/Cpp2CS.Core/Idioms/` | 元数据初始化、守卫、调用和部分共用归一规则 |
| `src/Cpp2CS.Core/Recovery/` | 公共符号值、内存、类型、调用及模板恢复 |
| `src/Cpp2CS.Output/`、`src/Cpp2CS.Pipeline/` | CIL、检查、源码导出与报告 |

固定大小参数、副本、隐藏结果缓冲区及部分 ICF/icall 包装已有支持。部分 FH4 捕获、清理及不返回路径能够建立分析图。静态 CRT 的若干数学与内存入口通过独立供应商 COFF 代码、常量和重定位关系识别。

这些支持均有前提。未知原生调用、未建模用户操作、不能证明的地址流向和不支持的异常形态继续报告失败。完整边界见[已知局限](LIMITATIONS.md)。

## 输出与阅读方式

| 产物 | 用途 |
|---|---|
| `recovery.jsonl`、`emitted.tsv` | 每个定义的恢复、写出状态与原因 |
| `call-resolution.jsonl` | 调用目标、候选、选择和拒绝依据 |
| `managed-checks.jsonl`、`managed-check-diagnostics.jsonl` | 托管静态检查及失败原因 |
| `windows-eh.jsonl` | 原生异常信息与投影诊断 |
| `rules.jsonl`、`native-expansions.jsonl` | 已应用规则和原生展开依据 |
| `publication.jsonl`、`run.json` | 已发布体摘要及运行清单 |
| `assemblies/`、`src/` | CIL 程序集和生成的 C# 工程 |

部分报告会保留早期拒绝、随后又被证明成立的记录；不能直接把 rejection 条数当成最终失败方法数。调用点和方法定义也不是同一统计单位。

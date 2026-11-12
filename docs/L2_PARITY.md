# L2 规则入口对照

当前 ARM64 执行完整的 `IdiomPipeline.Table`。Win64 使用 `IdiomRewriter.Run` 的独立归一流程，再执行 `RunPortable`；部分能力由公共恢复阶段后置处理。

共 45 条规则：9 条直接执行、14 条显式/部分/后置替代、22 条未进入同一 L2 序列。此表是源码入口和时序对照，不是 45 个功能的成功率测量。没有直接入口不等于整项能力完全不存在。

| 规则 | Win64 路径 | 边界说明 |
|---|---|---|
| `metadata` | 显式替代 | MetadataLoadsPass + GenericMetadataLoads；x64 使用核实后的偏移 |
| `interface.tails` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `indirect.tails` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `interface.dispatch` | 条件启用 | ClassVtable 需等于 RuntimeLayout；本机原生形态仍可能拒绝 |
| `interface.invokes` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `calls` | 部分替代 | x64 Direct + 下游 DispatchResolution；并非 L2 Calls/Indirect 的同一执行序列 |
| `invoker` | 显式替代 | InvokerCalls + InvokerCallsPass.AfterSplitting |
| `shared.values` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `stack.boxing` | 后置执行 | MethodDecompiler 在分派/内存分析前执行 StackBoxingPass.Run |
| `lazy.metadata` | 显式替代 | Direct/ReplaceLazy，未用结果仍要求守卫证明 |
| `operands` | 部分替代 | x64 循环仅显式刷新 InitClass；L3 ClassOperand 另可从实参实体推断 |
| `thread.statics` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `memory.constant` | 共用规则已执行 | RunPortable |
| `math.imports` | 共用规则已执行 | RunPortable |
| `array.fresh-elements` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `array.element-checks` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `enum.element-classes` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `unbox.guards` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `interface.operands` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `delegates` | 部分后置 | DelegateCallNormalizer.Discover/Run；时序与 ARM64 不相同 |
| `managed.throws` | 部分替代 | X64ExceptionHelpers + Direct 的 MSVC wrapper 处理；有未接通包装 |
| `catch.exception` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `runtime.guards` | 部分替代 | Guards/Checks/TypeChecks/ClassInitializationFacts |
| `class.initialized` | 部分替代 | ClassInitializationFacts 使用核实后的偏移 |
| `once.guards` | 部分启用 | x64 只启用 metadataOnly，类布局/类构造两臂证明不完整对齐 |
| `conditions.finite` | 共用规则已执行 | RunPortable |
| `conditions.zero-union` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `checked.references` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `checked.types` | 显式替代 | SuccessfulTypeCheckValuesPass.Run |
| `checked.classes` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `phi.zero-sources` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `phi.equal-addresses` | 共用规则已执行 | RunPortable |
| `phi.static-fields` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `phi.strings` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `phi.array-addresses` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `loops.affine` | 共用规则已执行 | RunPortable |
| `loops.array-pointers` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `exception.stack` | 部分后置 | MethodDecompiler 在内存提升后执行 TopValues/Run；不是完整 L2 规则组合 |
| `readonly.data` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `phi.address-loads` | 共用规则已执行 | RunPortable |
| `phi.class-allocations` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `allocations.merged` | 未在 x64 L2 序列启用 | 不代表整项功能完全不存在；L3 可能覆盖部分形态 |
| `select.address-loads` | 共用规则已执行 | RunPortable |
| `division.constant` | 共用规则已执行 | RunPortable |
| `phi.flags` | 共用规则已执行 | RunPortable |

## 阅读边界

- 已执行的共用规则也依赖输入 IR、调用身份和已核实布局，不保证每种原生形态都命中。
- 后置执行可能无法挽回此前已被未知调用、地址逃逸或签名失败挡住的函数。
- ARM64 专用指令字、GPR 编号及运行时偏移必须移植或抽象，不能直接启用整个表。
- 条件/φ、检查后类型细化、字符串槽位及合并分配等 IR 规则有复用价值，但仍应核对 Win64 前提及真实效果。
- `RuntimeOps` 等公共代码仍有寄存器映射假设；规则位于公共项目并不自动意味着 ABI 无关。

源码见 [IdiomPipeline.cs](../src/Cpp2CS.Core/Idioms/IdiomPipeline.cs)、[IdiomRewriter.cs](../src/Cpp2CS.Core/Idioms/IdiomRewriter.cs) 和 [MethodDecompiler.cs](../src/Cpp2CS.Core/Recovery/MethodDecompiler.cs)。

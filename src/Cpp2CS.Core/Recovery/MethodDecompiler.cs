using Cpp2CS.Calls;
using Cpp2CS.Diagnostics;
using Cpp2CS.Facts;
using Cpp2CS.Facts.Derived;
using Cpp2CS.Idioms;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Lifting;
using Cpp2CS.Recovery.Calls;
using Cpp2CS.Recovery.Control;
using Cpp2CS.Recovery.Inlining;
using Cpp2CS.Recovery.Lowering;
using Cpp2CS.Recovery.Memory;
using Cpp2CS.Recovery.Shape;
using Cpp2CS.Recovery.Typing;
using Cpp2CS.Recovery.Values;

namespace Cpp2CS.Recovery;

/// <summary>一次方法分析的各层产物，供下降与检查使用。</summary>
public sealed record MethodAnalysis(MethodRef Method, ulong Entry, MachineSignature Signature, MachineFunction Function,
    IdiomResult Idioms, MemoryLayout Memory, ValueModel Values)
{
    internal MethodEnvironment Environment { get; init; } = null!;
    /// <summary>路径拆分复制的合流块数。</summary>
    public int Splits { get; init; }
}

/// <summary>
/// 单个托管方法的恢复入口：签名 → 提升 → L2 → 符号值 → 类型 → 下降。
/// 实例不是线程安全的，并行时每个线程各用一个。
/// </summary>
public sealed class MethodDecompiler
{
    private readonly ProgramFacts facts;
    private readonly ManagedTypes types;
    private readonly FunctionLifter lifter;
    private readonly IdiomRewriter rewriter;
    private readonly ManagedAbi abi;
    private readonly CallShapes shapes;
    private readonly NativeMethodFacts native;
    private readonly Dictionary<MethodRequest, MethodRecoveryResult?> summaries = [];
    private MethodEntries? entries;
    private readonly NativeLeafInlining? nativeReads;

    public MethodDecompiler(ProgramFacts facts, ManagedTypes types)
    {
        this.facts = facts;
        this.types = types;
        lifter = new FunctionLifter(facts) { InlinesClosures = true, InlinesNativeLeaves = true, InlinesNativeBodies = true };
        rewriter = new IdiomRewriter(facts) { RecordFilter = _ => false, RecoverUnusedInputs = true };
        abi = facts.CreateAbi();
        shapes = new CallShapes(facts, abi, rewriter.UnusedInput);
        native = new NativeMethodFacts(facts, lifter, rewriter);
        if (facts.Model.Image.Architecture == Architecture.X64) nativeReads = new(facts, lifter.Machine);
    }

    public ManagedTypes Types => types;
    public ProgramFacts Facts => facts;
    public CallShapes Shapes => shapes;

    private string? BodyBoundaryProblem(ulong entry) => facts.Code.At(entry) switch
    {
        { Start: var start } when start != entry => "元数据入口不是已建图的函数入口",
        null => "元数据入口没有函数边界依据",
        { HasUnmodeledExceptions: true } => lifter.WindowsExceptionProblem(entry),
        _ => null,
    };

    public MethodRecoveryResult Recover(MethodRef method, ulong entry) => Declaration(method, entry) ?? PlatformInvoke(method, entry) ?? Run(method, entry);

    /// <summary>恢复泛型类型或泛型方法的封闭实例，方法体以封闭类型表达。</summary>
    public MethodRecoveryResult RecoverInstance(MethodRef method, ulong entry) => Declaration(method, entry) ?? PlatformInvoke(method, entry) ?? Run(method, entry);

    /// <summary>从已知原生实例恢复开放泛型体：类型参数带上实例的原生绑定，输出保留类型参数。</summary>
    public MethodRecoveryResult RecoverShared(MethodRef instance, ulong entry)
    {
        var open = BindShared(instance, entry);
        return Declaration(open, entry) ?? PlatformInvoke(open, entry) ?? Run(open, entry);
    }

    /// <summary>开放泛型的托管身份及当前入口提供的原生布局见证。</summary>
    public MethodRef BindShared(MethodRef instance, ulong entry)
    {
        var open = MethodRef.Open(instance.Method);
        return open with
        {
            TypeArguments = open.TypeArguments.Zip(instance.TypeArguments, Bind).ToArray(),
            MethodArguments = open.MethodArguments.Zip(instance.MethodArguments, Bind).ToArray(),
        };
        TypeRef Bind(TypeRef parameter, TypeRef actual) => parameter is GenericParameterRef g
            ? g with
            {
                Binding = new(FieldLayouts.IsFullyShared(actual) ? NativeBindingKind.Shared
                    : ManagedTypes.IsReferenceType(actual) ? NativeBindingKind.Reference
                    : types.Kind(actual) == TypeKind.Struct ? NativeBindingKind.Aggregate : NativeBindingKind.Scalar, actual, entry)
            } : parameter;
    }

    private static MethodRecoveryResult? Declaration(MethodRef method, ulong entry) => DelegateFacts.IsRuntimeMethod(method.Method)
        ? new(method, entry, null, []) { Declaration = RuntimeDeclarationKind.Delegate } : null;

    /// <summary>extern 方法没有 CIL 方法体，原生入口只是解析并转发的桩：结果是一条带库名与入口的声明。</summary>
    private MethodRecoveryResult? PlatformInvoke(MethodRef method, ulong entry)
    {
        if ((method.Method.Attributes & System.Reflection.MethodAttributes.PinvokeImpl) == 0) return null;
        if (BodyBoundaryProblem(entry) is { } boundary) return new(method, entry, null, [new(entry, boundary)]);
        var lifted = lifter.Lift(entry, null, null, simplify: true, promoteFrameSlots: false);
        if (!lifted.Succeeded) return new(method, entry, null, [new(entry, $"提升 {lifted.Errors[0]}")]);
        rewriter.Run(lifted.Function);
        var effects = new CallMemoryEffects(shapes.Of, abi);
        return PlatformInvokeStub.Read(lifted.Function, facts.Model.Image, effects, out var descriptorFailure) is { } import
            ? new(method, entry, null, []) { Declaration = RuntimeDeclarationKind.PlatformInvoke, PlatformImport = import }
            : new(method, entry, null, [new(entry, $"运行时 P/Invoke 桩不能证明：{descriptorFailure}")]);
    }

    private MethodRecoveryResult Run(MethodRef method, ulong entry)
    {
        if (!Analyze(method, entry).TryGet(out var analysis, out var failure))
            return new(method, entry, null, [new(failure.Address, failure.Reason)]);
        return Lower(analysis) with { Rejections = Attribution(analysis.Idioms), NativeExpansions = analysis.Function.NativeExpansions.ToArray() };
    }

    /// <summary>L2 留下的归因线索：证明被拒绝的规则，以及没有归一的运行时痕迹。</summary>
    private static Cpp2CS.Diagnostics.RuleRejection[] Attribution(IdiomResult idioms) => idioms.Rejections
        .Concat(idioms.Residuals.Select(r => new Cpp2CS.Diagnostics.RuleRejection("residual", r.Address, r.Category))).ToArray();

    /// <summary>类型与下降。</summary>
    public MethodRecoveryResult Lower(MethodAnalysis analysis)
    {
        var oracle = new TypeOracle(types, facts, analysis.Method, analysis.Environment.Shape, analysis.Values, analysis.Memory);
        var uses = new TypeUseAnalysis(analysis, oracle).Run();
        if (uses.State != TypeSolveState.Stable)
            return new(analysis.Method, analysis.Entry, null, [new(analysis.Entry,
                uses.State == TypeSolveState.Cycle ? "类型 φ 类型求解循环" : "类型 φ 类型求解超过预算")]);
        if (facts.Model.Image.Architecture == Architecture.X64 && ReferenceEqualityFlags.Run(analysis.Function, analysis.Values, oracle))
        {
            analysis = analysis with { Values = ValueModel.Build(analysis.Function, analysis.Environment) };
            oracle = new TypeOracle(types, facts, analysis.Method, analysis.Environment.Shape, analysis.Values, analysis.Memory);
            uses = new TypeUseAnalysis(analysis, oracle).Run();
            if (uses.State != TypeSolveState.Stable)
                return new(analysis.Method, analysis.Entry, null, [new(analysis.Entry, "引用比较归一后类型求解未收敛")]);
        }
        var referenced = analysis.Function.Blocks.SelectMany(b => b.Statements).SelectMany(ExprMap.Operands).SelectMany(ExprMap.Walk)
            .OfType<Symbol>().Where(s => s.Kind == SymbolKind.Method).Select(s => (MethodRef)s.Value).Distinct().ToArray();
        var fields = new InlineEvidence(types, analysis.Method, Summary, referenced);
        var templates = new TemplateRecovery(types, analysis.Method, Summary, fields);
        var lowered = BodyBuilder.Build(analysis, oracle, uses, fields, templates);
        MethodRecoveryResult Traced(MethodRecoveryResult result) => result with { Calls = oracle.CallResolutions() };
        if (lowered.Body is null) return Traced(new(analysis.Method, analysis.Entry, null, lowered.Holes));
        var recovered = templates.Run(lowered.Body, lowered.Constructions, lowered.NextLocal);
        var body = LocalCoalescing.Run(recovered.Body);
        var holes = lowered.Holes.Concat(recovered.Holes).DistinctBy(h => (h.Address, h.Reason)).ToArray();
        return Traced(holes.Length == 0 ? new(analysis.Method, analysis.Entry, body, [])
            : new(analysis.Method, analysis.Entry, null, holes) { Partial = body });
    }

    /// <summary>写出的方法体还原成源码编译器的形态；内联证明用的方法体不经过这一步。</summary>
    public MethodRecoveryResult SourceForm(MethodRecoveryResult result)
    {
        if (result.Body is not { } body) return result;
        var merged = AsReceivers.Run(body);
        if (!ReferenceEquals(merged, body)) result = result with { Rules = [.. result.Rules, new RuleTrace("as.receivers", result.Entry, RewriteStatus.Applied, "merged", null, null)] };
        var form = AsyncForms.Run(merged, types, Summary, Definition, out var rejected);
        if (rejected is not null) return result with { Rules = [.. result.Rules, new RuleTrace("async.form", result.Entry, RewriteStatus.Blocked, rejected, null, null)] };
        form = IteratorForms.Run(form, out rejected);
        if (rejected is null)
        {
            var joined = JoinCopies.Run(form, out var rewrites);
            return rewrites == 0 ? result with { Body = joined }
                : result with { Body = joined, Rules = [.. result.Rules, new RuleTrace("join.copies", result.Entry, RewriteStatus.Applied, "copied", null, null)] };
        }
        return result with { Rules = [.. result.Rules, new RuleTrace("iterator.form", result.Entry, RewriteStatus.Blocked, rejected, null, null)] };
    }

    private MethodRecoveryResult? Definition(MethodDef method)
    {
        entries ??= new MethodEntries(facts, types);
        return entries.ForDefinition(method) is { } target ? new RecoveryTarget(target.Instance, target.Address).Lowered(this) : null;
    }

    /// <summary>写出定义：使用统一索引选择的原生见证；实例模板分析仍走 Summary。</summary>
    public MethodRecoveryResult RecoverDefinition(MethodDef definition)
    {
        entries ??= new MethodEntries(facts, types);
        if (entries.ForDefinition(definition) is not { } target)
            return new(MethodRef.Open(definition), 0, null, [new(0, "依赖 定义没有原生见证")]);
        return new RecoveryTarget(target.Instance, target.Address).Recover(this);
    }

    /// <summary>
    /// 另一个方法自身原生代码的恢复结果，作为内联证明的依据。入口取自方法实例索引（泛型实例可取共享实现）；
    /// 按方法、入口与原生布局绑定缓存；递归恢复中的方法返回 null。
    /// </summary>
    public MethodRecoveryResult? Summary(MethodRef method)
    {
        entries ??= new MethodEntries(facts, types);
        var entry = entries.Of(method);
        if (entry == 0) return null;
        var request = new MethodRequest(method, entry, RecoveryMode.Instance);
        if (summaries.TryGetValue(request, out var known)) return known;
        // 泛型实参可能在模板依赖中不断嵌套；同一本体换绑定并不能解除递归依赖。
        if (activeSummaries.Contains((method.Method, entry)))
            return new(method, entry, null, [new(entry, "模板 同一原生方法在不同泛型绑定间递归依赖")]);
        if (activeSummaries.Count >= 64)
            return new(method, entry, null, [new(entry, "模板 依赖分析超过深度预算")]);
        summaries[request] = null;
        activeSummaries.Add((method.Method, entry));
        var result = method.TypeArguments.Count + method.MethodArguments.Count > 0 ? RecoverInstance(method, entry) : Recover(method, entry);
        activeSummaries.Remove((method.Method, entry));
        summaries[request] = result;
        return result;
    }

    private readonly HashSet<(MethodDef Method, ulong Entry)> activeSummaries = [];

    private static Func<Variable> FreshTemporaries(MachineFunction function)
    {
        var next = function.Blocks.SelectMany(b => b.Statements).SelectMany(s => s switch
            { Define d => new[] { d.Target }, Phi p => [p.Target], Call c => c.Defines.OfType<Variable>(), _ => [] })
            .Concat(function.Dead.Select(d => d.Define.Target)).Where(v => v.Storage.Bank == Bank.Temp)
            .Select(v => v.Storage.Index).DefaultIfEmpty(-1).Max() + 1;
        return () => new Variable(Storage.Temp(next++), 1);
    }

    /// <summary>委托根的类型：委托常与结构体的其他字段一起放在宽寄存器里，取低位的根按值的位片定型。</summary>
    private static Func<Expr, TypeRef?> RootType(TypeOracle oracle, ValueModel values) => e => e switch
    {
        Use { Width: var width, Variable: var variable } when width < variable.Width => oracle.TypeOf(values.Syms.Slice(values.Of(variable), 0, width)),
        Use use => oracle.TypeOf(values.Of(use.Variable)),
        _ => null,
    };

    /// <summary>运行到符号值为止的各层。</summary>
    public RecoveryResult<MethodAnalysis> Analyze(MethodRef method, ulong entry)
    {
        if (BodyBoundaryProblem(entry) is { } boundary)
            return RecoveryDiagnostics.Fail(entry, boundary, rule: "Prepare");
        if (abi.Machine(method, out var problem) is not { } signature)
            return RecoveryDiagnostics.Fail(entry, $"签名 {problem}", rule: "Prepare");
        var returnPieces = signature.Return is { Transfer: Transfer.Value } ret
            ? ret.Pieces.Select(p => new ReturnPiece(p.Offset, new Read(p.Register, p.Width))).ToArray() : null;
        var lifted = lifter.Lift(entry, null, returnPieces, simplify: true, promoteFrameSlots: false);
        if (!lifted.Succeeded)
            return RecoveryDiagnostics.Fail(entry, $"提升 {lifted.Errors[0]}", rule: "Prepare");
        var function = lifted.Function;
        if (facts.Options.Diagnostics.Frames.Contains(entry)) facts.Options.Diagnostics.Write("before-idioms", entry, function.ToString());
        var idioms = rewriter.Run(function, method);
        if (facts.Options.Diagnostics.Frames.Contains(entry)) facts.Options.Diagnostics.Write("after-idioms", entry, function.ToString());
        if (idioms.Errors.Count > 0)
            return RecoveryDiagnostics.Fail(entry, $"L2 {idioms.Errors[0]}", rule: "Prepare");
        GenericContext.Instantiate(function, method);
        if (facts.Model.Image.Architecture == Architecture.X64)
            new EmptyBaseConstructorProof(facts, abi).Bind(function, method);
        CleanupCalls.Run(function, address => facts.Helpers.At(address)?.Kind == HelperKind.Unknown
            ? native.CleanupThunk(address, method.Method.Owner) : null);
        ExceptionNormalization.Run(function, ExceptionFacts.WrapperWithoutDestructor(facts.Checks));
        var environment = new MethodEnvironment(method, signature, shapes);
        CallResultAliases.Run(function, environment.Shape);
        while (FloatRangeBranches.Run(function, ValueModel.Build(function, environment)) > 0)
        {
            var errors = Machine.Ssa.Lowering.Cleanup(function);
            if (errors.Count > 0) throw new InvalidOperationException($"浮点条件归一后 SSA 不成立：{errors[0]}");
        }
        // 已定位的位置保留类型上下文；只拆分尚不能表达的条件地址。
        var selectedMemory = SelectedMemoryPaths.Run(function, graph =>
        {
            var selectedValues = ValueModel.Build(graph, environment);
            var selectedOracle = new TypeOracle(types, facts, method, environment.Shape, selectedValues);
            return statement => statement switch
            {
                Store store => selectedOracle.Locate(selectedValues.Operands(store)[0], store.Value.Width) is null
                    && selectedOracle.Split(selectedValues.Operands(store)[0], store.Value.Width) is null,
                Define => selectedValues.ReadsAt(statement).Any(read => selectedOracle.Locate(read.Address, read.Width) is null
                    && selectedOracle.Split(read.Address, read.Width) is null),
                _ => false,
            };
        });
        var splits = selectedMemory + PathSplitting.Run(function, f => ValueModel.Build(f, environment),
            v => new TypeOracle(types, facts, method, environment.Shape, v), lifter.Calls, lifter.Machine.Convention.StackPointer, rewriter.RecognizeSplitTypeChecks);
        InvokerCallsPass.AfterSplitting(function, method, rewriter);
        // 分派在内存提升之前解析，使经指针的调用效果有签名可依。
        var preliminary = ValueModel.Build(function, environment);
        // 路径拆分后才唯一确定的接收者。
        if (StackBoxingPass.Run(function, new CallMemoryEffects(environment.Shape, abi), environment.Shape, abi.Size, FreshTemporaries(function)))
            preliminary = ValueModel.Build(function, environment);
        var interfaceInvokes = InterfaceInvokeCalls.Run(function, preliminary, facts, abi);
        if (interfaceInvokes) preliminary = ValueModel.Build(function, environment);
        DispatchResolution.Run(function, preliminary, new TypeOracle(types, facts, method, environment.Shape, preliminary));
        if (facts.Model.Image.Architecture == Architecture.X64 && (CallInputSnapshots.Trim(function, environment.Shape) | interfaceInvokes))
        {
            rewriter.ResumeGuards(function, method, idioms);
            if (idioms.Errors.Count > 0) return RecoveryDiagnostics.Fail(entry, $"L2 {idioms.Errors[0]}", rule: "CallInputs");
        }
        // 每轮从稳定输入构建分析图，只累积已证明的调用目标，不回滚生产语句和 SSA。
        var prepared = function;
        var targets = new Dictionary<CallSite, MethodRef>();
        MemoryLayout layout;
        while (true)
        {
            function = prepared.Copy(call => targets.TryGetValue(call.Site, out var target) ? call with { Resolved = target } : call);
            environment = new MethodEnvironment(method, signature, shapes);
            CallResultAliases.Run(function, environment.Shape);
            // 只读共享入口消去后再划分局部内存，避免沿用已不存在调用的地址逃逸。
            while (nativeReads?.RunReads(function, call => environment.Shape(call).Signature is null) > 0)
            {
                var errors = Machine.Ssa.Lowering.Cleanup(function);
                if (errors.Count > 0) return RecoveryDiagnostics.Fail(entry, $"提升 {errors[0]}", rule: "NativeReads");
                // 只读体展开后，原先只为其高位残值保留的合流可能失去用途。
                rewriter.ResumeGuards(function, method, idioms);
                if (idioms.Errors.Count > 0) return RecoveryDiagnostics.Fail(entry, $"L2 {idioms.Errors[0]}", rule: "NativeReadsGuards");
            }
            if (!MemoryPromotion.Run(function, signature, environment.Shape, abi, lifter.Calls, lifter.Machine.Convention.StackPointer).TryGet(out layout, out var memoryFailure))
                return memoryFailure;
            environment.Layout = layout;
            var promoted = ValueModel.Build(function, environment);
            var promotedOracle = new TypeOracle(types, facts, method, environment.Shape, promoted, layout);
            var discovered = DispatchResolution.Find(function, promoted, promotedOracle).ToDictionary();
            foreach (var (site, invoke) in DelegateCallNormalizer.Discover(facts, function, RootType(promotedOracle, promoted)))
                discovered.TryAdd(site, invoke);
            if (discovered.Count == 0) break;
            DispatchResolution.PreserveDiscardedInputs(prepared, discovered, call => shapes.Of(call, method));
            foreach (var (site, target) in discovered) targets.Add(site, target);
        }
        // 活动异常栈的长度字段提升之后才是 SSA 值：栈顶可以按路径求出，读完之后 push 不再被观察。
        // 读取换掉之后，下标地址的定义要清理掉，下一轮才能确认 push 没人读。
        for (var round = 0; round < 3 && (ExceptionStackValues.TopValues(function, new CallMemoryEffects(environment.Shape, abi, settled: true), FreshTemporaries(function)) | ExceptionStackValues.Run(function)); round++)
        {
            var errors = Cpp2CS.Machine.Ssa.Lowering.Cleanup(function);
            if (errors.Count > 0) return RecoveryDiagnostics.Fail(entry, $"L2 {errors[0]}", rule: "ExceptionStack");
        }
        // 帧提升消去异常值的栈副本后，落地跳板可能才成为纯传值链。
        if (StackGuardNormalizer.Run(function))
        {
            var errors = Cpp2CS.Machine.Ssa.Lowering.Cleanup(function);
            if (errors.Count > 0) return RecoveryDiagnostics.Fail(entry, $"L2 {errors[0]}", rule: "StackGuard");
        }
        ExceptionNormalization.Run(function, ExceptionFacts.WrapperWithoutDestructor(facts.Checks));
        environment.Layout = layout;
        while (nativeReads is not null)
        {
            var nativeValues = ValueModel.Build(function, environment);
            var nativeOracle = new TypeOracle(types, facts, method, environment.Shape, nativeValues, layout);
            if (nativeReads.RunReads(function, call => environment.Shape(call).Signature is null || nativeOracle.Callee(call) is null) == 0) break;
            var errors = Machine.Ssa.Lowering.Cleanup(function);
            if (errors.Count > 0) return RecoveryDiagnostics.Fail(entry, $"提升 {errors[0]}", rule: "NativeReads");
            var rewritten = ValueModel.Build(function, environment);
            DispatchResolution.Run(function, rewritten, new TypeOracle(types, facts, method, environment.Shape, rewritten, layout));
            environment = new MethodEnvironment(method, signature, shapes) { Layout = layout };
        }
        var values = ValueModel.Build(function, environment);
        var oracle = new TypeOracle(types, facts, method, environment.Shape, values, layout);
        if (DelegateCallNormalizer.Run(facts, function, idioms, RootType(oracle, values)))
            values = ValueModel.Build(function, environment);
        return new MethodAnalysis(method, entry, signature, function, idioms, layout, values) { Environment = environment, Splits = splits };
    }
}

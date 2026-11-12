using Cpp2CS.Facts;
using Cpp2CS.Ir;

namespace Cpp2CS.Recovery.Calls;

/// <summary>调用点的形状：可能的托管目标及其机器签名。运行时操作没有托管签名。</summary>
public sealed record CallShape(Call Call, IReadOnlyList<MethodRef> Candidates, MachineSignature? Signature)
{
    internal Cpp2CS.Facts.Derived.NativeCallSummary? NativeSummary { get; init; }
    /// <summary>被调方机器码不读取的输入寄存器：原生代码对这些位置的 IL 实参没有约束。</summary>
    public IReadOnlySet<Storage> Unused { get; init; } = new HashSet<Storage>();
    /// <summary>未登记目标的本地副本：x64 由完整机器码见证证明，执行对照按方法体透明执行。</summary>
    public bool LocalCopy { get; init; }
    /// <summary>原生实现不读取寄存器传入的 MethodInfo，可在同签名的共享入口候选间选择可访问声明。</summary>
    public bool MethodInfoUnused { get; init; }
    /// <summary>经运行时分派的托管调用：按托管签名传参，以 callvirt 调用。</summary>
    public bool IsDispatch => Call.Op?.Kind is OpKind.CallVirtual or OpKind.CallInterface or OpKind.CallDelegate or OpKind.CallGenericVirtual or OpKind.InvokeVirtualGeneric or OpKind.InvokeConstrainedGeneric;
    public bool IsRuntime => Call.Op is not null && !IsDispatch
        && !(Call.Op.Kind is OpKind.CallMethodPointer or OpKind.InvokeGeneric && Candidates.Count == 1);

    /// <summary>未知签名阶段记录的多余寄存器，不是已确认机器签名的输入。</summary>
    internal bool OutsideSignature(int argument)
    {
        if (Signature is not { } signature || IsRuntime || argument < Call.Arguments.Length - Call.Sources.Length
            || argument >= Call.Arguments.Length || Call.Memory.Length != 0) return false;
        var source = Call.Sources[argument - (Call.Arguments.Length - Call.Sources.Length)];
        return source.Bank is Bank.Gpr or Bank.Vec && signature.MethodInfo?.Register != source
            && !signature.Arguments.Concat(signature.Indirections).SelectMany(a => a.Pieces).Any(p => p.Register == source);
    }
}

/// <summary>
/// 按事实解析调用目标。直接调用的地址可能被多个方法共用（相同代码折叠），候选全部保留，由类型约束选择；
/// 候选的机器签名不一致时签名为 null。
/// </summary>
public sealed class CallShapes(ProgramFacts facts, ManagedAbi abi, Func<ulong, Storage, bool> unused)
{
    public ProgramFacts Facts => facts;
    private readonly Dictionary<ulong, (MethodRef[] Candidates, MachineSignature? Signature)> direct = [];
    private Cpp2CS.Facts.Derived.EmptyBaseConstructorProof? baseConstructors;
    private Cpp2CS.Facts.Derived.NativeCalleeFacts? aliasInputs;

    public CallShape Of(Call call) => Of(call, null);

    public CallShape Of(Call call, MethodRef? caller)
    {
        if (call.Op is { Kind: OpKind.InvokeGeneric or OpKind.InvokeVirtualGeneric, Operand: MethodRef invoked })
            return new(call, [invoked], abi.Invoker(invoked));
        if (call.Op is { Kind: OpKind.InvokeConstrainedGeneric, Operand: ValueTuple<TypeRef, MethodRef> constrained })
            return new(call, [constrained.Item2], abi.ConstrainedInvoker(constrained.Item1, constrained.Item2));
        if (call.Resolved is { } resolved)
            return new(call, [resolved], CallSignature(abi.Machine(resolved, out _)));
        if (call.Op is { Operand: MethodRef method } && call.Op.Kind is OpKind.CallGenericVirtual or OpKind.InvokeGeneric or OpKind.CallMethodPointer)
            return new(call, [method], CallSignature(abi.Machine(method, out _)));
        if (call is { Op: null, Kind: CallKind.Direct or CallKind.Tail, Target: Const target })
        {
            var (candidates, signature) = Direct(target.Value);
            if (signature is null && caller is not null && facts.Model.Image.Architecture == Architecture.X64
                && (baseConstructors ??= new(facts, abi)).Resolve(call, caller, candidates) is { } constructor)
            {
                candidates = [constructor];
                signature = abi.Machine(constructor, out _);
            }
            var named = signature is null ? Named(call, candidates) : null;
            if (named is var (instance, namedSignature)) (candidates, signature) = ([instance], namedSignature);
            var ignored = signature?.Arguments.SelectMany(a => a.Pieces).Select(p => p.Register)
                .Where(r => r.Bank is Bank.Gpr or Bank.Vec && unused(target.Value, r)).ToHashSet() ?? [];
            return new(call, candidates, CallSignature(signature)) { Unused = ignored,
                NativeSummary = signature is null ? facts.NativeCalls.At(target.Value) : null,
                MethodInfoUnused = facts.Model.Image.Architecture == Architecture.X64 && candidates.Length > 1
                    && signature?.MethodInfo is { Register.Bank: Bank.Gpr } info
                    && facts.Code.At(target.Value) is { HasUnmodeledExceptions: false } range && range.Start == target.Value
                    && ((aliasInputs ??= new(facts, true)).UnusedInput(target.Value, info.Register)
                        || Cpp2CS.Facts.Derived.RuntimeIcallProof.IgnoresMethodInfo(facts, target.Value, candidates, signature)),
                LocalCopy = signature is not null && facts.EntriesAt(target.Value).Length == 0
                    && (named is not null || facts.NativeCopies.At(target.Value).Length > 0) };
        }
        return new(call, [], null);
    }

    private MachineSignature? CallSignature(MachineSignature? signature)
    {
        if (signature is null || facts.Model.Image.Architecture != Architecture.X64) return signature;
        // 调用点 RSP 尚未压入返回地址，入口栈槽相对调用点前移八字节。
        static AbiPiece Piece(AbiPiece p) => p.Register.Bank == Bank.Stack ? p with { Register = Storage.Slot(p.Register.Index - 8) } : p;
        return signature with
        {
            Arguments = signature.Arguments.Select(a => a with { Pieces = a.Pieces.Select(Piece).ToArray() }).ToArray(),
            MethodInfo = signature.MethodInfo is { } info ? Piece(info) : null,
        };
    }

    private (MethodRef[], MachineSignature?) Direct(ulong address)
    {
        if (direct.TryGetValue(address, out var known)) return known;
        var candidates = facts.EntriesAt(address)
            .Where(e => e.Kind is EntryKind.Method or EntryKind.GenericMethod && e.Method is not null)
            .Select(e => e.Method!).Distinct().ToArray();
        if (candidates.Length == 0) candidates = facts.NativeCopies.At(address).Select(e => e.Method!).Distinct().ToArray();
        if (candidates.Length == 0 && facts.AdjustorTargets.At(address) is { } adjusted) candidates = [adjusted.Method];
        // 未登记在方法指针表中的方法：事实层由调用证据推断出定义，实例取自见证。
        if (candidates.Length == 0 && facts.Unregistered.At(address) is { } inferred)
            candidates = inferred.Witnesses.Select(w => w.Instance).Distinct().DefaultIfEmpty(new MethodRef(inferred.Definition, [], [])).ToArray();
        var signatures = candidates.Select(c => abi.Machine(c, out _)).ToArray();
        var signature = signatures.Length > 0 && signatures.All(s => s is not null && SameShape(s, signatures[0]!)) ? signatures[0] : null;
        return direct[address] = (candidates, signature);
    }

    /// <summary>
    /// 共享泛型代码的调用传入确切实例的 MethodInfo：某个实参是方法实体，且该方法签名的 MethodInfo 正落在这个实参的寄存器上时，
    /// 还须与直接目标的已知定义一致；x64 未知入口不单凭残留寄存器推断方法身份。
    /// </summary>
    private (MethodRef, MachineSignature)? Named(Call call, IReadOnlyList<MethodRef> candidates)
    {
        // 寄存器可能仍保存调用者自己的 MethodInfo，不能据此覆盖直接目标的注册身份。
        for (var i = 0; i < call.Arguments.Length && i < call.Sources.Length; i++)
            if (call.Arguments[i] is Symbol { Kind: SymbolKind.Method, Value: MethodRef method }
                && (candidates.Count == 0 || candidates.Any(c => c.Method == method.Method))
                && abi.Machine(method, out _) is { MethodInfo: { } info } signature && info.Register == call.Sources[i]
                && (candidates.Count != 0 || facts.Model.Image.Architecture != Architecture.X64
                    || call.Target is Const target && facts.NativeCopies.Matches(target.Value, method)))
                return (method, signature);
        return null;
    }

    /// <summary>直接调用目标的各候选及其机器签名（检查用）。</summary>
    public IEnumerable<(MethodRef Method, MachineSignature? Signature, string? Problem)> Candidates(ulong address) =>
        Direct(address).Item1.Select(c => (c, abi.Machine(c, out var problem), problem));

    /// <summary>两个签名占用相同的机器位置并有相同的内存效果。</summary>
    internal static bool SameShape(MachineSignature a, MachineSignature b) =>
        a.Arguments.Length == b.Arguments.Length && a.Arguments.Zip(b.Arguments).All(p => Same(p.First, p.Second))
        && (a.Return is null) == (b.Return is null) && (a.Return is null || Same(a.Return, b.Return!))
        && a.MethodInfo == b.MethodInfo && a.BufferPointerResult == b.BufferPointerResult;

    private static bool Same(MachineValue a, MachineValue b) => a.Index == b.Index && a.Transfer == b.Transfer && a.Size == b.Size
        && a.Access == b.Access && a.Pieces.AsSpan().SequenceEqual(b.Pieces);
}

using Cpp2CS.Idioms;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Lifting;
using Cpp2CS.Machine.Ssa;

namespace Cpp2CS.Facts.Derived;

/// <summary>完整元数据守卫归一后的原生副本；比较返回、非易失寄存器、调用和内存效果。</summary>
internal sealed class GuardedNativeCopyProof(ProgramFacts facts)
{
    private readonly Dictionary<(ulong, Storage, int), string?> shapes = new();
    private readonly Dictionary<object, int> identities = new();
    private readonly Dictionary<ulong, bool> hasMetadataInitializer = new();
    internal readonly Dictionary<(ulong, Storage, int), string> Rejections = new();
    private readonly IMachine machine = facts.CreateMachine();

    internal bool Matches(ulong candidate, ulong witness, IEnumerable<MethodRef> methods)
    {
        var returns = methods.Select(m => facts.CreateAbi().Machine(m, out _)?.Return).ToArray();
        if (returns.Length == 0 || returns.Any(r => r is not { Transfer: Transfer.Value, Pieces.Length: 1, Size: > 0 and <= 8 })) return false;
        var pieces = returns.Select(r => r!.Pieces[0]).Distinct().ToArray();
        if (pieces is not [var piece] || piece.Width is <= 0 or > 64) return false;
        var left = Shape(candidate, piece.Register, piece.Width);
        return left is not null && left == Shape(witness, piece.Register, piece.Width);
    }

    private string? Shape(ulong entry, Storage returned, int width)
    {
        var key = (entry, returned, width);
        if (shapes.TryGetValue(key, out var known)) return known;
        shapes[key] = null;
        string? Reject(string reason) { Rejections[key] = reason; return null; }
        if (facts.Usages is null || facts.Helpers is null
            || facts.Code.At(entry) is not { Start: var start, HasUnmodeledExceptions: false, Size: > 5 and <= 1024 } range || start != entry) return Reject("元数据事实或函数边界不完整");
        if (!HasMetadataInitializer(entry, range.End)) return Reject("没有已识别的元数据初始化调用");
        // 证明过程仅用保守调用契约，不查询待证明的副本身份，避免循环自证。
        var calls = new FactsCallModel(facts, machine.Convention, useNativeCopies: false);
        var lifter = new FunctionLifter(facts, calls);
        var preserved = Enumerable.Range(0, 16).Select(Storage.Gpr).Concat(Enumerable.Range(0, 16).Select(Storage.Vec))
            .Where(s => !machine.Convention.Clobbered.Contains(s)).ToArray();
        ReturnPiece[] outputs = [new(0, new Read(returned, width)),
            .. preserved.Select((s, i) => new ReturnPiece((i + 1) * 16, new Read(s, s.Width)))];
        var lifted = lifter.Lift(entry, null, outputs, simplify: true, promoteFrameSlots: false);
        if (!lifted.Succeeded) return Reject(string.Join("；", lifted.Errors));
        if (lifted.Function.Blocks.SelectMany(b => b.Statements).Any(s => s is IndirectJump
            || s is Call { Kind: not CallKind.Direct })) return Reject("包含间接跳转或非普通直接调用");
        var function = lifted.Function;
        var rewriter = new IdiomRewriter(facts) { RecordFilter = _ => false };
        var state = new IdiomState(rewriter, function);
        for (var round = 0; round < 8; round++)
        {
            MetadataLoadsPass.Run(function, facts.Usages, state.Result, facts.Base.RuntimeOffsets?.ClassStaticFields, facts.Base.RuntimeOffsets?.MethodClass);
            state.defs = new IdiomRewriter.Defs(function);
            if (!state.Guards()) break;
            if (Lowering.Cleanup(function).Count != 0) return Reject("守卫改写后 SSA 不完整");
            state.removed.Clear();
        }
        if (state.Result.Guards.Count == 0 || state.Result.Errors.Count != 0
            || Lowering.Cleanup(function).Count != 0) return Reject("没有通过完整证明的元数据守卫");
        // 死值清理不能为副本证明隐藏可能抛出的读取；只豁免已建模的运行时元数据。
        if (function.Dead.SelectMany(d => ExprMap.Walk(d.Define.Value)).OfType<Load>().Any(load => !MetadataRead(load)))
            return Reject("存在未保留的原生内存读取");
        var lines = new List<string>();
        lines.Add("guards:" + string.Join(';', state.Result.GuardSlots.Values.Select(slots => string.Join(',', slots
            .Select(slot => facts.Usages.At(slot)!.Usage).Select(usage => $"{usage.Kind}:{Identity(usage.Value)}").Order()))
            .Order()));
        foreach (var block in function.Blocks)
        {
            if (block.Handler is not null || block.IsLandingPad) return Reject("包含异常路径");
            lines.Add($"block:{block.Start - entry:x}:" + string.Join(',', block.Successors.Select(b => b.Start - entry)));
            foreach (var statement in block.Statements.Where(s => s is not Nop))
            {
                var normalized = ExprMap.MapOperands(statement, e => ExprMap.Map(e, node => node is Symbol symbol
                    ? new Symbol(symbol.Kind, Identity(symbol.Value)) : null));
                if (normalized is Call { Op: { } op } runtimeCall)
                    normalized = runtimeCall with { Op = op with { Operand = op.Operand is { } operand ? Identity(operand) : null } };
                var description = normalized switch
                {
                    Call call => $"{call};sp:{call.StackPointer};sources:{string.Join(',', call.Sources)};results:{string.Join(',', call.Results)};noreturn:{call.DoesNotReturn}",
                    Branch branch => $"branch:{branch.Condition}:{Target(branch.Target)}:{Target(branch.Fallthrough)}",
                    Jump jump => $"jump:{Target(jump.Target)}",
                    _ => normalized.ToString(),
                };
                lines.Add($"{statement.Address - entry:x}:{description}");
            }
        }
        return shapes[key] = string.Join('\n', lines);

        string Target(ulong address) => range.Contains(address) ? $"local:{address - entry:x}" : $"absolute:{address:x}";
        bool MetadataRead(Load load) => load switch
        {
            { Address: Const address, Width: 8 } when state.Result.GuardSlots.ContainsKey(address.Value) => true,
            { Address: Const address, Width: 64 } when facts.Usages.At(address.Value) is not null => true,
            { Address: Binary { Op: BinOp.Add, Left: Symbol { Kind: SymbolKind.Class }, Right: Const offset }, Width: 32 }
                when state.Result.Hits.GetValueOrDefault(Template.ClassConstructorGuard) > 0
                    && facts.Base.RuntimeOffsets?.ClassCctorFinished is { } finished && offset.Value == (ulong)finished => true,
            _ => false,
        };
    }

    private int Identity(object value)
    {
        if (!identities.TryGetValue(value, out var id)) identities.Add(value, id = identities.Count);
        return id;
    }

    private bool HasMetadataInitializer(ulong entry, ulong end)
    {
        if (hasMetadataInitializer.TryGetValue(entry, out var known)) return known;
        for (var pc = entry; pc < end;)
        {
            var statements = new List<Stmt>();
            var size = machine.Lift(pc, statements);
            if (size <= 0 || (ulong)size > end - pc) break;
            if (statements.OfType<Call>().Any(c => c.Target is Const target && facts.Helpers.At(target.Value)?.Kind == HelperKind.InitMetadata))
                return hasMetadataInitializer[entry] = true;
            pc += (ulong)size;
        }
        return hasMetadataInitializer[entry] = false;
    }
}

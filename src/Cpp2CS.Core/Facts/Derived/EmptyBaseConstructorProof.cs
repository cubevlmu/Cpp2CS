using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;

namespace Cpp2CS.Facts.Derived;

/// <summary>构造链调用：入口 this、直接基类无参构造及无可观察效果的原生见证。</summary>
internal sealed class EmptyBaseConstructorProof(ProgramFacts facts, ManagedAbi abi)
{
    private readonly IMachine machine = facts.CreateMachine();
    private readonly Dictionary<(ulong Entry, ulong Site, ulong Target), bool> native = new();
    private readonly Dictionary<ulong, bool> empty = new();

    internal bool ReturnsOnly(ulong entry)
    {
        if (empty.TryGetValue(entry, out var known)) return known;
        empty[entry] = false;
        return empty[entry] = ReturnPath(entry, new HashSet<ulong>(), 0);
    }

    private bool ReturnPath(ulong entry, HashSet<ulong> visited, int depth)
    {
        if (depth >= 4 || !visited.Add(entry)
            || facts.Code.At(entry) is not { Start: var start, HasUnmodeledExceptions: false, Size: > 0 } range || start != entry) return false;
        var constants = new Dictionary<Storage, Expr>();
        var instructions = 0;
        for (var pc = entry; pc < range.End;)
        {
            var statements = new List<Stmt>();
            var length = machine.Lift(pc, statements);
            if (length <= 0 || (ulong)length > range.End - pc || pc - entry + (ulong)length > 96 || ++instructions > 16) return false;
            pc += (ulong)length;
            foreach (var statement in statements)
            {
                switch (statement)
                {
                    case Assign a when facts.Model.Image.Architecture == Architecture.X64
                        && (a.Target == Storage.Gpr(2) || a.Target.Bank == Bank.Temp):
                        if (ExprMap.Walk(a.Value).Any(e => e is Load or Intrinsic or Unknown)) return false;
                        var value = Fold.Simplify(ExprMap.Map(a.Value, e => e is Read r && constants.TryGetValue(r.Storage, out var c)
                            ? Fold.Convert(ConvKind.Truncate, c, r.Width) : null));
                        if (value is not Const) return false;
                        constants[a.Target] = value;
                        break;
                    case Return:
                        return statements[^1] == statement && ClearedInfo();
                    case Jump jump when facts.Model.Image.Architecture == Architecture.X64:
                        return statements[^1] == statement && ClearedInfo() && ReturnPath(jump.Target, visited, depth + 1);
                    case Nop: break;
                    default: return false;
                }
            }
        }
        return false;

        // 无参实例构造的隐藏参数在 RDX；跳板只允许清零它及常量标志，不改 this、栈或内存。
        bool ClearedInfo() => !constants.TryGetValue(Storage.Gpr(2), out var value) || value is Const { Value: 0 };
    }

    internal MethodRef? Resolve(Call call, MethodRef caller, IReadOnlyList<MethodRef> candidates, MachineFunction? function = null)
    {
        if (facts.Model.Image.Architecture != Architecture.X64 || caller.Method is not { Name: ".ctor", IsStatic: false, Owner.IsValueType: false }
            || caller.Method.Owner.BaseType?.Substitute(caller.TypeArguments, []) is not DefinitionRef parent
            || call.Target is not Const target || call.Kind is not (CallKind.Direct or CallKind.Tail)
            || abi.Machine(caller, out _)?.This?.Pieces is not [{ Register: var receiver }]) return null;
        var bases = candidates.Where(m => m.Method is { Name: ".ctor", IsStatic: false, Parameters.Count: 0, GenericParameters.Count: 0 }
            && m.Method.Owner == parent.Definition && ManagedTypes.IsVoid(m.Method.ReturnType)).Select(m => m.Method).Distinct().ToArray();
        // 编译器可跳过空构造跳板；仅以直接基类唯一的空实现作独立见证。
        if (bases.Length == 0)
            bases = parent.Definition.Methods.Where(m => m is { Name: ".ctor", IsStatic: false, Parameters.Count: 0, GenericParameters.Count: 0, Address: not 0 }
                && ManagedTypes.IsVoid(m.ReturnType) && ReturnsOnly(m.Address)).ToArray();
        if (bases is not [var definition] || Array.IndexOf(call.Sources, receiver) is not (var at and >= 0)
            || at >= call.Arguments.Length || call.Arguments[at] is not Use { Width: 64, Variable.Version: 0 } input
            || input.Variable.Storage != receiver) return null;
        var key = (caller.Method.Address, call.Address, target.Value);
        if (!native.TryGetValue(key, out var proven)) native[key] = proven = Native(key);
        if (!proven && (function is null || !Site((function.Entry, call.Address, target.Value)) || !Prefix(function, call, receiver))) return null;
        return new MethodRef(definition, parent.Arguments, []);
    }

    /// <summary>有 SSA 时允许字段初始化、非 this 调用和分支；构造初始化合法性仍由公共写出检查验证。</summary>
    internal int Bind(MachineFunction function, MethodRef caller)
    {
        if (facts.Model.Image.Architecture != Architecture.X64 || caller.Method is not { Name: ".ctor", IsStatic: false, Owner.IsValueType: false }) return 0;
        var count = 0;
        foreach (var block in function.Blocks)
            for (var i = 0; i < block.Statements.Count; i++)
            {
                if (block.Statements[i] is not Call { Op: null, Resolved: null, Kind: CallKind.Direct or CallKind.Tail, Target: Const target } call) continue;
                var candidates = facts.EntriesAt(target.Value).Select(e => e.Method).OfType<MethodRef>().Distinct().ToArray();
                if (candidates.Length < 2 || Resolve(call, caller, candidates, function) is not { } constructor) continue;
                block.Statements[i] = call with { Resolved = constructor };
                count++;
            }
        return count;
    }

    private bool Prefix(MachineFunction function, Call call, Storage receiver)
    {
        var site = function.Blocks.SingleOrDefault(b => b.Statements.Any(s => ReferenceEquals(s, call)));
        if (site is null || site.Handler is not null || site.IsLandingPad) return false;
        var dominators = Cpp2CS.Machine.Ssa.Dominators.Compute(function);
        if (function.Blocks.Where(b => b.Statements.Any(s => s is Return)).Any(b => !dominators.Dominates(site.Index, b.Index))) return false;
        var definitions = function.Blocks.SelectMany(b => b.Statements).OfType<Define>().ToDictionary(d => d.Target, d => d.Value);
        foreach (var (_, dead) in function.Dead) definitions.TryAdd(dead.Target, dead.Value);
        var phis = function.Blocks.SelectMany(b => b.Statements).OfType<Phi>().ToDictionary(p => p.Target, p => p.Sources);
        bool UsesThis(Expr expression)
        {
            var pending = new Stack<Expr>(); pending.Push(expression);
            var seen = new HashSet<Variable>(); var budget = 4096;
            while (pending.TryPop(out var part))
            {
                if (--budget < 0) return true;
                if (part is Use use)
                {
                    if (use.Variable.Version == 0 && use.Variable.Storage == receiver) return true;
                    if (!seen.Add(use.Variable)) continue;
                    if (definitions.TryGetValue(use.Variable, out var value)) pending.Push(value);
                    if (phis.TryGetValue(use.Variable, out var sources))
                        foreach (var source in sources) pending.Push(new Use(source, source.Width));
                }
                else foreach (var child in ExprMap.Children(part)) pending.Push(child);
            }
            return false;
        }
        bool ReadsThis(Expr expression) => ExprMap.Walk(expression).OfType<Load>().Any(l => UsesThis(l.Address));
        var nativeCalls = new Cpp2CS.Machine.Lifting.FactsCallModel(facts, machine.Convention);
        var visited = new HashSet<Block>(); var ready = new Stack<Block>(); ready.Push(function.EntryBlock);
        var remaining = 8192; var reached = false;
        while (ready.TryPop(out var block))
        {
            if (!visited.Add(block)) continue;
            if (block.Handler is not null || block.IsLandingPad) return false;
            foreach (var statement in block.Statements)
            {
                if (--remaining < 0) return false;
                if (ReferenceEquals(statement, call)) { reached = true; break; }
                if (ExprMap.Operands(statement).Any(ReadsThis)) return false;
                switch (statement)
                {
                    case Call previous:
                        if (UsesThis(previous.Target)) return false;
                        // 已证明的 GC 通知由托管字段写入隐式承担，不把字段地址交给用户代码。
                        if (previous.Op?.Kind == OpKind.WriteBarrier) break;
                        if (previous.Op is not null)
                        {
                            if (previous.Arguments.Any(UsesThis)) return false;
                            break;
                        }
                        if (previous.Target is not Const target || nativeCalls.Signature(target.Value) is not { } signature) return false;
                        foreach (var input in signature.Reads.Where(s => s != signature.MethodInfo))
                            if (previous.ArgumentIndex(input) is not (var at and >= 0) || UsesThis(previous.Arguments[at])) return false;
                        break;
                    case Store store:
                        // 入口 this 可以出现在字段写入地址中，不能作为值存出；公共构造检查再核对字段归属。
                        if (UsesThis(store.Value)) return false;
                        break;
                    case Branch branch when UsesThis(branch.Condition): return false;
                    case IndirectJump or Return or Trap or Opaque: return false;
                }
            }
            if (block == site) continue;
            foreach (var successor in block.NormalSuccessors) ready.Push(successor);
        }
        return reached;
    }

    private bool Site((ulong Entry, ulong Site, ulong Target) key)
    {
        if (facts.Code.At(key.Entry) is not { HasUnmodeledExceptions: false } caller || caller.Start != key.Entry
            || !caller.Contains(key.Site) || !ReturnsOnly(key.Target)) return false;
        var statements = new List<Stmt>();
        var length = machine.Lift(key.Site, statements);
        return length > 0 && (ulong)length <= caller.End - key.Site && statements.Any(s => s is Call { Target: Const target } && target.Value == key.Target
            || s is Jump jump && jump.Target == key.Target);
    }

    private bool Native((ulong Entry, ulong Site, ulong Target) key)
    {
        if (facts.Code.At(key.Entry) is not { HasUnmodeledExceptions: false } caller || caller.Start != key.Entry
            || !caller.Contains(key.Site) || key.Site - key.Entry > 256
            || facts.Code.At(key.Target) is not { HasUnmodeledExceptions: false } target || target.Start != key.Target) return false;
        var statements = new List<Stmt>();
        if (!ReturnsOnly(key.Target)) return false;
        for (var pc = key.Entry; pc < key.Site;)
        {
            statements.Clear();
            var length = machine.Lift(pc, statements);
            if (length <= 0 || pc + (ulong)length > key.Site
                || statements.Any(s => s is Call or Jump or Branch or IndirectJump or Return or Opaque or Trap)) return false;
            pc += (ulong)length;
        }
        statements.Clear();
        var callLength = machine.Lift(key.Site, statements);
        return callLength > 0 && (ulong)callLength <= caller.End - key.Site && statements.Any(s => s is Call { Target: Const address } && address.Value == key.Target
            || s is Jump jump && jump.Target == key.Target);
    }
}

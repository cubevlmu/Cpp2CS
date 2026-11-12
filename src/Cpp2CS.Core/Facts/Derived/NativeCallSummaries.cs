using System.Collections.Concurrent;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Storage;

namespace Cpp2CS.Facts.Derived;

/// <summary>完整直线原生体的机器事实；Body 保留访存顺序，不能仅凭返回关系删除效果。</summary>
internal sealed record NativeCallSummary(ulong Entry, IReadOnlyList<Stmt> Body, Ir.Storage[] Inputs,
    Ir.Storage[] Written, IReadOnlyDictionary<Ir.Storage, Expr> Returns, bool WritesMemory,
    IReadOnlyDictionary<Ir.Storage, ArgumentUse> Arguments);

/// <summary>缓存属于当前映像事实实例；未知、超预算和带异常处理的目标不产生摘要。</summary>
internal sealed class NativeCallSummaries(ProgramFacts facts)
{
    private readonly ConcurrentDictionary<ulong, Lazy<NativeCallSummary?>> cache = new();

    internal NativeCallSummary? At(ulong entry) => facts.Model.Image.Architecture != Architecture.X64 ? null
        : cache.GetOrAdd(entry, target => new(() => Build(target))).Value;

    private NativeCallSummary? Build(ulong entry)
    {
        if (facts.Helpers?.At(entry) is { Kind: not HelperKind.Unknown }
            || facts.Code.At(entry) is not { Start: var start, Size: > 1 and <= 96,
                HasUnmodeledExceptions: false, ExceptionRegions.Length: 0 } range || start != entry) return null;
        var machine = facts.CreateMachine();
        var body = new List<Stmt>();
        var instructions = 0;
        var ended = false;
        bool Writable(Ir.Storage storage) => storage.Bank == Bank.Temp && (storage.Index >= 1000 || machine.Convention.Clobbered.Contains(storage))
            || storage.Bank is Bank.Gpr or Bank.Vec && machine.Convention.Clobbered.Contains(storage);
        bool Movable(Expr expression) => expression switch
        {
            Const => true,
            Read r => r.Storage != machine.Convention.StackPointer && (r.Storage.Bank is Bank.Gpr or Bank.Vec
                || r.Storage.Bank == Bank.Temp && (r.Storage.Index >= 1000 || machine.Convention.Clobbered.Contains(r.Storage))),
            Load l => Movable(l.Address),
            Binary { Op: BinOp.Add or BinOp.Sub or BinOp.Mul or BinOp.And or BinOp.Or or BinOp.Xor or BinOp.Shl or BinOp.LShr or BinOp.AShr } b
                => Movable(b.Left) && Movable(b.Right),
            Compare c => Movable(c.Left) && Movable(c.Right),
            Select s => Movable(s.Condition) && Movable(s.True) && Movable(s.False),
            Unary { Op: UnOp.PopCount } u => Movable(u.Operand),
            Not n => Movable(n.Operand),
            Logical l => Movable(l.Left) && Movable(l.Right),
            Ir.Convert { Kind: ConvKind.ZeroExtend or ConvKind.SignExtend or ConvKind.Truncate or ConvKind.Bitcast } c => Movable(c.Operand),
            Extract e => Movable(e.Operand),
            Insert i => Movable(i.Base) && Movable(i.Value),
            _ => false,
        };
        for (var pc = entry; pc < range.End;)
        {
            var statements = new List<Stmt>();
            var length = machine.Lift(pc, statements);
            if (length <= 0 || pc + (ulong)length > range.End || ++instructions > 32) return null;
            pc += (ulong)length;
            if (statements.LastOrDefault() is Return)
            {
                var padding = machine.Image.ReadUpTo(pc, (int)(range.End - pc));
                if (padding.Length != (int)(range.End - pc) || padding.ContainsAnyExcept((byte)0x90, (byte)0xcc)) return null;
                statements.RemoveAt(statements.Count - 1); ended = true;
            }
            foreach (var statement in statements)
            {
                if (statement is not (Assign or Store or Nop) || statement is Assign a && !Writable(a.Target)
                    || ExprMap.Operands(statement).Any(e => !Movable(e))) return null;
                body.Add(statement);
            }
            if (ended) break;
        }
        if (!ended || !body.Any(s => s is Assign or Store)) return null;
        var inputs = new HashSet<Ir.Storage>();
        var state = new Dictionary<Ir.Storage, Expr>();
        var reads = new List<Load>();
        var stores = body.OfType<Store>().Any();
        var budget = 4096;
        foreach (var statement in body)
        {
            foreach (var read in ExprMap.Operands(statement).SelectMany(ExprMap.Walk).OfType<Read>())
                if (!state.ContainsKey(read.Storage))
                {
                    // 未定义的 unique 或标志输入不能冒充机器参数。
                    if (read.Storage.Bank is not (Bank.Gpr or Bank.Vec)) return null;
                    inputs.Add(read.Storage);
                }
            Expr Substitute(Expr expression) => Fold.Simplify(ExprMap.Map(expression, e => e is Read read && state.TryGetValue(read.Storage, out var value)
                ? Fold.Convert(ConvKind.Truncate, value, read.Width) : null));
            foreach (var operand in ExprMap.Operands(statement))
            {
                var normalized = Substitute(operand);
                var nodes = ExprMap.Walk(normalized).ToArray();
                budget -= nodes.Length;
                if (budget < 0) return null;
                reads.AddRange(nodes.OfType<Load>());
            }
            if (statement is Assign assign)
            {
                var value = Substitute(assign.Value);
                state[assign.Target] = value.Width < assign.Target.Width ? Fold.Convert(ConvKind.ZeroExtend, value, assign.Target.Width) : value;
            }
        }
        var written = body.OfType<Assign>().Select(a => a.Target).Where(s => s.Bank is Bank.Gpr or Bank.Vec).Distinct().ToArray();
        var returns = state.Where(p => machine.Convention.IntegerResults.Contains(p.Key) || machine.Convention.FloatResults.Contains(p.Key))
            .ToDictionary(p => p.Key, p => p.Value);
        var arguments = new Dictionary<Ir.Storage, ArgumentUse>();
        foreach (var input in inputs)
        {
            // 写入目标、存储值及返回别名的捕获尚未证明时保持未知。
            if (stores || returns.Values.Any(v => Escapes(v, input))) { arguments[input] = ArgumentUse.Unknown; continue; }
            var access = 0; var unknown = false;
            foreach (var load in reads)
            {
                if (!ExprMap.Walk(load.Address).OfType<Read>().Any(r => r.Storage == input)) continue;
                var offset = load.Address switch
                {
                    Read { Width: 64 } r when r.Storage == input => 0L,
                    Binary { Width: 64, Op: BinOp.Add, Left: Read r, Right: Const c } when r.Storage == input => c.Signed,
                    _ => -1,
                };
                var length = (load.Width + 7) / 8;
                if (offset < 0 || offset > int.MaxValue - length) { unknown = true; break; }
                access = Math.Max(access, (int)offset + length);
            }
            arguments[input] = unknown ? ArgumentUse.Unknown : access == 0 ? ArgumentUse.None : new(access, MemoryAccess.Read, false);
        }
        return new(entry, body.ToArray(), inputs.ToArray(), written, returns, stores, arguments);
    }

    private static bool Escapes(Expr value, Ir.Storage input) => value switch
    {
        // 指针宽度的返回读取可能把槽内保存的另一个帧地址带出；缺少返回别名消费者时保守保留捕获。
        Load load => load.Width >= 64 && ExprMap.Walk(load.Address).OfType<Read>().Any(r => r.Storage == input),
        Read r => r.Storage == input,
        _ => ExprMap.Children(value).Any(v => Escapes(v, input)),
    };
}

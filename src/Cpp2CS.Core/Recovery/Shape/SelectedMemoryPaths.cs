using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Ssa;

namespace Cpp2CS.Recovery.Shape;

/// <summary>地址中的纯条件选择下降为互斥访存路径，不提前读取未选中的位置。</summary>
internal static class SelectedMemoryPaths
{
    private const ulong SyntheticBase = 0xffff_ffe0_0000_0000;

    internal static int Run(MachineFunction function, Func<MachineFunction, Func<Stmt, bool>>? unresolved = null)
    {
        var count = 0;
        for (var round = 0; round < 32; round++)
        {
            Func<Stmt, bool>? needsSplit = null;
            bool Allowed(Stmt statement)
            {
                needsSplit ??= unresolved?.Invoke(function);
                return needsSplit?.Invoke(statement) != false;
            }
            var definitions = function.Blocks.SelectMany(b => b.Statements).OfType<Define>().ToDictionary(d => d.Target, d => d.Value);
            Expr? Expand(Expr expression)
            {
                var remaining = 512;
                var exhausted = false;
                Expr Visit(Expr value, int depth) => ExprMap.Map(value, node =>
                {
                    if (--remaining < 0 || depth == 0) { exhausted = true; return node; }
                    return node is Use use && definitions.TryGetValue(use.Variable, out var source) && Pure(source)
                        ? Visit(source, depth - 1) : null;
                });
                var expanded = Visit(expression, 32);
                return exhausted ? null : expanded;
            }
            (Block Block, int Index, Stmt Statement, Load? Load, Expr Address, Select Selection)? found = null;
            foreach (var block in function.Blocks.Where(b => b.Handler is null && !b.IsLandingPad))
            {
                for (var index = 0; index < block.Statements.Count; index++)
                {
                    var statement = block.Statements[index];
                    if (statement is Define define)
                    {
                        foreach (var load in RequiredLoads(define.Value))
                        {
                            var address = Expand(load.Address);
                            if (address is null || Choice(address) is not { } selection || !Allowed(statement)) continue;
                            found = (block, index, statement, load, address, selection); break;
                        }
                    }
                    else if (statement is Store store)
                    {
                        var address = Expand(store.Target);
                        if (address is not null && Choice(address) is { } selection && Allowed(statement)) found = (block, index, statement, null, address, selection);
                    }
                    if (found is not null) break;
                }
                if (found is not null) break;
            }
            if (found is not { } item) break;
            Split(function, item.Block, item.Index, item.Statement, item.Load, item.Address, item.Selection);
            var errors = Machine.Ssa.Lowering.Cleanup(function);
            if (errors.Count != 0) throw new InvalidOperationException($"条件访存路径拆分后 SSA 不成立：{errors[0]}");
            count++;
        }
        return count;
    }

    private static IEnumerable<Load> RequiredLoads(Expr expression)
    {
        if (expression is Select) yield break;
        if (expression is Load load) { yield return load; yield break; }
        foreach (var child in ExprMap.Children(expression))
            foreach (var read in RequiredLoads(child)) yield return read;
    }

    private static bool Pure(Expr expression) => ExprMap.Walk(expression).All(e => e switch
    {
        Const or Use or Entry or FrameAddress or Symbol => true,
        Select or Extract or Insert or Compare or Not or Logical => true,
        Cpp2CS.Ir.Convert { Kind: ConvKind.ZeroExtend or ConvKind.SignExtend or ConvKind.Truncate or ConvKind.Bitcast } => true,
        Binary { Op: BinOp.Add or BinOp.Sub or BinOp.Mul or BinOp.And or BinOp.Or or BinOp.Xor or BinOp.Shl or BinOp.LShr or BinOp.AShr or BinOp.Ror } => true,
        _ => false,
    });

    private static Select? Choice(Expr address) => address.Width == 64 && Pure(address)
        ? ExprMap.Walk(address).OfType<Select>().FirstOrDefault(s => s.Width == 64 && Pure(s.Condition)) : null;

    private static void Split(MachineFunction function, Block block, int index, Stmt statement, Load? load, Expr address, Select selection)
    {
        var used = function.Blocks.Select(b => b.Start).ToHashSet();
        var nextAddress = SyntheticBase;
        ulong FreshAddress() { while (!used.Add(nextAddress)) nextAddress++; return nextAddress++; }
        var taken = new Block(FreshAddress()) { End = block.End };
        var fallthrough = new Block(FreshAddress()) { End = block.End };
        var merge = new Block(FreshAddress()) { End = block.End };
        var tail = block.Statements.Skip(index + 1).ToArray();
        var successors = block.Successors.ToArray();
        foreach (var successor in successors)
            for (var p = 0; p < successor.Predecessors.Count; p++)
                if (successor.Predecessors[p] == block) successor.Predecessors[p] = merge;
        merge.Successors.AddRange(successors);
        block.Successors.Clear();
        block.Statements.RemoveRange(index, block.Statements.Count - index);
        block.Statements.Add(new Branch(statement.Address, selection.Condition, taken.Start, fallthrough.Start));
        MachineFunction.AddEdge(block, taken); MachineFunction.AddEdge(block, fallthrough);

        Expr Address(bool side) => Fold.Simplify(ExprMap.Map(address, e => ReferenceEquals(e, selection) ? side ? selection.True : selection.False : null));
        Stmt Arm(bool side)
        {
            if (statement is Store store) return store with { Target = Address(side) };
            var define = (Define)statement;
            return define with { Value = ExprMap.Map(define.Value, e => ReferenceEquals(e, load) ? load! with { Address = Address(side) } : null) };
        }
        if (statement is Define original)
        {
            var next = function.Blocks.SelectMany(b => b.Statements).SelectMany(s => s switch
                { Define d => new[] { d.Target }, Phi p => [p.Target], Call c => c.Defines, _ => [] })
                .Concat(tail.SelectMany(s => s switch { Define d => new[] { d.Target }, Phi p => [p.Target], Call c => c.Defines, _ => [] }))
                .Concat(function.Dead.Select(d => d.Define.Target)).Append(original.Target).Where(v => v.Storage.Bank == Bank.Temp)
                .Select(v => v.Storage.Index + 1).DefaultIfEmpty(1000).Max();
            var yes = new Variable(new Storage(Bank.Temp, next, original.Target.Width), 1);
            var no = new Variable(new Storage(Bank.Temp, next + 1, original.Target.Width), 1);
            taken.Statements.Add(((Define)Arm(true)) with { Target = yes });
            fallthrough.Statements.Add(((Define)Arm(false)) with { Target = no });
            merge.Statements.Add(new Phi(statement.Address, original.Target, [yes, no]));
        }
        else { taken.Statements.Add(Arm(true)); fallthrough.Statements.Add(Arm(false)); }
        taken.Statements.Add(new Jump(statement.Address, merge.Start));
        fallthrough.Statements.Add(new Jump(statement.Address, merge.Start));
        MachineFunction.AddEdge(taken, merge); MachineFunction.AddEdge(fallthrough, merge);
        merge.Statements.AddRange(tail);
        for (var d = 0; d < function.Dead.Count; d++)
            if (function.Dead[d] is var dead && dead.Block == block && dead.Define.Address > statement.Address)
                function.Dead[d] = (merge, dead.Define);
        function.Blocks.AddRange([taken, fallthrough, merge]);
        function.Renumber();
    }
}

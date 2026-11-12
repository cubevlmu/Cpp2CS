using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Ssa;

namespace Cpp2CS.Idioms;

internal static class KnownMetadataGuardsPass
{
    /// <summary>元数据守卫可复用前一分支已确定的低字节；只传播已支配该守卫的相等路径事实。</summary>
    internal static bool MetadataGuardOperands(this IdiomState state)
    {
        var dominators = Dominators.Compute(state.function);
        var definitions = state.function.Blocks.SelectMany(b => b.Statements).OfType<Define>().ToDictionary(d => d.Target, d => d.Value);
        var equalities = state.function.Blocks.Where(b => b.Statements.LastOrDefault() is Branch)
            .SelectMany(b => new[] { true, false }.Select(truth => (Block: b,
                Target: truth ? ((Branch)b.Statements[^1]).Target : ((Branch)b.Statements[^1]).Fallthrough,
                Facts: EdgeConstants.PartialFacts(((Branch)b.Statements[^1]).Condition, truth, definitions))))
            .ToArray();
        var changed = false;
        foreach (var head in state.function.Blocks)
        {
            if (head.Statements.LastOrDefault() is not Branch branch
                || TopLoadsPass.TopLoads(state.defs.Expand(branch.Condition)).Distinct()
                    .Any(l => l is { Width: 8, Address: Const flag } && state.owner.guardSections.Any(s => s.Contains(flag.Value))) == false) continue;
            var facts = new List<(Use Use, Const Constant)>();
            foreach (var equality in equalities)
            {
                var taken = equality.Block.NormalSuccessors.FirstOrDefault(b => b.Start == equality.Target);
                if (taken is not { Predecessors.Count: 1 } || !dominators.Dominates(taken.Index, head.Index)) continue;
                foreach (var fact in equality.Facts) facts.Add((new Use(fact.Key, fact.Value.Width), fact.Value));
            }
            if (facts.Count == 0) continue;
            // 只原位替换已有操作数，不能将分析时展开的 Load 复制到分支处。
            for (var i = 0; i < head.Statements.Count; i++)
            {
                var before = head.Statements[i];
                var after = ExprMap.MapOperands(before, expression => Fold.Simplify(ExprMap.Map(expression, node =>
                {
                    if (node is not Use observed) return null;
                    foreach (var fact in facts)
                        if (observed.Variable == fact.Use.Variable && observed.Width <= fact.Use.Width)
                            return Fold.Convert(ConvKind.Truncate, fact.Constant, observed.Width);
                    return null;
                })));
                if (after == before) continue;
                head.Statements[i] = after; changed = true;
            }
        }
        if (changed) state.defs = new IdiomRewriter.Defs(state.function);
        return changed;
    }

    /// <summary>
    /// 写入标志字节的值在路径条件下等于 1 时，寄存器分配可复用持有 1 的寄存器。还原成常量，守卫证明才能看到写入的是 1。
    /// </summary>
    internal static bool GuardFlagValues(this IdiomState state)
    {
        var writes = state.function.Blocks.SelectMany(b => b.Statements.Select(s => (Block: b, Statement: s)))
            .Where(w => w.Statement is Store { Target: Const, Value: Use { Width: 8 } }).ToArray();
        if (writes.Length == 0) return false;
        var dominators = Dominators.Compute(state.function);
        var definitions = state.function.Blocks.SelectMany(b => b.Statements).OfType<Define>().ToDictionary(d => d.Target, d => d.Value);
        var ones = state.function.Blocks.Where(b => b.Statements.LastOrDefault() is Branch)
            .SelectMany(b => new[] { true, false }.Select(truth => (Block: b,
                Target: truth ? ((Branch)b.Statements[^1]).Target : ((Branch)b.Statements[^1]).Fallthrough,
                Facts: EdgeConstants.PartialFacts(((Branch)b.Statements[^1]).Condition, truth, definitions))))
            .ToArray();
        bool KnownOne(Use value, Block at) => ones.Any(edge =>
            edge.Facts.TryGetValue(value.Variable, out var constant) && value.Width <= constant.Width
            && Fold.Convert(ConvKind.Truncate, constant, value.Width) is Const { Value: 1 }
            && edge.Block.NormalSuccessors.FirstOrDefault(s => s.Start == edge.Target) is { Predecessors.Count: 1 } taken
            && dominators.Dominates(taken.Index, at.Index));
        var changed = false;
        foreach (var (block, statement) in writes)
        {
            var store = (Store)statement;
            if (!KnownOne((Use)store.Value, block)) continue;
            block.Statements[block.Statements.IndexOf(store)] = store with { Value = Expr.C(1, 8) };
            changed = true;
        }
        return changed;
    }

    internal static bool KnownMetadataGuards(this IdiomState state)
    {
        if (state.initializedGuards.Count == 0)
            return false;
        var dominators = Dominators.Compute(state.function);
        var seeds = state.initializedGuards.Where(p => state.function.Blocks.Contains(p.End) && !state.removed.Contains(p.End) && !state.All.OfType<Store>().Any(s => s.Target is Const target && target.Value == p.Guard && s.Value is not Const { Value: 1, Width: 8 })).ToArray();
        var changed = false;
        foreach (var block in state.function.Blocks.Where(b => !state.removed.Contains(b)))
        {
            var known = seeds.Where(p => p.End != block && dominators.Dominates(p.End.Index, block.Index)).Select(p => p.Guard).ToHashSet();
            if (known.Count == 0)
                continue;
            for (var i = 0; i < block.Statements.Count; i++)
            {
                var previous = block.Statements[i];
                var replacement = previous is Store { Target: Const target, Value: Const { Value: 1, Width: 8 } } store && known.Contains(target.Value) ? new Nop(store.Address, "MetadataInitGuard") : ExprMap.MapOperands(previous, e => ExprMap.Map(e, part => part is Load { Width: 8, Address: Const address } && known.Contains(address.Value) ? Expr.C(1, 8) : null));
                if (replacement == previous)
                    continue;
                block.Statements[i] = replacement;
                changed = true;
            }
        }

        return changed;
    }
}

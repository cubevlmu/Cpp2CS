using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;

namespace Cpp2CS.Machine.Ssa;

internal sealed partial class FiniteConditions
{
    /// <summary>φ 的每条入边都确定同一判零结果时，只替换该判定，不把非零值猜成 1。</summary>
    internal static bool PhiPredicates(MachineFunction function)
    {
        if (!function.Blocks.Any(b => b.Statements.Any(s => s is Phi))) return false;
        var finite = new FiniteConditions(function);
        var phis = function.Blocks.SelectMany(b => b.Statements.OfType<Phi>().Select(p => (p.Target, Phi: p, Block: b)))
            .ToDictionary(p => p.Target);
        var known = new Dictionary<Compare, bool?>();
        bool? Predicate(Compare comparison)
        {
            if (known.TryGetValue(comparison, out var cached)) return cached;
            if (comparison is not { Cond: Cond.Eq or Cond.Ne, Left: Use use, Right: Const { Value: 0 } zero }
                || use.Width != zero.Width || use.Width > use.Variable.Width || !phis.TryGetValue(use.Variable, out var at)
                || at.Phi.Sources.Length != at.Block.Predecessors.Count || at.Phi.Sources.Length == 0
                || !finite.PredicateInputsSafe(use.Variable)) return known[comparison] = null;
            bool? agreed = null;
            for (var i = 0; i < at.Phi.Sources.Length; i++)
            {
                var test = comparison with { Left = new Use(at.Phi.Sources[i], use.Width) };
                if (finite.PredicateOnEdge(test, at.Block.Predecessors[i], at.Block) is not { } value
                    || agreed is { } previous && value != previous) return known[comparison] = null;
                agreed = value;
            }
            return known[comparison] = agreed;
        }
        var changed = false;
        foreach (var block in function.Blocks)
            for (var i = 0; i < block.Statements.Count; i++)
            {
                var statement = block.Statements[i];
                var rewritten = ExprMap.MapOperands(statement, expression => ExprMap.Map(expression, part =>
                {
                    if (part is not Compare comparison || Predicate(comparison) is not { } truth) return null;
                    // 原生读取的求值仍须保留；初始化守卫只有在完整证明后才能解除强制读取。
                    ReadEffects.PreserveInputs(function, [comparison.Left]);
                    return Expr.C(truth ? 1UL : 0UL, 1);
                }));
                if (ReferenceEquals(statement, rewritten)) continue;
                if (rewritten is Define define && block.Statements[i] is Define { PreserveRead: true })
                    rewritten = define with { PreserveRead = true };
                block.Statements[i] = rewritten;
                changed = true;
            }
        return changed;
    }

    private Expr PredicateTerm(Expr expression, HashSet<Variable> active, int depth = 0)
    {
        if (depth >= 32) return expression;
        return Fold.Simplify(ExprMap.Map(expression, part =>
        {
            if (part is not Use use || !definitions.TryGetValue(use.Variable, out var statement)
                || statement is not Define definition || !active.Add(use.Variable)) return null;
            // 保持读取快照的 SSA 身份，不能用地址相同冒充观察时刻相同。
            var value = definition.Value;
            if (ExprMap.Walk(value).Any(e => e is Load or Intrinsic)) { active.Remove(use.Variable); return null; }
            var projected = Fold.Convert(ConvKind.Truncate, value, use.Width);
            var result = PredicateTerm(projected, active, depth + 1);
            active.Remove(use.Variable);
            return result;
        }));
    }

    private bool? PredicateOnEdge(Expr expression, Block from, Block to)
    {
        var expected = PredicateTerm(expression, []);
        if (expected is Const constant) return constant.Value != 0;
        var seen = new HashSet<Block>();
        for (var depth = 0; depth < 16 && seen.Add(from); depth++)
        {
            if (from.Statements.LastOrDefault() is Branch branch && branch.Target != branch.Fallthrough
                && (branch.Target == to.Start || branch.Fallthrough == to.Start))
            {
                var condition = PredicateTerm(branch.Condition, []);
                if (condition == expected) return branch.Target == to.Start;
                if (condition == Fold.Not(expected)) return branch.Fallthrough == to.Start;
            }
            if (from.Predecessors.ToArray() is not [var previous]) break;
            to = from; from = previous;
        }
        return null;
    }

    private bool PredicateInputsSafe(Variable variable)
    {
        var pending = new Stack<Variable>(); pending.Push(variable);
        var seen = new HashSet<Variable>();
        while (pending.TryPop(out var next))
        {
            if (!seen.Add(next)) continue;
            if (seen.Count > 256) return false;
            if (!definitions.TryGetValue(next, out var statement)) continue;
            if (statement is Phi phi)
            {
                foreach (var source in phi.Sources) pending.Push(source);
                continue;
            }
            foreach (var part in ExprMap.Operands(statement).SelectMany(ExprMap.Walk))
            {
                if (part is Intrinsic) return false;
                if (part is Use use) pending.Push(use.Variable);
            }
        }
        return true;
    }
}

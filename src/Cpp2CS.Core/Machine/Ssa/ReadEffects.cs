using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;

namespace Cpp2CS.Machine.Ssa;

/// <summary>调用签名收窄或展开前，保留已经参与实参求值的读取；调用自身的效果另由调用语句保留。</summary>
internal static class ReadEffects
{
    internal static void PreserveInputs(MachineFunction function, IEnumerable<Expr> inputs)
    {
        var definitions = function.Blocks.SelectMany(b => b.Statements.Select((s, i) => (Block: b, Index: i, Statement: s)))
            .Where(at => at.Statement is Define or Phi).ToDictionary(at => at.Statement is Define d ? d.Target : ((Phi)at.Statement).Target);
        var pending = new Stack<Variable>(inputs.SelectMany(ExprMap.Walk).OfType<Use>().Select(u => u.Variable));
        var seen = new HashSet<Variable>();
        while (pending.TryPop(out var variable))
        {
            if (!seen.Add(variable) || !definitions.TryGetValue(variable, out var at)) continue;
            if (at.Statement is Phi phi)
            {
                foreach (var source in phi.Sources) pending.Push(source);
                continue;
            }
            var definition = (Define)at.Statement;
            foreach (var node in ExprMap.Walk(definition.Value))
                if (node is Use use) pending.Push(use.Variable);
                else if (node is Load) at.Block.Statements[at.Index] = definition with { PreserveRead = true };
        }
    }
}

using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;

namespace Cpp2CS.Machine.Ssa;

using Storage = Cpp2CS.Ir.Storage;

/// <summary>为只观察低位的使用建立窄 φ，避免未观察的寄存器高位穿过合流。</summary>
internal static class PhiSlices
{
    internal static bool Run(MachineFunction function)
    {
        var statements = function.Blocks.SelectMany(b => b.Statements).ToArray();
        var definitions = new Dictionary<Variable, Stmt>();
        var phis = new Dictionary<Variable, (Block Block, Phi Phi)>();
        foreach (var block in function.Blocks)
            foreach (var statement in block.Statements)
                switch (statement)
                {
                    case Define d: definitions[d.Target] = d; break;
                    case Phi p: definitions[p.Target] = p; phis[p.Target] = (block, p); break;
                    case Call c:
                        foreach (var output in c.Defines.Where(v => v is not null)) definitions[output] = c;
                        break;
                }
        var requested = statements.SelectMany(ExprMap.Operands).SelectMany(ExprMap.Walk).OfType<Use>()
            .Where(u => u.Width > 0 && u.Width < u.Variable.Width && phis.ContainsKey(u.Variable)).Distinct().ToArray();
        if (requested.Length == 0) return false;

        // 原有读取不能因高位死亡而消失；循环来源也暂不拆分，避免生成无界的投影链。
        bool Safe(Variable variable, HashSet<Variable> visiting, HashSet<Variable> done)
        {
            if (variable.Version <= 0 || done.Contains(variable)) return true;
            if (visiting.Count + done.Count >= 256 || !visiting.Add(variable) || !definitions.TryGetValue(variable, out var statement)) return false;
            IEnumerable<Variable> inputs;
            if (statement is Define d)
            {
                if (ExprMap.Walk(d.Value).Any(e => e is Load or Intrinsic)) return false;
                inputs = ExprMap.Walk(d.Value).OfType<Use>().Select(u => u.Variable);
            }
            else if (statement is Phi phi) inputs = phi.Sources;
            else if (statement is Call) inputs = [];
            else return false;
            foreach (var input in inputs)
                if (!Safe(input, visiting, done)) return false;
            visiting.Remove(variable);
            done.Add(variable);
            return true;
        }

        var next = definitions.Keys.Concat(phis.Values.SelectMany(p => p.Phi.Sources))
            .Concat(statements.SelectMany(ExprMap.Operands).SelectMany(ExprMap.Walk).OfType<Use>().Select(u => u.Variable))
            .Where(v => v.Storage.Bank == Bank.Temp).Select(v => v.Storage.Index).DefaultIfEmpty(999).Max() + 1;
        Variable Fresh(int width) => new(new Storage(Bank.Temp, next++, width), 1);
        var replacements = new Dictionary<Use, Expr>();
        foreach (var use in requested)
        {
            var (block, phi) = phis[use.Variable];
            // 只拆分各臂显式写过的低位；完整指针或结构体的位片继续共用原来的 φ。
            if (phi.Sources.Any(source => !definitions.TryGetValue(source, out var definition)
                || definition is not Define { Value: Insert { Low: 0 } inserted } || inserted.Value.Width < use.Width
                || ExprMap.Walk(inserted.Value).Any(e => e is Load or Intrinsic)
                || !ExprMap.Walk(inserted.Base).OfType<Use>().All(u => Safe(u.Variable, [], []))
                || ExprMap.Walk(inserted.Base).Any(e => e is Load or Intrinsic))) continue;
            if (block.Predecessors.Count != phi.Sources.Length || block.Predecessors.Any(p => p.Statements.LastOrDefault() is Call or Return or Trap)) continue;
            var inputs = new Variable[phi.Sources.Length];
            for (var i = 0; i < inputs.Length; i++)
            {
                var predecessor = block.Predecessors[i];
                var at = predecessor.Statements.Count;
                if (at > 0 && predecessor.Statements[^1] is Branch or Jump) at--;
                inputs[i] = Fresh(use.Width);
                // 取值仍引用原有 SSA 快照，不复制或收窄真正的内存读取。
                var source = ((Define)definitions[phi.Sources[i]]).Value;
                predecessor.Statements.Insert(at, new Define(phi.Address, inputs[i], Fold.Convert(ConvKind.Truncate, source, use.Width)));
            }
            var target = Fresh(use.Width);
            block.Statements.Insert(block.Statements.TakeWhile(s => s is Phi).Count(), new Phi(phi.Address, target, inputs));
            replacements[use] = new Use(target, use.Width);
        }
        if (replacements.Count == 0) return false;
        foreach (var block in function.Blocks)
            for (var i = 0; i < block.Statements.Count; i++)
                block.Statements[i] = ExprMap.MapOperands(block.Statements[i], e => ExprMap.Map(e,
                    node => node is Use use && replacements.TryGetValue(use, out var value) ? value : null));
        return true;
    }
}

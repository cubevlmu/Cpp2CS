using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;

namespace Cpp2CS.Recovery.Calls;

/// <summary>已确认签名之外的纯寄存器快照不构成指针传递；不穿透读取或未知操作。</summary>
internal sealed class CallInputSnapshots
{
    private readonly Dictionary<Variable, Stmt> definitions = [];
    private readonly Dictionary<Variable, bool> safe = [];

    internal CallInputSnapshots(MachineFunction function)
    {
        foreach (var statement in function.Blocks.SelectMany(b => b.Statements))
            switch (statement)
            {
                case Define d: definitions[d.Target] = d; break;
                case Phi p: definitions[p.Target] = p; break;
                case Call c:
                    foreach (var output in c.Defines.OfType<Variable>()) definitions[output] = c;
                    break;
            }
    }

    internal bool Contains(CallShape shape, int argument) => shape.OutsideSignature(argument)
        && Pure(shape.Call.Arguments[argument], [], 0);

    internal static bool Trim(MachineFunction function, Func<Call, CallShape> shapes)
    {
        var inputs = new CallInputSnapshots(function);
        var changed = false;
        foreach (var block in function.Blocks)
            for (var i = 0; i < block.Statements.Count; i++)
            {
                if (block.Statements[i] is not Call call) continue;
                var shape = shapes(call);
                var prefix = call.Arguments.Length - call.Sources.Length;
                var kept = Enumerable.Range(0, call.Arguments.Length).Where(a => !inputs.Contains(shape, a)).ToArray();
                if (kept.Length == call.Arguments.Length) continue;
                block.Statements[i] = call with { Arguments = kept.Select(a => call.Arguments[a]).ToArray(),
                    Sources = kept.Where(a => a >= prefix).Select(a => call.Sources[a - prefix]).ToArray() };
                changed = true;
            }
        return changed;
    }

    private bool Pure(Expr expression, HashSet<Variable> visiting, int depth)
    {
        if (depth >= 64) return false;
        foreach (var node in ExprMap.Walk(expression))
        {
            if (node is Load or Intrinsic) return false;
            if (node is not Use use || use.Variable.Version <= 0) continue;
            if (safe.TryGetValue(use.Variable, out var known)) { if (!known) return false; continue; }
            if (!visiting.Add(use.Variable) || !definitions.TryGetValue(use.Variable, out var statement)) return false;
            // 调用本身另有语句，丢弃其返回快照不会省去调用效果。
            var valid = statement switch
            {
                Define d => Pure(d.Value, visiting, depth + 1),
                Phi p => p.Sources.All(s => Pure(new Use(s, s.Width), visiting, depth + 1)),
                Call => true,
                _ => false,
            };
            visiting.Remove(use.Variable);
            safe[use.Variable] = valid;
            if (!valid) return false;
        }
        return true;
    }
}

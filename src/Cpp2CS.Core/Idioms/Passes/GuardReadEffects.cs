using Cpp2CS.Ir;

namespace Cpp2CS.Idioms;

/// <summary>完整守卫已归一为运行时操作后，仅解除该守卫读取的强制求值；其他原生读取保持。</summary>
internal static class GuardReadEffects
{
    internal static void ReleaseGuardRead(this IdiomState state, Load proved)
    {
        foreach (var block in state.function.Blocks)
            for (var i = 0; i < block.Statements.Count; i++)
            {
                if (block.Statements[i] is not Define { PreserveRead: true } define) continue;
                var reads = ExprMap.Walk(state.defs.Expand(define.Value)).OfType<Load>().ToArray();
                if (reads.Length > 0 && reads.All(read => read == proved)) block.Statements[i] = define with { PreserveRead = false };
            }
    }
}

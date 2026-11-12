using Cpp2CS.Ir;
using Cpp2CS.Machine.Ssa;
using static Cpp2CS.Idioms.IdiomRewriter;

namespace Cpp2CS.Idioms;

internal static class ReplaceLazyPass
{
    internal static void ReplaceLazy(this IdiomState state)
    {
        var calls = new Dictionary<CallSite, (Call Call, ulong Slot, Symbol Value)>(ReferenceEqualityComparer.Instance);
        foreach (var proof in state.lazyValues)
            calls[proof.Call.Site] = proof;
        foreach (var block in state.function.Blocks)
            for (var i = 0; i < block.Statements.Count; i++)
            {
                if (block.Statements[i] is not Call { Op: null, Defines.Length: <= 1, Arguments.Length: > 0 } call
                    || !calls.TryGetValue(call.Site, out var proof) || call.Kind != proof.Call.Kind || call.Target != proof.Call.Target
                    || state.defs.Expand(call.Arguments[0]) is not Const address || address.Value != proof.Slot
                    || call.Defines is [var output] && output.Width != 64)
                    continue;
                var value = proof.Value;
                state.Result.MetadataInitializations.Add((block, call.Site, proof.Slot));
                if (call.Defines.FirstOrDefault() is { } result)
                    block.Statements[i] = new Define(call.Address, result, value);
                else
                    block.Statements[i] = new Nop(call.Address, "InitMetadata");
            }

        state.Result.Errors.AddRange(Lowering.Cleanup(state.function));
        state.defs = new Defs(state.function);
    }
}

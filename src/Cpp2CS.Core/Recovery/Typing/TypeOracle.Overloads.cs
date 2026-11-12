using Cpp2CS.Facts;
using Cpp2CS.Ir;

namespace Cpp2CS.Recovery.Typing;

public sealed partial class TypeOracle
{
    /// <summary>同类型同名重载共享入口，只有原生证明后缀参数及全部隐藏上下文未用时才选唯一最短签名。</summary>
    internal MethodRef? ErasedOverload(Call call)
    {
        if (facts.Model.Image.Architecture != Architecture.X64 || call.Op is not null || call.Kind != CallKind.Direct
            || call.Target is not Const target || shapes(call) is not { Signature: null, Candidates.Count: > 1 } shape
            || facts.Code.At(target.Value) is not { Start: var start, HasUnmodeledExceptions: false } || start != target.Value) return null;
        var candidates = shape.Candidates.Distinct().ToArray();
        var shortest = candidates.GroupBy(c => c.Method.Parameters.Count).OrderBy(g => g.Key).First().ToArray();
        if (shortest is not [var chosen] || chosen.Method.Name is ".ctor" or ".cctor") return null;
        var signatures = new Dictionary<MethodRef, MachineSignature>();
        foreach (var candidate in candidates)
        {
            if (candidate.Method.Owner != chosen.Method.Owner || candidate.Method.Name != chosen.Method.Name
                || candidate.Method.IsStatic != chosen.Method.IsStatic || candidate.Method.Address != target.Value
                || candidate.TypeArguments.Count != 0 || candidate.MethodArguments.Count != 0 || candidate.Method.GenericParameters.Count != 0
                || !candidate.Method.ReturnType.Equals(chosen.Method.ReturnType)
                || !candidate.Method.Parameters.Take(chosen.Method.Parameters.Count).Select(p => p.Type).SequenceEqual(chosen.Method.Parameters.Select(p => p.Type))
                || NativeSignature(candidate) is not { MethodInfo.Register.Bank: Bank.Gpr } signature
                || !(typedInputs ??= new(facts, false)).UnusedInput(target.Value, signature.MethodInfo!.Register)) return null;
            signatures.Add(candidate, signature);
        }
        var canonical = signatures[chosen];
        foreach (var (candidate, signature) in signatures)
        {
            if (!SameValue(canonical.Return, signature.Return) || !SameValue(canonical.This, signature.This)) return null;
            foreach (var argument in canonical.Arguments)
                if (!SameValue(argument, signature.Arguments.FirstOrDefault(a => a.Index == argument.Index))) return null;
            foreach (var argument in signature.Arguments.Where(a => a.Index >= chosen.Method.Parameters.Count))
                if (argument.Transfer != Transfer.Value || argument.Size is <= 0 or > 8
                    || argument.Pieces.Length != 1 || argument.Pieces[0].Register.Bank is not (Bank.Gpr or Bank.Vec)
                    || !typedInputs!.UnusedInput(target.Value, argument.Pieces[0].Register)) return null;
        }
        return chosen;
    }

    private static bool SameValue(MachineValue? first, MachineValue? second) => first is null ? second is null
        : second is not null && first.Type.Equals(second.Type) && first.Index == second.Index && first.Size == second.Size
            && first.Transfer == second.Transfer && first.Access == second.Access && first.Pieces.SequenceEqual(second.Pieces);
}

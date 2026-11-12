using Cpp2CS.Facts;
using Cpp2CS.Ir;
using Cpp2CS.Recovery.Calls;

namespace Cpp2CS.Recovery.Typing;

public sealed partial class TypeOracle
{
    /// <summary>先代入接收者再筛选候选；仅接受注册的共享实现，机器位置与内存效果须保持一致。</summary>
    private MethodRef ReceiverCandidate(Call call, MethodRef candidate, DefinitionRef receiver)
    {
        if (candidate.Method.IsStatic || call.Op is not null || call.Kind is not (CallKind.Direct or CallKind.Tail)
            || call.Target is not Const target) return candidate;
        var bound = Specialize(candidate, receiver);
        if (bound.Equals(candidate)) return candidate;
        var shared = bound with { TypeArguments = bound.TypeArguments.Select(types.SharedGenericArgument).ToArray(),
            MethodArguments = bound.MethodArguments.Select(types.SharedGenericArgument).ToArray() };
        if (!shared.Equals(candidate)
            || !facts.EntriesAt(target.Value).Any(e => e.Kind is EntryKind.Method or EntryKind.GenericMethod && candidate.Equals(e.Method))
            || NativeSignature(candidate) is not { } before || NativeSignature(bound) is not { } after
            || !CallShapes.SameShape(before, after)) return candidate;
        return bound;
    }
}

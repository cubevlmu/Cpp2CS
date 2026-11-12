using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Ir;
using Cpp2CS.Recovery.Calls;

namespace Cpp2CS.Recovery.Typing;

public sealed partial class TypeOracle
{
    private readonly Dictionary<Call, MethodRef[]> equivalentCalls = new(ReferenceEqualityComparer.Instance);
    private int typeVersion;

    /// <summary>相同入口不提供原始声明身份；完整签名、初始化与隐藏上下文一致时可投影到合法的等价声明。</summary>
    private MethodRef? EquivalentProjection(Call call, CallShape shape, MethodRef[] candidates, TypeRef? receiver)
    {
        if (!shape.MethodInfoUnused || candidates.Length < 2 || call.Op is not null || call.Kind is not (CallKind.Direct or CallKind.Tail)
            || call.Target is not Const target || shape.Signature is null
            || facts.Code.At(target.Value) is not { HasUnmodeledExceptions: false } range || range.Start != target.Value) return null;
        var first = candidates[0];
        const MethodAttributes dispatch = MethodAttributes.Static | MethodAttributes.Virtual | MethodAttributes.Final | MethodAttributes.NewSlot;
        var signature = NativeSignature(first);
        if (signature is null) return null;
        foreach (var candidate in candidates)
        {
            if (candidate.Method.Address != target.Value || candidate.Method.Name is ".ctor" or ".cctor"
                || candidate.Method.GenericParameters.Count != 0 || candidate.Method.Owner.GenericParameters.Count != 0
                || candidate.MethodArguments.Count != 0 || !SameInitialization(first, candidate)
                || (candidate.Method.Attributes & dispatch) != (first.Method.Attributes & dispatch)
                || (candidate.Method.Attributes & MethodAttributes.PinvokeImpl) != 0
                || !candidate.Concrete(candidate.Method.ReturnType).Equals(first.Concrete(first.Method.ReturnType))
                || candidate.Method.Parameters.Count != first.Method.Parameters.Count
                || !candidate.Method.Parameters.Zip(first.Method.Parameters).All(pair => pair.First.Attributes == pair.Second.Attributes
                    && candidate.Concrete(pair.First.Type).Equals(first.Concrete(pair.Second.Type)))
                || NativeSignature(candidate) is not { } other || !CallShapes.SameShape(signature, other)) return null;
        }
        var legal = candidates.Where(c => ManagedAccess.Method(types, method.Method.Owner, c, receiver))
            .OrderBy(c => (c.Method.Attributes & MethodAttributes.SpecialName) != 0).ThenBy(c => c.Method.Index).ToArray();
        if (legal.Length == 0) return null;
        equivalentCalls[call] = candidates;
        return legal[0];
    }

    private static bool SameInitialization(MethodRef first, MethodRef candidate)
    {
        if (candidate.DeclaringType.Equals(first.DeclaringType)) return true;
        if (!first.Method.IsStatic || !candidate.Method.IsStatic) return false;
        // 不同静态声明只能在两侧及其基类均无类型初始化器时互换，避免引入额外初始化效果。
        static bool NoInitializer(TypeRef type)
        {
            var seen = new HashSet<TypeDef>();
            while (type is DefinitionRef definition && seen.Add(definition.Definition))
            {
                if (definition.Definition.Methods.Any(m => m.Name == ".cctor")) return false;
                if (definition.Definition.BaseType is not { } parent) return true;
                type = parent.Substitute(definition.Arguments, []);
            }
            return false;
        }
        return NoInitializer(first.DeclaringType) && NoInitializer(candidate.DeclaringType);
    }

    /// <summary>在当前类型解的版本中记录选择依据；等价声明投影不冒充确切原始方法身份。</summary>
    public IReadOnlyList<CallResolution> CallResolutions()
    {
        var result = new List<CallResolution>();
        foreach (var call in values.Function.Blocks.SelectMany(b => b.Statements).OfType<Call>())
        {
            var shape = shapes(call);
            if (shape.IsRuntime) continue;
            var selected = Callee(call);
            var projected = equivalentCalls.ContainsKey(call);
            var status = projected ? "native-equivalent-projection" : selected is not null ? "selected-by-context"
                : call.Target is Const target && facts.Helpers?.At(target.Value) is { Kind: not HelperKind.Unknown } ? "runtime-helper-unprojected"
                : shape.Candidates.Count > 1 ? "managed-identity-not-unique" : "managed-target-not-proven";
            result.Add(new(call.Address, call.Target is Const direct ? direct.Value : null, typeVersion,
                shape.Candidates.Select(c => new CallCandidate(c, projected && equivalentCalls[call].Contains(c)
                    ? "same-native-entry/same-managed-signature/same-initialization-context/same-abi/unused-MethodInfo"
                    : "registered-or-proven-target", selected is null ? "candidate-not-uniquely-proven" : null)).ToArray(), selected, status));
        }
        return result;
    }
}

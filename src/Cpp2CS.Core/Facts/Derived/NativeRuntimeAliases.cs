using System.Reflection;
using Cpp2CS.Ir;

namespace Cpp2CS.Facts.Derived;

/// <summary>已登记核心库浮点内部调用的纯跳板与实现共享身份；不猜测静态链接库符号。</summary>
internal sealed class NativeRuntimeAliases(ProgramFacts facts)
{
    private readonly Lazy<IReadOnlyDictionary<ulong, MethodRef>> aliases = new(() => Build(facts));

    internal MethodRef? At(ulong entry) => aliases.Value.GetValueOrDefault(entry);

    private static IReadOnlyDictionary<ulong, MethodRef> Build(ProgramFacts facts)
    {
        var candidates = new Dictionary<ulong, List<MethodRef>>();
        if (facts.Model.Image.Architecture != Architecture.X64) return new Dictionary<ulong, MethodRef>();
        var machine = facts.CreateMachine();
        var abi = facts.CreateAbi();
        foreach (var method in facts.Model.Methods)
        {
            if (!method.IsStatic || method.Address == 0 || method.GenericParameters.Count != 0
                || method.Owner.Assembly is not ("mscorlib.dll" or "System.Private.CoreLib.dll")
                || method.Owner.FullName is not ("System.Math" or "System.MathF")
                || (method.ImplAttributes & MethodImplAttributes.InternalCall) == 0
                || !Scalar(method.ReturnType) || method.Parameters.Count is < 1 or > 2
                || !method.Parameters.All(p => Scalar(p.Type))) continue;
            var reference = MethodRef.Open(method);
            if (abi.Classify(reference, out _) is not { This: null, Return: { Passing: Passing.Registers, Pieces: [{ Register.Bank: Bank.Vec }] } } signature
                || signature.Parameters.Any(p => p.Passing != Passing.Registers || p.Pieces is not [{ Register.Bank: Bank.Vec }])) continue;
            var path = new HashSet<ulong> { method.Address };
            var current = method.Address;
            var targets = new List<ulong>();
            var valid = false;
            for (var depth = 0; depth < 8; depth++)
            {
                if (!machine.Image.IsExecutable(current) || facts.Code.At(current)?.HasUnmodeledExceptions == true) break;
                var statements = new List<Stmt>();
                if (machine.Lift(current, statements) <= 0) break;
                if (statements is not [Jump jump]) { valid = current != method.Address; break; }
                if (!path.Add(jump.Target)) break;
                current = jump.Target;
                targets.Add(current);
            }
            if (!valid) continue;
            foreach (var target in targets)
            {
                // 已有登记和运行时语义优先，避免覆盖别的入口身份。
                if (facts.EntriesAt(target).Length != 0 || facts.Helpers.At(target) is { Kind: not HelperKind.Unknown }) continue;
                if (!candidates.TryGetValue(target, out var list)) candidates[target] = list = [];
                list.Add(reference);
            }
        }
        return candidates.Where(p => p.Value.Distinct().Count() == 1).ToDictionary(p => p.Key, p => p.Value[0]);
    }

    private static bool Scalar(TypeRef type) => type is DefinitionRef { Definition.FullName: "System.Single" or "System.Double" }
        or PrimitiveRef { Name: "float" or "double" };
}

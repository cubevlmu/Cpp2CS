using Cpp2CS.Facts;
using Cpp2CS.Ir;
using Cpp2CS.Model;
using Cpp2CS.Recovery.Calls;

namespace Cpp2CS.X64.Tests;

internal static class CallIdentityTests
{
    internal static void Run(BaseFacts basis)
    {
        var owner = new TypeDef { Index = 0, Assembly = "Fixture.dll", Namespace = "", Name = "Owner", Token = 0x02000001,
            Attributes = System.Reflection.TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 };
        var type = new DefinitionRef(owner, []);
        MethodRef Method(int parameters) => new(new MethodDef { Index = parameters, Owner = owner, Name = "Method" + parameters,
            Token = (uint)(0x06000001 + parameters), Attributes = System.Reflection.MethodAttributes.Static, ImplAttributes = 0,
            Slot = -1, ReturnType = type, Parameters = Enumerable.Range(0, parameters).Select(i => new ParameterDef("p" + i, type, 0, null, false)).ToArray() }, [], []);
        var first = Method(0); var second = Method(1); var caller = Method(2);
        const ulong target = 0x180001010;
        CodeEntry[] entries = [new(target, EntryKind.Method, first, 0, null), new(target, EntryKind.Method, second, 1, null)];
        var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries,
            ByAddress = new Dictionary<ulong, CodeEntry[]> { [target] = entries }, Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
            MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
        var facts = basis with { Registrations = registrations };
        var nativeSignature = new Cpp2CS.Machine.Lifting.FactsCallModel(facts, facts.MachineFactory!().Convention).Signature(target);
        Check(nativeSignature is not null && nativeSignature.Reads.Contains(Storage.Gpr(1))
            && nativeSignature.Reads.Contains(Storage.Gpr(2)) && nativeSignature.MethodInfo is null,
            "混合签名入口保留全部候选输入，MethodInfo 位置不同则不指名某个寄存器");
        var reversed = entries.Reverse().ToArray();
        var reversedFacts = basis with { Registrations = new Registrations {
            CodeRegistration = 0, MetadataRegistration = 0, Entries = reversed,
            ByAddress = new Dictionary<ulong, CodeEntry[]> { [target] = reversed }, Rgctx = registrations.Rgctx,
            MetadataUsageSlots = [], TypePointers = registrations.TypePointers, InvokerOf = registrations.InvokerOf } };
        var reversedSignature = new Cpp2CS.Machine.Lifting.FactsCallModel(reversedFacts, facts.MachineFactory!().Convention).Signature(target);
        Check(reversedSignature is not null && nativeSignature!.Reads.ToHashSet().SetEquals(reversedSignature.Reads)
            && nativeSignature.Results.ToHashSet().SetEquals(reversedSignature.Results), "注册表枚举顺序不能决定机器数据流");
        var shapes = new CallShapes(new ProgramFacts(facts, new()), new ManagedAbi(facts.Layouts, Architecture.X64), (_, _) => false);
        var stale = new Call(0x180001000, CallKind.Direct, Expr.C(target, 64)) {
            Sources = [Storage.Gpr(1), Storage.Gpr(2), Storage.Gpr(8)],
            Arguments = [Expr.C(0, 64), Expr.C(0, 64), new Symbol(SymbolKind.Method, caller)] };
        var ambiguous = shapes.Of(stale);
        Check(ambiguous.Signature is null && ambiguous.Candidates.Count == 2 && !ambiguous.LocalCopy,
            "调用者残留 MethodInfo 不得覆盖目标注册身份或伪造递归调用");
        var named = shapes.Of(stale with { Arguments = [Expr.C(0, 64), new Symbol(SymbolKind.Method, second), Expr.C(0, 64)] });
        Check(named.Candidates is [var actual] && actual == second && named.Signature is not null && !named.LocalCopy,
            "目标自己的 MethodInfo 可消歧，已注册目标不是未登记副本");
    }

    private static void Check(bool condition, string reason)
    {
        if (!condition) throw new InvalidOperationException(reason);
    }
}

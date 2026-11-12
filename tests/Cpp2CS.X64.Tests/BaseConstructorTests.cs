using System.Buffers.Binary;
using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Model;
using Cpp2CS.Recovery.Calls;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class BaseConstructorTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        const ulong basis = 0x180000000;
        var bytes = original.ToArray();
        void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
        U32(0x124, 24); U32(0x704, 0x100a); U32(0x708, 0x3140);
        U32(0x70c, 0x1080); U32(0x710, 0x1083); U32(0x714, 0x3140); bytes[0x740] = 1; U32(0x744, 0x1080);
        System.Convert.FromHexString("33D2E979000000909090").CopyTo(bytes, 0x200);
        bytes[0x280] = 0xc3;
        TypeDef Type(int index, string name) => new() { Index = index, Assembly = "Fixture.dll", Namespace = "", Name = name,
            Token = (uint)(0x02000001 + index), Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 };
        var parent = Type(0, "Parent"); var child = Type(1, "Child"); child.BaseType = new DefinitionRef(parent, []);
        var pointer = new PointerRef(new PrimitiveRef("void"));
        MethodDef Method(int index, TypeDef owner, string name, bool isStatic, int count, ulong address) => new() {
            Index = index, Owner = owner, Name = name, Token = (uint)(0x06000001 + index), Address = address,
            Attributes = MethodAttributes.Public | (isStatic ? MethodAttributes.Static : 0), ImplAttributes = 0, Slot = -1,
            Parameters = Enumerable.Range(0, count).Select(i => new ParameterDef("p" + i, pointer, 0, null, false)).ToArray() };
        var baseCtor = new MethodRef(Method(0, parent, ".ctor", false, 0, basis + 0x1080), [], []);
        var unrelated = new MethodRef(Method(1, parent, "Ignore", true, 2, basis + 0x1080), [], []);
        var caller = new MethodRef(Method(2, child, ".ctor", false, 1, basis + 0x1000), [], []);
        CodeEntry[] entries = [new(basis + 0x1080, EntryKind.Method, baseCtor, 0, null), new(basis + 0x1080, EntryKind.Method, unrelated, 1, null)];
        var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries,
            ByAddress = new Dictionary<ulong, CodeEntry[]> { [basis + 0x1080] = entries }, Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
            MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
        CallShapes Shapes(byte[] data)
        {
            var image = ImageDocument.Parse(data); var code = CodeMap.BuildPe(image, [basis + 0x1000, basis + 0x1080]);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [], Types = [parent, child], Fields = [],
                Methods = [baseCtor.Method, unrelated.Method, caller.Method], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [],
                Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = CodeScan.Unscanned(code), Registrations = registrations,
                Layouts = new FieldLayouts(model), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            return new(facts, facts.CreateAbi(), (_, _) => false);
        }
        var call = new Call(basis + 0x1002, CallKind.Tail, Expr.C(basis + 0x1080, 64)) { Sources = [Storage.Gpr(1), Storage.Gpr(2), Storage.Gpr(8)],
            Arguments = [new Use(new Variable(Storage.Gpr(1), 0), 64), Expr.C(0, 64), new Symbol(SymbolKind.Method, caller)] };
        Check(Shapes(bytes).Of(call).Signature is null, "没有构造上下文时保留共享入口歧义");
        Check(Shapes(bytes).Of(call, caller) is { Signature: not null, Candidates: [var actual] } && actual == baseCtor,
            "首次调用且目标纯返回时，选择直接基类构造，不能选择当前构造造成递归");
        Check(Shapes(bytes).Of(call with { Arguments = [Expr.C(0, 64), Expr.C(0, 64), new Symbol(SymbolKind.Method, caller)] }, caller).Signature is null,
            "其他对象不能被视为入口 this");
        foreach (var at in new[] { 0x203, 0x280, 0x740 })
        {
            var changed = bytes.ToArray(); changed[at] ^= (byte)(at == 0x740 ? 8 : 1);
            Check(Shapes(changed).Of(call, caller).Signature is null, "目标调用、纯返回或异常边不符时拒绝构造证明");
        }
        var earlier = bytes.ToArray();
        System.Convert.FromHexString("E87B000000E976000000").CopyTo(earlier, 0x200);
        Check(Shapes(earlier).Of(call with { Address = basis + 0x1005 }, caller).Signature is null, "存在更早调用时不能假设 this 尚未初始化");
        var branched = bytes.ToArray(); branched[0x200] = 0xeb; branched[0x201] = 0;
        Check(Shapes(branched).Of(call, caller).Signature is null, "控制流前缀不由直线首次调用证明覆盖");
        var truncated = bytes.ToArray();
        System.Convert.FromHexString("C20000").CopyTo(truncated, 0x280);
        BinaryPrimitives.WriteUInt32LittleEndian(truncated.AsSpan(0x710), 0x1081);
        Check(Shapes(truncated).Of(call, caller).Signature is null, "RET 0 指令跨越已核实函数边界时不接受");
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

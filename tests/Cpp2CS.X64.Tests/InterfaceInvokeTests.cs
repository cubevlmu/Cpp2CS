using System.Buffers.Binary;
using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Model;
using Cpp2CS.Output;
using Cpp2CS.Recovery;
using Cpp2CS.X64;
using Mono.Cecil.Cil;

namespace Cpp2CS.X64.Tests;

internal static class InterfaceInvokeTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        const ulong basis = 0x180000000;
        var bytes = original.ToArray();
        var callerBytes = System.Convert.FromHexString("4C8BC1488B15FE0F0000B9010000004883EC28E8680000004883C428C3");
        // 完整接口扫描与两条尾调用，慢路径独立保留为查找契约。
        var body = System.Convert.FromHexString("40534883EC20498BD833C0440FB7C14C8B1B450FB78B2E01000066413BC173254D8B93B0000000660F1F8400000000000FB7C84803C9493914CA742366FFC066413BC172EB488BCBE800000000488BCB4C8B00488B50084883C4205B49FFE00FB7D0488BCB4803D2418B44D2084103C0489848C1E0044805380100004903C34C8B00488B50084883C4205B49FFE0");
        Check(body.Length == 0x8e, "接口桩夹具完整");
        callerBytes.CopyTo(bytes, 0x200); body.CopyTo(bytes, 0x280); bytes[0x350] = 0xc3;
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(0x2c9), 0x1150 - 0x10cd);
        void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
        U32(0x124, 24); U32(0x700, 0x1000); U32(0x704, (uint)(0x1000 + callerBytes.Length)); U32(0x708, 0x3140);
        U32(0x70c, 0x1080); U32(0x710, 0x110e); U32(0x714, 0x3150); bytes[0x740] = 1; bytes[0x750] = 1;
        var names = new[] { "Void", "Boolean", "Char", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64", "Single", "Double",
            "String", "TypedReference", "IntPtr", "UIntPtr", "Object", "ValueType", "RuntimeTypeHandle", "RuntimeFieldHandle", "RuntimeMethodHandle", "NullReferenceException" };
        var core = names.Select((name, i) => new TypeDef { Index = i, Assembly = "mscorlib.dll", Namespace = "System", Name = name, Token = (uint)(0x02000001 + i),
            Attributes = TypeAttributes.Public, IsValueType = name is not ("String" or "Object" or "ValueType" or "NullReferenceException"), IsEnum = false, Size = name == "Int32" ? 4 : 8 }).ToArray();
        TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
        TypeDef Type(int id, string name, TypeAttributes attributes) => new() { Index = core.Length + id, Assembly = "InterfaceInvoke.dll", Namespace = "Fixture", Name = name,
            Token = (uint)(0x02000001 + id), Attributes = attributes, IsValueType = false, IsEnum = false, Size = 16,
            BaseType = (attributes & TypeAttributes.Interface) != 0 ? null : Corlib("Object") };
        var module = Type(0, "<Module>", TypeAttributes.NotPublic); var contract = Type(1, "IValue", TypeAttributes.Public | TypeAttributes.Interface | TypeAttributes.Abstract);
        var first = Type(2, "First", TypeAttributes.Public); var second = Type(3, "Second", TypeAttributes.Public); var owner = Type(4, "Reader", TypeAttributes.Public);
        module.BaseType = null;
        var interfaceType = new DefinitionRef(contract, []); first.Interfaces = [interfaceType]; second.Interfaces = [interfaceType];
        MethodDef Method(int index, TypeDef type, string name, MethodAttributes attributes, int slot = -1) => new() { Index = index, Owner = type, Name = name,
            Token = (uint)(0x06000001 + index), Attributes = attributes, ImplAttributes = 0, Slot = slot, ReturnType = Corlib("Int32") };
        var caller = Method(0, owner, "Run", MethodAttributes.Public | MethodAttributes.Static);
        caller = new MethodDef { Index = caller.Index, Owner = owner, Name = caller.Name, Token = caller.Token, Attributes = caller.Attributes,
            ImplAttributes = 0, Slot = -1, ReturnType = caller.ReturnType, Address = basis + 0x1000, Parameters = [new("value", interfaceType, 0, null, false)] };
        var member = Method(1, contract, "ReadValue", MethodAttributes.Public | MethodAttributes.Abstract | MethodAttributes.Virtual | MethodAttributes.NewSlot, 1);
        var a = Method(2, first, "ReadValue", MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.Final | MethodAttributes.NewSlot);
        var b = Method(3, second, "ReadValue", MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.Final | MethodAttributes.NewSlot);
        owner.Methods = [caller]; contract.Methods = [member]; first.Methods = [a]; second.Methods = [b];
        var nullType = core.Single(t => t.Name == "NullReferenceException");
        var nullConstructor = new MethodDef { Index = 4, Owner = nullType, Name = ".ctor", Token = 0x06000001,
            Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1 };
        nullType.Methods = [nullConstructor];
        var coreAssembly = new AssemblyDef { Name = "mscorlib.dll", AssemblyName = "mscorlib", Version = new(4, 0, 0, 0), Culture = "", PublicKey = [], Types = core };
        var fixture = new AssemblyDef { Name = "InterfaceInvoke.dll", AssemblyName = "InterfaceInvoke", Version = new(1, 0, 0, 0), Culture = "", PublicKey = [], Types = [module, contract, first, second, owner] };
        ProgramFacts Facts(byte[] data, HelperKind helper = HelperKind.InterfaceLookup, int? vtable = 0x138)
        {
            var image = ImageDocument.Parse(data);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [coreAssembly, fixture], Types = [.. core, module, contract, first, second, owner],
                Methods = [caller, member, a, b, nullConstructor], Fields = [], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var code = CodeMap.BuildPe(image, [caller.Address]); var scan = CodeScan.Unscanned(code);
            var entries = new[] { new CodeEntry(caller.Address, EntryKind.Method, MethodRef.Open(caller), 0, null) };
            return new(new BaseFacts { Model = model, Code = code, Scan = scan, Layouts = new FieldLayouts(model),
                Registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries, ByAddress = entries.GroupBy(e => e.Address).ToDictionary(g => g.Key, g => g.ToArray()),
                    Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(), MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() },
                Usages = new UsageSlots { Slots = new Dictionary<ulong, UsageSlot> { [basis + 0x2008] = new(basis + 0x2008, new(UsageKind.TypeInfo, 0, interfaceType), 1, 1) },
                    SlotAddressBeforeCall = new Dictionary<ulong, int>(), UnreferencedDecodable = new Dictionary<ulong, Usage>() },
                Helpers = RuntimeHelpers.FromEvidence(code, scan, [new(basis + 0x1150, helper, null, "独立接口查找契约", 1)]),
                RuntimeOffsets = new(null, null, "独立布局契约") { ClassVtable = vtable, MethodClass = 0x20 }, Checks = new(), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
        }
        var facts = Facts(bytes);
        Check(facts.NativeInterfaceInvokes.Matches(basis + 0x1080), "完整原生接口桩须匹配");
        foreach (var offset in new[] { 6, 14, 18, 22, 30, 35, 48, 57, 65, 72, 73, 81, 85, 94, 102, 112, 118, 127, 136 })
        {
            var changed = bytes.ToArray(); changed[0x280 + offset] ^= 1;
            Check(!Facts(changed).NativeInterfaceInvokes.Matches(basis + 0x1080), "接口扫描、对象、槽、慢路径、MethodInfo 或尾调用变化须拒绝");
        }
        Check(!Facts(bytes, HelperKind.Unknown).NativeInterfaceInvokes.Matches(basis + 0x1080)
            && !Facts(bytes, vtable: null).NativeInterfaceInvokes.Matches(basis + 0x1080), "未知慢路径或布局不能构成证明");
        var badSlot = bytes.ToArray(); badSlot[0x20b] = 0;
        var badFacts = Facts(badSlot);
        var badRecovery = new MethodDecompiler(badFacts, new ManagedTypes(badFacts.Model, badFacts.Layouts));
        Check(badRecovery.Analyze(MethodRef.Open(caller), caller.Address).TryGet(out var rejected, out _)
            && rejected.Function.Blocks.SelectMany(block => block.Statements).OfType<Call>().Single().Resolved is null,
            "槽号没有元数据声明时保留未知调用");
        var types = new ManagedTypes(facts.Model, facts.Layouts);
        var recovery = new MethodDecompiler(facts, types);
        Check(recovery.Analyze(MethodRef.Open(caller), caller.Address).TryGet(out var analysis, out _), "接口桩完整分析");
        Check(analysis.Function.Blocks.SelectMany(block => block.Statements).OfType<Call>().Single().Resolved?.Method == member,
            "接口桩按元数据槽选择声明：" + analysis.Function);
        var result = recovery.Recover(MethodRef.Open(caller), caller.Address);
        Check(result.Body is not null && result.Holes.Count == 0, "接口桩经过完整恢复：" + string.Join(';', result.Holes.Select(h => h.Reason)));
        var skeleton = new Skeleton(facts.Model);
        foreach (var (definition, value) in new[] { (a, 37), (b, -91) })
        {
            var il = skeleton.Method(definition).Body.GetILProcessor(); il.Body.Instructions.Clear(); il.Emit(OpCodes.Ldc_I4, value); il.Emit(OpCodes.Ret);
        }
        Check(new BodyEmitter(skeleton, types).Emit([result.Body!]).Count == 0, "接口分派 CIL 检查");
        Check(skeleton.Method(caller).Body.Instructions.Count(i => i.OpCode == OpCodes.Callvirt) == 1, "实际写出动态接口调用");
        using var stream = new MemoryStream(); skeleton.Assembly(fixture.Name).Write(stream);
        var loaded = Assembly.Load(stream.ToArray()); var run = loaded.GetType("Fixture.Reader", true)!.GetMethod("Run")!;
        foreach (var (name, expected) in new[] { ("Fixture.First", 37), ("Fixture.Second", -91) })
        {
            var instance = System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(loaded.GetType(name, true)!);
            Check((int)run.Invoke(null, [instance])! == expected, "根据实际对象选择接口实现");
        }
        try { run.Invoke(null, [null]); }
        catch (TargetInvocationException error) when (error.InnerException is NullReferenceException)
        {
            Console.WriteLine("原生接口桩完整恢复/CIL/CLR 对照通过：两个动态实现、空引用及原生变异拒绝"); return;
        }
        throw new InvalidOperationException("接口调用必须保留空引用异常");
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

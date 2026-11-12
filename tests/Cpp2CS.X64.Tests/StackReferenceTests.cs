using System.Buffers.Binary;
using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Model;
using Cpp2CS.Output;
using Cpp2CS.Recovery;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class StackReferenceTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        var cases = 0;
        foreach (var position in new[] { 4, 5 })
        foreach (var scalar in new[] { "Byte", "Int32", "UInt64", "Single", "Double" })
        foreach (var variant in new[] { "valid", "narrow", "wide", "slot" })
        {
            // 浮点形参按位置使用 XMM0；ref 指针位于第五或第六个 ABI 槽。
            if (variant == "wide" && scalar is not ("Byte" or "Int32")) continue;
            if (variant == "narrow" && scalar is not ("Int32" or "UInt64")) continue;
            var bytes = original.ToArray();
            var offset = 40 + (position - 4) * 8 + (variant == "slot" ? 8 : 0);
            var store = variant == "wide" ? "488908" : variant == "narrow" ? "8808" : scalar switch
            {
                "Byte" => "8808",
                "Int32" => "8908",
                "UInt64" => "488908",
                "Single" => "F30F1100",
                _ => "F20F1100",
            };
            var native = System.Convert.FromHexString("488B4424" + offset.ToString("X2") + store + "C3");
            native.CopyTo(bytes, 0x200);
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            U32(0x124, 12); U32(0x704, (uint)(0x1000 + native.Length)); U32(0x708, 0x3140); bytes[0x740] = 1;
            var names = new[] { "Void", "Boolean", "Char", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64", "Single", "Double",
                "String", "TypedReference", "IntPtr", "UIntPtr", "Object", "ValueType", "RuntimeTypeHandle", "RuntimeFieldHandle", "RuntimeMethodHandle", "NullReferenceException" };
            var core = names.Select((name, i) => new TypeDef { Index = i, Assembly = "mscorlib.dll", Namespace = "System", Name = name,
                Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public, IsValueType = name is not ("String" or "Object" or "ValueType" or "NullReferenceException"),
                IsEnum = false, Size = name switch { "Byte" or "Boolean" => 1, "Int16" or "UInt16" or "Char" => 2, "Int32" or "UInt32" or "Single" => 4, _ => 8 } }).ToArray();
            TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
            var assemblyName = $"StackReference{position}{scalar}{variant}";
            TypeDef Define(int i, string name) => new() { Index = core.Length + i, Assembly = assemblyName + ".dll", Namespace = "", Name = name,
                Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16, BaseType = Corlib("Object") };
            var module = Define(0, "<Module>"); var owner = Define(1, "Writer");
            var parameters = Enumerable.Range(0, position)
                .Select(i => new ParameterDef("a" + i, Corlib(i == 0 ? scalar : "Int32"), 0, null, false)).ToList();
            parameters.Add(new("target", new ByRefRef(Corlib(scalar)), 0, null, false));
            var run = new MethodDef { Index = 0, Owner = owner, Name = "Run", Token = 0x06000001, Address = 0x180001000,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void"), Parameters = parameters.ToArray() };
            owner.Methods = [run];
            var exception = core.Single(t => t.Name == "NullReferenceException");
            var exceptionCtor = new MethodDef { Index = 1, Owner = exception, Name = ".ctor", Token = 0x06000001,
                Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void") };
            exception.Methods = [exceptionCtor];
            var coreAssembly = new AssemblyDef { Name = "mscorlib.dll", AssemblyName = "mscorlib", Version = new(4, 0, 0, 0), Culture = "", PublicKey = [], Types = core };
            var fixture = new AssemblyDef { Name = module.Assembly, AssemblyName = assemblyName, Version = new(1, 0, 0, 0), Culture = "", PublicKey = [], Types = [module, owner] };
            var image = ImageDocument.Parse(bytes);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [coreAssembly, fixture], Types = [.. core, module, owner],
                Methods = [run, exceptionCtor], Fields = [], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            CodeEntry[] registered = [new(run.Address, EntryKind.Method, MethodRef.Open(run), 0, null)];
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = registered,
                ByAddress = registered.GroupBy(e => e.Address).ToDictionary(g => g.Key, g => g.ToArray()), Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
                MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var code = CodeMap.BuildPe(image, [run.Address]); var scan = CodeScan.Unscanned(code);
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = scan, Registrations = registrations, Layouts = new FieldLayouts(model),
                Helpers = RuntimeHelpers.Unclassified(code, scan), Usages = UsageSlots.Build(model, code, scan), Checks = new(), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var method = MethodRef.Open(run);
            var signature = facts.CreateAbi().Machine(method, out var problem);
            Check(signature?.Arguments[position] is { Transfer: Transfer.Reference, Pieces: [{ Register.Bank: Bank.Stack, Width: 64 }] } reference
                && reference.Pieces[0].Register.Index == 40 + (position - 4) * 8, "ref 参数须使用栈传指针 ABI：" + problem);
            var types = new ManagedTypes(model, facts.Layouts);
            var result = new MethodDecompiler(facts, types).Recover(method, run.Address);
            if (variant is "wide" or "slot")
            {
                Check(result.Body is null, "宽度越界或错误栈槽不能解释为 ref 写入：" + scalar + "/" + variant
                    + ": " + string.Join(';', result.Body?.Blocks.SelectMany(b => b.Statements) ?? []));
                continue;
            }
            Check(result.Body is not null, "栈传 ref 须恢复原位置：" + position + "/" + scalar + ": " + string.Join(';', result.Holes.Select(h => h.Reason)));
            var skeleton = new Skeleton(model);
            Check(new BodyEmitter(skeleton, types).Emit([result.Body!]).Count == 0, "栈传 ref CIL 写出");
            using var stream = new MemoryStream(); skeleton.Assembly(module.Assembly).Write(stream);
            var loaded = Assembly.Load(stream.ToArray()); var execute = loaded.GetType("Writer", true)!.GetMethod("Run")!;
            foreach (var value in Values(scalar))
            {
                var arguments = new object[position + 1]; arguments[0] = value;
                for (var i = 1; i < position; i++) arguments[i] = i * 113;
                arguments[position] = variant == "narrow" ? scalar == "Int32" ? (object)unchecked((int)0xaabbccdd) : 0xaabbccddeeff0011UL : Values(scalar)[0];
                var expected = variant != "narrow" ? value : scalar == "Int32"
                    ? (object)unchecked(((int)arguments[position] & ~255) | ((int)value & 255))
                    : ((ulong)arguments[position] & ~255UL) | ((ulong)value & 255UL);
                execute.Invoke(null, arguments);
                Check(EqualBits(arguments[position], expected), "ref 写入必须修改调用方位置并保留未写位：" + scalar + "/" + variant);
                for (var i = 1; i < position; i++) Check((int)arguments[i] == i * 113, "相邻参数不得改写");
                cases++;
            }
        }
        Console.WriteLine($"栈传 ref 完整恢复/CIL/CLR 对照通过：{cases} 组，第五/第六槽、整数/浮点位型、宽度与栈槽变异拒绝");
    }

    private static object[] Values(string scalar) => scalar switch
    {
        "Byte" => [(byte)0, (byte)1, (byte)127, (byte)128, byte.MaxValue],
        "Int32" => [0, 1, -1, int.MinValue, int.MaxValue],
        "UInt64" => [0UL, 1UL, 0x8000000000000000UL, 0xdeadbeef12345678UL, ulong.MaxValue],
        "Single" => [0f, -0f, 1.5f, float.PositiveInfinity, BitConverter.Int32BitsToSingle(unchecked((int)0xffc01234))],
        _ => [0d, -0d, 1.5d, double.NegativeInfinity, BitConverter.Int64BitsToDouble(unchecked((long)0xfff8123456789abc))],
    };

    private static bool EqualBits(object left, object right) => left switch
    {
        float f when right is float g => BitConverter.SingleToInt32Bits(f) == BitConverter.SingleToInt32Bits(g),
        double d when right is double e => BitConverter.DoubleToInt64Bits(d) == BitConverter.DoubleToInt64Bits(e),
        _ => left.Equals(right),
    };

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

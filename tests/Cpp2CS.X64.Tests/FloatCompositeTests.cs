using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Model;
using Cpp2CS.Output;
using Cpp2CS.Recovery;
using Cpp2CS.X64;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Recovery.Typing;
using Cpp2CS.Recovery.Values;
using Convert = System.Convert;

namespace Cpp2CS.X64.Tests;

internal static class FloatCompositeTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        var executed = 0;
        foreach (var width in new[] { 32, 64 })
        foreach (var op in new[] { 0x54, 0x56, 0x57 })
        foreach (var variant in new[] { "sign", "exponent", "mantissa", "phi", "masked-phi", "pair-low", "pair-high", "undefined", "select" })
        {
            var pair = variant is "pair-low" or "pair-high";
            if (pair && width != 32) continue;
            var bytes = original.ToArray(); var prefix = width == 64 ? new byte[] { 0x66 } : [];
            byte[] native = [.. prefix, 0x0f, (byte)op, (byte)(variant == "undefined" ? 0x0d : 0x05), 0, 0, 0, 0, 0xc3];
            BinaryPrimitives.WriteInt32LittleEndian(native.AsSpan(prefix.Length + 3), 0x31c0 - (0x1007 + prefix.Length));
            if (variant == "undefined") native = [.. native[..^1], 0x0f, 0x28, 0xc1, 0xc3];
            if (variant == "phi")
            {
                native = [.. Convert.FromHexString("85D274030F28C2"), .. native];
                BinaryPrimitives.WriteInt32LittleEndian(native.AsSpan(7 + prefix.Length + 3), 0x31c0 - (0x100e + prefix.Length));
            }
            if (variant == "select")
            {
                native = [width == 32 ? (byte)0xf3 : (byte)0xf2, 0x0f, 0x5f, 0xc1, .. native];
                BinaryPrimitives.WriteInt32LittleEndian(native.AsSpan(4 + prefix.Length + 3), 0x31c0 - (0x100b + prefix.Length));
            }
            if (variant == "masked-phi")
            {
                var operation = native[..^1]; var length = operation.Length;
                native = [0x85, 0xd2, 0x74, (byte)(3 + length + 2), 0x0f, 0x28, 0xc2,
                    .. operation, 0xeb, (byte)length, .. operation, 0xc3];
                foreach (var at in new[] { 7, 7 + length + 2 })
                    BinaryPrimitives.WriteInt32LittleEndian(native.AsSpan(at + prefix.Length + 3), 0x31c0 - (0x1000 + at + length));
            }
            if (pair)
            {
                byte[] load = [.. Convert.FromHexString("85D27408F3410F7E4010EB05F30F7E4110"),
                    .. variant == "pair-high" ? Convert.FromHexString("660F73D804") : Array.Empty<byte>()];
                native = [.. load, .. native];
                BinaryPrimitives.WriteInt32LittleEndian(native.AsSpan(load.Length + prefix.Length + 3), 0x31c0 - (0x1000 + native.Length - 1));
            }
            native.CopyTo(bytes, 0x200);
            ulong mask = (width, variant) switch
            {
                (32, "sign" or "phi" or "masked-phi" or "pair-low" or "pair-high" or "undefined") => 0x7fffffff, (32, "exponent") => 0x3fffffff, (32, _) => 0xff800000,
                (64, "sign" or "phi" or "masked-phi" or "undefined") => 0x7fffffffffffffff, (64, "exponent") => 0x3fffffffffffffff, _ => 0xfff0000000000000,
            };
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x7c0), mask);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x7c8), 0);
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            U32(0x124, 12); U32(0x700, 0x1000); U32(0x704, (uint)(0x1000 + native.Length)); U32(0x708, 0x3140); bytes[0x740] = 1;
            var names = new[] { "Void", "Boolean", "Char", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64", "Single", "Double", "String", "TypedReference", "IntPtr", "UIntPtr", "Object", "ValueType", "RuntimeTypeHandle", "RuntimeFieldHandle", "RuntimeMethodHandle", "BitConverter", "NullReferenceException" };
            var core = names.Select((name, i) => new TypeDef { Index = i, Assembly = "mscorlib.dll", Namespace = "System", Name = name, Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public,
                IsValueType = name is not ("String" or "Object" or "ValueType" or "BitConverter" or "NullReferenceException"), IsEnum = false, Size = name is "Single" or "Int32" or "UInt32" ? 4 : 8 }).ToArray();
            TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
            var assemblyName = $"FloatComposite{width}_{op}_{variant}";
            var module = new TypeDef { Index = core.Length, Assembly = assemblyName + ".dll", Namespace = "", Name = "<Module>", Token = 0x02000001, Attributes = TypeAttributes.NotPublic, IsValueType = false, IsEnum = false };
            var owner = new TypeDef { Index = core.Length + 1, Assembly = module.Assembly, Namespace = "Fixture", Name = "Bits", Token = 0x02000002, Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, BaseType = Corlib("Object") };
            var scalar = Corlib(width == 32 ? "Single" : "Double");
            var holder = new TypeDef { Index = core.Length + 2, Assembly = module.Assembly, Namespace = "Fixture", Name = "Pair", Token = 0x02000003,
                Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 24, BaseType = Corlib("Object") };
            holder.Fields = new[] { "x", "y" }.Select((name, index) => new FieldDef { Index = index, Owner = holder, Name = name,
                Attributes = FieldAttributes.Public, Type = Corlib("Single"), Offset = 16 + index * 4 }).ToArray();
            var inputType = pair ? new DefinitionRef(holder, []) : scalar;
            var run = new MethodDef { Index = 0, Owner = owner, Name = "Run", Token = 0x06000001, Address = 0x180001000, Attributes = MethodAttributes.Public | MethodAttributes.Static,
                ImplAttributes = 0, Slot = -1, ReturnType = scalar, Parameters = pair || variant is "phi" or "masked-phi"
                    ? [new("input", inputType, 0, null, false), new("choose", Corlib("Int32"), 0, null, false), new("second", inputType, 0, null, false)]
                    : variant == "select" ? [new("input", scalar, 0, null, false), new("second", scalar, 0, null, false)]
                    : [new("input", scalar, 0, null, false)] }; owner.Methods = [run];
            var converter = core.Single(t => t.Name == "BitConverter");
            var signatures = new[] { ("SingleToInt32Bits", "Single", "Int32"), ("Int32BitsToSingle", "Int32", "Single"), ("DoubleToInt64Bits", "Double", "Int64"), ("Int64BitsToDouble", "Int64", "Double") };
            converter.Methods = signatures.Select((s, i) => new MethodDef { Index = i + 1, Owner = converter, Name = s.Item1, Token = (uint)(0x06000001 + i), Attributes = MethodAttributes.Public | MethodAttributes.Static,
                ImplAttributes = 0, Slot = -1, ReturnType = Corlib(s.Item3), Parameters = [new("value", Corlib(s.Item2), 0, null, false)] }).ToArray();
            var exception = core.Single(t => t.Name == "NullReferenceException");
            var exceptionCtor = new MethodDef { Index = 5, Owner = exception, Name = ".ctor", Token = 0x06000005, Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void") }; exception.Methods = [exceptionCtor];
            var coreAssembly = new AssemblyDef { Name = "mscorlib.dll", AssemblyName = "mscorlib", Version = new(4, 0, 0, 0), Culture = "", PublicKey = [], Types = core };
            var fixture = new AssemblyDef { Name = module.Assembly, AssemblyName = assemblyName, Version = new(1, 0, 0, 0), Culture = "", PublicKey = [], Types = pair ? [module, owner, holder] : [module, owner] };
            var image = ImageDocument.Parse(bytes);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [coreAssembly, fixture], Types = [.. core, .. fixture.Types], Methods = [run, .. converter.Methods, exceptionCtor], Fields = pair ? holder.Fields : [], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var code = CodeMap.BuildPe(image, [run.Address]); var scan = CodeScan.Unscanned(code);
            var entry = new CodeEntry(run.Address, EntryKind.Method, MethodRef.Open(run), 0, null);
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = [entry], ByAddress = new Dictionary<ulong, CodeEntry[]> { [run.Address] = [entry] }, Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(), MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = scan, Registrations = registrations, Layouts = new FieldLayouts(model), Helpers = RuntimeHelpers.Unclassified(code, scan), Usages = UsageSlots.Build(model, code, scan), Checks = new(), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var types = new ManagedTypes(model, facts.Layouts); var recovery = new MethodDecompiler(facts, types);
            if (pair && op == 0x54)
            {
                Check(recovery.Analyze(MethodRef.Open(run), run.Address).TryGet(out var analysis, out _), "合并字段读取的独立位片夹具需要有效机器分析");
                var symbols = analysis!.Values.Syms;
                var oracle = new TypeOracle(types, facts, MethodRef.Open(run), analysis.Environment.Shape, analysis.Values, analysis.Memory);
                var join = new Block(0x9000); var left = new Block(0x9010); var right = new Block(0x9020);
                MachineFunction.AddEdge(left, join); MachineFunction.AddEdge(right, join);
                var site = analysis.Function.EntryBlock.Statements.First();
                var readLeft = symbols.Read(site, 10, symbols.Binary(BinOp.Add, symbols.Arg(0, 64), symbols.Const(16, 64), 64), 64);
                var readRight = symbols.Read(site, 11, symbols.Binary(BinOp.Add, symbols.Arg(2, 64), symbols.Const(16, 64), 64), 64);
                var whole = symbols.Phi(join, new object(), 64);
                symbols.SetSource(whole, 0, readLeft); symbols.SetSource(whole, 1, readRight);
                foreach (var low in new[] { 0, 32 })
                {
                    var piece = oracle.UntypedWidePhiPiece(new SliceSym(whole, low, 31));
                    Check(piece is not null && piece.Sources.Length == 2 && oracle.IntegerPhiBits(piece),
                        "64 位相邻浮点字段合流的低／高 31 位必须逐入边投影并证明位片载体");
                }
                var unknown = symbols.Phi(join, new object(), 64);
                symbols.SetSource(unknown, 0, readLeft); symbols.SetSource(unknown, 1, symbols.Undef(64));
                Check(oracle.UntypedWidePhiPiece(new SliceSym(unknown, 0, 31)) is null, "缺少一条入边的定义不能投影成已知位片");
                var narrow = symbols.Phi(join, new object(), 31);
                symbols.SetSource(narrow, 0, symbols.Slice(readLeft, 0, 31)); symbols.SetSource(narrow, 1, symbols.Undef(31));
                Check(!oracle.IntegerPhiBits(narrow), "非标准宽度载体不能补零未知入边");
            }
            var result = recovery.Recover(MethodRef.Open(run), run.Address);
            if (variant == "undefined") { Check(result.Body is null && result.Holes.Count > 0, "未知浮点位不得填零冒充成功"); continue; }
            Check(result.Body is not null, "浮点位重组须完成恢复：" + width + "/" + op + "/" + variant + ":" + string.Join(';', result.Holes.Select(h => h.Reason)));
            var skeleton = new Skeleton(model);
            Check(new BodyEmitter(skeleton, types).Emit([result.Body!]).Count == 0, "浮点位重组须通过 CIL 写出");
            using var stream = new MemoryStream(); skeleton.Assembly(module.Assembly).Write(stream);
            var method = Assembly.Load(stream.ToArray()).GetType("Fixture.Bits", true)!.GetMethod("Run")!;
            ulong[] special = width == 32 ? [0, 0x80000000, 0x3f800000, 0xbf800000, 0x7f800000, 0xff800000, 0x7fc12345, 0xffc54321, 0x7f812345, 0xff812345, 1, 0x80000001, 0x7fffff, 0x807fffff]
                : [0, 0x8000000000000000, 0x3ff0000000000000, 0xbff0000000000000, 0x7ff0000000000000, 0xfff0000000000000, 0x7ff8123456789abc, 0xfff854321fedcba9, 0x7ff0123456789abc, 0xfff0123456789abc, 1, 0x8000000000000001, 0xfffffffffffff, 0x800fffffffffffff];
            var random = new Random(81237); var inputs = special.Concat(Enumerable.Range(0, 256).Select(_ => { var raw = new byte[8]; random.NextBytes(raw); return BinaryPrimitives.ReadUInt64LittleEndian(raw) & (width == 32 ? uint.MaxValue : ulong.MaxValue); }));
            foreach (var bits in inputs)
            for (var choose = 0; choose < (pair || variant is "phi" or "masked-phi" ? 2 : 1); choose++)
            {
                object input = width == 32 ? (object)BitConverter.Int32BitsToSingle(unchecked((int)bits)) : BitConverter.Int64BitsToDouble(unchecked((long)bits));
                var otherBits = (bits ^ 0x80abcdef83456789) & (width == 32 ? uint.MaxValue : ulong.MaxValue);
                object other = width == 32 ? (object)BitConverter.Int32BitsToSingle(unchecked((int)otherBits)) : BitConverter.Int64BitsToDouble(unchecked((long)otherBits));
                object firstArgument = input, secondArgument = other;
                if (pair)
                {
                    var pairType = method.GetParameters()[0].ParameterType;
                    firstArgument = System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(pairType);
                    secondArgument = System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(pairType);
                    pairType.GetField("x")!.SetValue(firstArgument, input); pairType.GetField("y")!.SetValue(firstArgument, other);
                    pairType.GetField("x")!.SetValue(secondArgument, other); pairType.GetField("y")!.SetValue(secondArgument, input);
                }
                var output = method.Invoke(null, pair || variant is "phi" or "masked-phi" ? [firstArgument, choose, secondArgument] : variant == "select" ? [input, other] : [input])!;
                var actual = width == 32 ? unchecked((uint)BitConverter.SingleToInt32Bits((float)output)) : unchecked((ulong)BitConverter.DoubleToInt64Bits((double)output));
                var selected = (pair || variant is "phi" or "masked-phi") && choose != 0 ? otherBits : bits;
                if (variant == "pair-high") selected = choose == 0 ? otherBits : bits;
                if (variant == "select")
                    selected = width == 32
                        ? BitConverter.SingleToUInt32Bits(Sse.MaxScalar(Vector128.CreateScalar((float)input), Vector128.CreateScalar((float)other)).GetElement(0))
                        : BitConverter.DoubleToUInt64Bits(Sse2.MaxScalar(Vector128.CreateScalar((double)input), Vector128.CreateScalar((double)other)).GetElement(0));
                var expected = op == 0x54 ? selected & mask : op == 0x56 ? selected | mask : selected ^ mask;
                Check(actual == expected, $"浮点位型不符：{width}/{op}/{variant} {bits:x}: {actual:x} != {expected:x}"); executed++;
            }
        }
        Console.WriteLine($"浮点位重组完整恢复/CIL/CLR 对照通过：{executed} 组位型，含 NaN 载荷、符号零、非规格化数及未定义位拒绝");
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

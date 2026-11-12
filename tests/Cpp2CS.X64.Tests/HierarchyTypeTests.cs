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

internal static class HierarchyTypeTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        ModularEquality();
        foreach (var variant in new[] { "is", "is-not", "as", "wrong-index", "wrong-scale", "wrong-hierarchy", "wrong-depth-source", "wrong-type", "extra-store", "different-failure-value", "different-fail-phi", "interface" })
        {
            const ulong basis = 0x180000000;
            var bytes = original.ToArray(); var native = new List<byte>(); var failures = new List<int>();
            void Emit(string hex) => native.AddRange(System.Convert.FromHexString(hex));
            void Fail(byte opcode) { native.Add(opcode); failures.Add(native.Count); native.Add(0); }
            if (variant == "different-fail-phi") Emit("4533D2");
            Emit("4885C9"); Fail(0x74); Emit("488B01488B15");
            var displacement = native.Count; Emit("00000000");
            Emit(variant == "wrong-depth-source" ? "440FB68030010000" : "440FB68230010000");
            Emit("44388030010000"); Fail(0x72);
            Emit(variant == "wrong-hierarchy" ? "488B80D0000000" : "488B80C8000000");
            if (variant == "extra-store") Emit("C7411001000000");
            if (variant == "different-fail-phi") Emit("41BA14000000");
            Emit(variant == "wrong-type" ? "4A394CC0F8" : variant == "wrong-scale" ? "4A395480F8" : variant == "wrong-index" ? "4A3954C0F0" : "4A3954C0F8");
            int? differentFailure = null;
            if (variant == "as") Emit("B800000000480F44C1C3");
            else
            {
                Fail(0x75);
                if (variant == "different-failure-value") { differentFailure = failures[^1]; failures.RemoveAt(failures.Count - 1); }
                Emit(variant == "is-not" ? "B800000000C3" : "B801000000C3");
            }
            var failure = native.Count; Emit(variant == "different-fail-phi" ? "418BC2C3" : variant == "is-not" ? "B801000000C3" : "B800000000C3");
            if (differentFailure is { } alternate) { native[alternate] = checked((byte)(native.Count - alternate - 1)); Emit("B814000000C3"); }
            foreach (var at in failures) native[at] = checked((byte)(failure - at - 1));
            var machineCode = native.ToArray(); BinaryPrimitives.WriteInt32LittleEndian(machineCode.AsSpan(displacement), 0x2000 - (0x1000 + displacement + 4));
            machineCode.CopyTo(bytes, 0x200);
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            U32(0x124, 12); U32(0x700, 0x1000); U32(0x704, (uint)(0x1000 + machineCode.Length)); U32(0x708, 0x3140); bytes[0x740] = 1;
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(0x400), 0x20000001);
            var names = new[] { "Void", "Boolean", "Char", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64", "Single", "Double",
                "String", "TypedReference", "IntPtr", "UIntPtr", "Object", "ValueType", "RuntimeTypeHandle", "RuntimeFieldHandle", "RuntimeMethodHandle", "NullReferenceException" };
            var core = names.Select((name, i) => new TypeDef { Index = i, Assembly = "mscorlib.dll", Namespace = "System", Name = name,
                Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public, IsValueType = name is not ("String" or "Object" or "ValueType" or "NullReferenceException"),
                IsEnum = false, Size = name == "Boolean" ? 1 : name == "Int32" ? 4 : 8 }).ToArray();
            TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
            var exception = core.Single(t => t.Name == "NullReferenceException");
            var exceptionCtor = new MethodDef { Index = 1, Owner = exception, Name = ".ctor", Token = 0x06000001,
                Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void") }; exception.Methods = [exceptionCtor];
            var assemblyName = "HierarchyType" + variant;
            TypeDef Define(int index, string name, TypeRef parent) => new() { Index = core.Length + index, Assembly = assemblyName + ".dll", Namespace = index == 0 ? "" : "Fixture",
                Name = name, Token = (uint)(0x02000001 + index), Attributes = TypeAttributes.Public | (variant == "interface" && index == 1 ? TypeAttributes.Interface | TypeAttributes.Abstract : 0),
                IsValueType = false, IsEnum = false, Size = 24, BaseType = parent };
            var module = Define(0, "<Module>", Corlib("Object")); var target = Define(1, "Ancestor", Corlib("Object"));
            var targetType = new DefinitionRef(target, []); var child = Define(2, "Descendant", targetType); var other = Define(3, "Unrelated", Corlib("Object"));
            var owner = Define(4, "Test", Corlib("Object"));
            var method = new MethodDef { Index = 0, Owner = owner, Name = "Check", Token = 0x06000001, Address = basis + 0x1000,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1,
                ReturnType = Corlib(variant == "as" ? "Object" : variant is "different-failure-value" or "different-fail-phi" ? "Int32" : "Boolean"), Parameters = [new("value", Corlib("Object"), 0, null, false)] };
            owner.Methods = [method];
            var fixture = new AssemblyDef { Name = module.Assembly, AssemblyName = assemblyName, Version = new(1, 0, 0, 0), Culture = "", PublicKey = [], Types = [module, target, child, other, owner] };
            var corlib = new AssemblyDef { Name = "mscorlib.dll", AssemblyName = "mscorlib", Version = new(4, 0, 0, 0), Culture = "", PublicKey = [], Types = core };
            var image = ImageDocument.Parse(bytes);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [corlib, fixture], Types = [.. core, .. fixture.Types], Methods = [method, exceptionCtor],
                Fields = [], RuntimeTypes = [targetType], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var code = CodeMap.BuildPe(image, [method.Address]); var machine = new PcodeMachine(image, decoder);
            var scan = X64References.Scan(code, machine, [method.Address]); var usages = UsageSlots.Build(model, code, scan);
            var entry = new CodeEntry(method.Address, EntryKind.Method, MethodRef.Open(method), 0, null);
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = [entry], ByAddress = new Dictionary<ulong, CodeEntry[]> { [method.Address] = [entry] },
                Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(), MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = scan, Registrations = registrations, Layouts = new FieldLayouts(model), Usages = usages,
                Helpers = RuntimeHelpers.Unclassified(code, scan), Checks = new(), MachineFactory = () => machine }, new());
            var types = new ManagedTypes(model, facts.Layouts); var recovery = new MethodDecompiler(facts, types);
            Check(recovery.Analyze(MethodRef.Open(method), method.Address).TryGet(out var analysis, out _), "继承链夹具须完成分析");
            var recognized = analysis!.Function.Blocks.SelectMany(b => b.Statements).OfType<Call>().Count(c => c.Op?.Kind == OpKind.TypeCheck);
            Check(recognized == (variant is "is" or "is-not" or "as" ? 1 : 0), "只匹配同一目标深度的继承表槽，保留额外效果：" + variant
                + "\n" + string.Join(';', analysis.Idioms.Rejections) + "\n" + analysis.Function);
            if (variant is not ("is" or "is-not" or "as")) continue;
            var result = recovery.Recover(MethodRef.Open(method), method.Address);
            Check(result.Body is not null, "P-code 字节标志须接回已有类型检查：" + string.Join(';', result.Holes.Select(h => h.Reason)));
            var skeleton = new Skeleton(model);
            Check(new BodyEmitter(skeleton, types).Emit([result.Body!]).Count == 0, "继承链类型检查须通过 CIL 检查");
            using var stream = new MemoryStream(); skeleton.Assembly(module.Assembly).Write(stream);
            var loaded = Assembly.Load(stream.ToArray()); var check = loaded.GetType("Fixture.Test", true)!.GetMethod("Check")!;
            foreach (var name in new[] { "Ancestor", "Descendant", "Unrelated" })
            {
                var value = System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(loaded.GetType("Fixture." + name, true)!);
                var expected = (name is "Ancestor" or "Descendant") != (variant == "is-not");
                var actual = check.Invoke(null, [value]);
                Check(variant == "as" ? ReferenceEquals(actual, name is "Ancestor" or "Descendant" ? value : null) : (bool)actual! == expected,
                    "实际 CLR 类型关系须与原生继承表检查一致");
            }
            var nullResult = check.Invoke(null, [null]);
            Check(variant == "as" ? nullResult is null : (bool)nullResult! == (variant == "is-not"), "空引用保持原分支结果");
        }
        Console.WriteLine("继承链完整恢复/CIL/CLR 对照通过：is、反向判断及 as，目标、子类、其他类型与空引用；索引、比例、层次表、目标、额外写入与不同失败值变异拒绝");
    }

    private static void ModularEquality()
    {
        var cases = 0;
        foreach (var width in new[] { 8, 16, 32, 64 })
        {
            var left = new Read(Storage.Gpr(0), width); var right = new Read(Storage.Gpr(1), width);
            var mask = Expr.Mask(width);
            foreach (var condition in new[] { Cond.Eq, Cond.Ne })
            {
                var original = new Compare(condition, new Binary(BinOp.Sub, left, right, width), Expr.C(0, width));
                var folded = Fold.Simplify(original);
                Check(folded is Compare { Left: Read, Right: Read }, "同宽减法零测试应还原成操作数比较");
                foreach (var a in new[] { 0UL, 1UL, 2UL, mask, mask >> 1, (mask >> 1) + 1 })
                foreach (var b in new[] { 0UL, 1UL, 2UL, mask, mask >> 1, (mask >> 1) + 1 })
                {
                    var evaluator = new Evaluator(); evaluator.Registers[Storage.Gpr(0)] = a; evaluator.Registers[Storage.Gpr(1)] = b;
                    var zero = ((a - b) & mask) == 0;
                    Check((evaluator.Eval(folded) != 0) == (condition == Cond.Eq ? zero : !zero), "保留模减法的相等与不等语义");
                    cases++;
                }
            }
            var truncated = new Compare(Cond.Eq, new Binary(BinOp.Sub, new Read(Storage.Gpr(0), 64), new Read(Storage.Gpr(1), 64), width), Expr.C(0, width));
            if (width < 64) Check(Fold.Simplify(truncated) is Compare { Left: Binary { Op: BinOp.Sub } }, "截断差为零不等于完整操作数相等");
            var ordered = new Compare(Cond.Slt, new Binary(BinOp.Sub, left, right, width), Expr.C(0, width));
            Check(Fold.Simplify(ordered) is Compare { Left: Binary { Op: BinOp.Sub } }, "有序比较不能忽略减法溢出");
        }
        Console.WriteLine($"减法零测试执行对照通过：{cases} 组输入，保留截断及有序比较边界");
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

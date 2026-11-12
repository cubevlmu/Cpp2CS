using System.Buffers.Binary;
using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Model;
using Cpp2CS.Output;
using Cpp2CS.Recovery;
using Cpp2CS.X64;
using Convert = System.Convert;

namespace Cpp2CS.X64.Tests;

internal static class StackCopyTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        foreach (var variant in new[] { "read", "write", "snapshot", "sixth", "overwrite", "conditional", "escape", "snapshot-escape", "mixed-address" })
        {
            var bytes = original.ToArray();
            var native = Convert.FromHexString(variant switch
            {
                "write" => "488B4424288950088B4008C3",
                "snapshot" => "488B44242848894C24288B4008C3",
                "sixth" => "488B4424308B4008C3",
                "overwrite" => "48894C2428488B4424288B4008C3",
                "conditional" => "85D2740548894C2428488B4424288B4008C3",
                "escape" => "4883EC28488D4C2450E872000000488B4424508B40084883C428C3",
                "mixed-address" => "488D44242885D27403488BC1488B008B4008C3",
                "snapshot-escape" => "534883EC20488B5C2450488D4C2450E86C0000008B43084883C4205BC3",
                _ => "488B4424288B4008C3",
            });
            native.CopyTo(bytes, 0x200);
            Convert.FromHexString("0F0BC3").CopyTo(bytes, 0x280);
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            U32(0x124, 12); U32(0x704, (uint)(0x1000 + native.Length)); U32(0x708, 0x3140); bytes[0x740] = 1;
            var names = new[] { "Void", "Boolean", "Char", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64", "Single", "Double",
                "String", "TypedReference", "IntPtr", "UIntPtr", "Object", "ValueType", "RuntimeTypeHandle", "RuntimeFieldHandle", "RuntimeMethodHandle", "NullReferenceException" };
            var core = names.Select((name, i) => new TypeDef { Index = i, Assembly = "mscorlib.dll", Namespace = "System", Name = name,
                Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public, IsValueType = name is not ("String" or "Object" or "ValueType" or "NullReferenceException"),
                IsEnum = false, Size = name == "Int32" ? 4 : 8 }).ToArray();
            TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
            var assemblyName = "StackCopy" + variant;
            TypeDef Define(int i, string name, bool value) => new() { Index = core.Length + i, Assembly = assemblyName + ".dll", Namespace = "", Name = name,
                Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public | (value ? TypeAttributes.SequentialLayout | TypeAttributes.Sealed : 0),
                IsValueType = value, IsEnum = false, Size = 16, BaseType = Corlib(value ? "ValueType" : "Object") };
            var module = Define(0, "<Module>", false); var aggregate = Define(1, "Aggregate", true); var owner = Define(2, "Reader", false);
            aggregate.Fields = Enumerable.Range(0, 4).Select(i => new FieldDef { Index = i, Owner = aggregate, Name = "p" + i,
                Type = Corlib("Int32"), Offset = i * 4, Attributes = FieldAttributes.Public }).ToArray();
            var arguments = Enumerable.Range(0, variant == "sixth" ? 5 : 4)
                .Select(i => new ParameterDef("a" + i, Corlib(i == 0 ? "UInt64" : "Int32"), 0, null, false)).ToList();
            arguments.Add(new("value", new DefinitionRef(aggregate, []), 0, null, false));
            var run = new MethodDef { Index = 0, Owner = owner, Name = "Run", Token = 0x06000001, Address = 0x180001000,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Int32"), Parameters = arguments.ToArray() };
            owner.Methods = [run];
            var exception = core.Single(t => t.Name == "NullReferenceException");
            var exceptionCtor = new MethodDef { Index = 1, Owner = exception, Name = ".ctor", Token = 0x06000001,
                Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void") };
            exception.Methods = [exceptionCtor];
            var coreAssembly = new AssemblyDef { Name = "mscorlib.dll", AssemblyName = "mscorlib", Version = new(4, 0, 0, 0), Culture = "", PublicKey = [], Types = core };
            var fixture = new AssemblyDef { Name = module.Assembly, AssemblyName = assemblyName, Version = new(1, 0, 0, 0), Culture = "", PublicKey = [], Types = [module, aggregate, owner] };
            var image = ImageDocument.Parse(bytes);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [coreAssembly, fixture], Types = [.. core, module, aggregate, owner],
                Methods = [run, exceptionCtor], Fields = aggregate.Fields, RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            CodeEntry[] registered = [new(run.Address, EntryKind.Method, MethodRef.Open(run), 0, null)];
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = registered,
                ByAddress = registered.GroupBy(e => e.Address).ToDictionary(g => g.Key, g => g.ToArray()), Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
                MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var code = CodeMap.BuildPe(image, [run.Address]); var scan = CodeScan.Unscanned(code);
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = scan, Registrations = registrations, Layouts = new FieldLayouts(model),
                Helpers = RuntimeHelpers.Unclassified(code, scan), Usages = UsageSlots.Build(model, code, scan), Checks = new(), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var types = new ManagedTypes(model, facts.Layouts);
            var decompiler = new MethodDecompiler(facts, types);
            var result = decompiler.Recover(MethodRef.Open(run), run.Address);
            if (variant is "overwrite" or "conditional" or "escape" or "snapshot-escape" or "mixed-address")
            {
                Check(result.Body is null, "入口指针被改写或可能经调用改写时必须拒绝：" + variant);
                if (decompiler.Analyze(MethodRef.Open(run), run.Address).TryGet(out var analysis, out _))
                {
                    // 上游可以拆分混合地址的分支；栈分支可提升，外部指针分支必须保留原读取。
                    if (variant == "mixed-address")
                        Check(analysis.Function.Blocks.SelectMany(b => b.Statements).SelectMany(ExprMap.Operands).SelectMany(ExprMap.Walk)
                            .OfType<Load>().Any(l => l.Address is Entry { Storage: { Bank: Bank.Gpr, Index: 1 } }
                                or Use { Variable: { Version: 0, Storage: { Bank: Bank.Gpr, Index: 1 } } }),
                            "混合地址的外部分支不能被入口副本替换");
                    else Check(!analysis.Memory.Cells.Any(c => c.Space == Cpp2CS.Recovery.Memory.LocalSpace.Copy(arguments.Count - 1) && c.Promoted),
                        "拒绝例不能先错误提升副本、再仅因其它缺口失败：" + variant);
                }
                continue;
            }
            Check(result.Body is not null, "栈传副本须恢复：" + variant + ": " + string.Join(';', result.Holes.Select(h => h.Reason)));
            var skeleton = new Skeleton(model);
            Check(new BodyEmitter(skeleton, types).Emit([result.Body!]).Count == 0, "栈传副本 CIL 写出");
            using var stream = new MemoryStream(); skeleton.Assembly(module.Assembly).Write(stream);
            var loaded = Assembly.Load(stream.ToArray()); var execute = loaded.GetType("Reader", true)!.GetMethod("Run")!;
            var clrAggregate = loaded.GetType("Aggregate", true)!;
            foreach (var value in new[] { 0, 1, -1, int.MinValue, int.MaxValue })
            foreach (var written in new[] { 0, 37, int.MinValue, int.MaxValue })
            {
                var item = Activator.CreateInstance(clrAggregate)!;
                for (var i = 0; i < 4; i++) clrAggregate.GetField("p" + i)!.SetValue(item, i == 2 ? value : 123 + i);
                var actualArguments = new List<object> { 0UL, written, 0, 0 };
                if (variant == "sixth") actualArguments.Add(0);
                actualArguments.Add(item);
                Check((int)execute.Invoke(null, actualArguments.ToArray())! == (variant == "write" ? written : value), "副本字段及读取快照结果");
                Check((int)clrAggregate.GetField("p2")!.GetValue(item)! == value, "按值形参写入不得修改调用方原值");
            }
        }
        Console.WriteLine("栈传值类型副本完整恢复/CIL/CLR 对照通过：80 组，第五及第六参数、字段写入、指针快照及改写拒绝");
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

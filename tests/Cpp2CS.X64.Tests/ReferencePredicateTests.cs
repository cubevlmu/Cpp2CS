using System.Buffers.Binary;
using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Managed;
using Cpp2CS.Model;
using Cpp2CS.Output;
using Cpp2CS.Recovery;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class ReferencePredicateTests
{
    internal static void Run(byte[] original, SleighDecoder decoder, TypeDef[] core)
    {
        core = core.Select(t => new TypeDef { Index = t.Index, Assembly = t.Assembly, Namespace = t.Namespace, Name = t.Name,
            Token = t.Token, Attributes = t.Attributes, IsValueType = t.IsValueType, IsEnum = false, Size = t.Size }).ToArray();
        foreach (var variant in new[] { "not-null", "unsigned-null", "reverse-null", "is-null", "ordering", "numeric", "field-not-null", "always-false-field", "always-true-field" })
        {
            var bytes = original.ToArray();
            var native = Convert.FromHexString(variant switch
            {
                "unsigned-null" => "33C04883F9000F97C0C3",
                "reverse-null" => "33C04839C80F92C0C3",
                "is-null" => "33C04885C90F94C0C3",
                "ordering" => "33C04839D10F92C0C3",
                "numeric" => "488BC14883C001C3",
                "field-not-null" => "488B491033C04883F9000F97C0C3",
                "always-false-field" => "488B491033C04883F9000F92C0C3",
                "always-true-field" => "488B491033C04883F9000F93C0C3",
                _ => "33C04885C90F95C0C3",
            });
            native.CopyTo(bytes, 0x200);
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            U32(0x124, 12); U32(0x700, 0x1000); U32(0x704, (uint)(0x1000 + native.Length)); U32(0x708, 0x3140); bytes[0x740] = 1;
            TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
            var assemblyName = "ReferencePredicate" + variant;
            var module = new TypeDef { Index = core.Length, Assembly = assemblyName + ".dll", Namespace = "", Name = "<Module>", Token = 0x02000001,
                Attributes = TypeAttributes.NotPublic, IsValueType = false, IsEnum = false };
            var owner = new TypeDef { Index = core.Length + 1, Assembly = module.Assembly, Namespace = "Fixture", Name = "Predicate", Token = 0x02000002,
                Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, BaseType = Corlib("Object") };
            var fromField = variant.Contains("field", StringComparison.Ordinal);
            var field = new FieldDef { Index = 0, Owner = owner, Name = "Value", Type = Corlib("Object"), Offset = 16, Attributes = FieldAttributes.Public };
            owner.Fields = [field];
            var run = new MethodDef { Index = 0, Owner = owner, Name = "Run", Token = 0x06000001, Address = 0x180001000,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1,
                ReturnType = Corlib(variant == "numeric" ? "UInt64" : "Boolean"),
                Parameters = [new("left", fromField ? new DefinitionRef(owner, []) : Corlib("Object"), 0, null, false), new("right", Corlib("Object"), 0, null, false)] };
            owner.Methods = [run];
            var exception = core.Single(t => t.Name == "NullReferenceException");
            var exceptionCtor = new MethodDef { Index = 1, Owner = exception, Name = ".ctor", Token = 0x06000001,
                Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void") };
            exception.Methods = [exceptionCtor];
            var corlib = new AssemblyDef { Name = "mscorlib.dll", AssemblyName = "mscorlib", Version = new(4, 0, 0, 0), Culture = "", PublicKey = [], Types = core };
            var fixture = new AssemblyDef { Name = module.Assembly, AssemblyName = assemblyName, Version = new(1, 0, 0, 0), Culture = "", PublicKey = [], Types = [module, owner] };
            var image = ImageDocument.Parse(bytes);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [corlib, fixture], Types = [.. core, module, owner],
                Methods = [run, .. core.SelectMany(t => t.Methods)], Fields = [field], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            CodeEntry[] entries = [new(run.Address, EntryKind.Method, MethodRef.Open(run), 0, null)];
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries,
                ByAddress = entries.GroupBy(e => e.Address).ToDictionary(g => g.Key, g => g.ToArray()), Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
                MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var code = CodeMap.BuildPe(image, [run.Address]); var scan = CodeScan.Unscanned(code);
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = scan, Registrations = registrations, Layouts = new FieldLayouts(model),
                Helpers = RuntimeHelpers.Unclassified(code, scan), Usages = UsageSlots.Build(model, code, scan), Checks = new(), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var types = new ManagedTypes(model, facts.Layouts); var result = new MethodDecompiler(facts, types).Recover(MethodRef.Open(run), run.Address);
            var skeleton = new Skeleton(model); var emitter = new BodyEmitter(skeleton, types);
            if (variant is "ordering" or "numeric")
            {
                Check(result.Body is null || emitter.Check([result.Body!], EmissionPolicy.Recovered).Count == 1,
                    "引用排序或引用数值地址必须有明确缺口，不能发射非法 CIL");
                continue;
            }
            var problems = result.Body is null ? null : emitter.Emit([result.Body!]);
            Check(result.Body is not null && problems!.Count == 0, "引用判空须完整恢复并通过静态检查：" + variant + ": "
                + string.Join(';', result.Holes.Select(h => h.Reason)) + "; " + string.Join(';', problems?.Values.Select(p => p.Message) ?? [])
                + "; " + string.Join(';', result.Body?.Blocks.SelectMany(b => b.Statements).SelectMany(ManagedValues.Of).SelectMany(ManagedValues.Walk)
                    .OfType<ComparisonValue>().Select(c => c.ToString()) ?? []));
            using var stream = new MemoryStream(); skeleton.Assembly(module.Assembly).Write(stream);
            var loadedType = Assembly.Load(stream.ToArray()).GetType("Fixture.Predicate", true)!;
            var execute = loadedType.GetMethod("Run")!;
            foreach (var value in new object?[] { null, new object(), "value" })
            {
                object? input = value;
                var expected = variant == "is-null" ? value is null : value is not null;
                if (fromField)
                {
                    if (value is null)
                    {
                        var threw = false;
                        try { execute.Invoke(null, [null, new object()]); }
                        catch (TargetInvocationException e) when (e.InnerException is NullReferenceException) { threw = true; }
                        Check(threw, "常量比较结果不能删除字段读取引起的空引用异常");
                        continue;
                    }
                    input = System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(loadedType);
                    var payload = value is string ? null : value;
                    loadedType.GetField("Value")!.SetValue(input, payload);
                    expected = variant == "always-true-field" || variant == "field-not-null" && payload is not null;
                }
                Check((bool)execute.Invoke(null, [input, new object()])! == expected, "引用判空的 CLR 执行结果");
            }
        }
        Console.WriteLine("引用谓词完整恢复/CIL/CLR通过：18组返回值、3组读取异常，排序和数值地址转换拒绝");
    }
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}

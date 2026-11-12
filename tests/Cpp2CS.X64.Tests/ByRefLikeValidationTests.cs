using System.Reflection;
using System.Text.Json;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Managed;
using Cpp2CS.Model;
using Cpp2CS.Output;
using Cpp2CS.Pipeline;

namespace Cpp2CS.X64.Tests;

internal static class ByRefLikeValidationTests
{
    internal static void Run(TypeDef[] core, byte[] bytes)
    {
        PartialHoleTests.Run(core, bytes);
        core = core.Select(t => new TypeDef { Index = t.Index, Assembly = t.Assembly, Namespace = t.Namespace, Name = t.Name,
            Token = t.Token, Attributes = t.Attributes, IsValueType = t.IsValueType, IsEnum = false, Size = t.Size }).ToArray();
        TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
        foreach (var variant in new[] { "ordinary", "restricted", "restricted-array", "typed-reference" })
        {
            var marker = new TypeDef { Index = core.Length, Assembly = "mscorlib.dll", Namespace = "System.Runtime.CompilerServices", Name = "IsByRefLikeAttribute",
                Token = 0x02000100, Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false };
            var attribute = new MethodDef { Index = 1, Owner = marker, Name = ".ctor", Token = 0x06000100,
                Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void") };
            marker.Methods = [attribute];
            var assemblyName = "Boxability" + variant;
            var value = new TypeDef { Index = core.Length + 1, Assembly = assemblyName + ".dll", Namespace = "Fixture", Name = "Item",
                Token = 0x02000001, Attributes = TypeAttributes.Public | TypeAttributes.SequentialLayout, IsValueType = true, IsEnum = false,
                BaseType = Corlib("ValueType"), Size = 4 };
            value.Fields = [new() { Index = 0, Owner = value, Name = "number", Type = Corlib("Int32"), Attributes = FieldAttributes.Public, Offset = 0 }];
            if (variant.StartsWith("restricted", StringComparison.Ordinal)) value.CustomAttributes = [new(attribute, [], [], [])];
            var owner = new TypeDef { Index = core.Length + 2, Assembly = value.Assembly, Namespace = "Fixture", Name = "Factory", Token = 0x02000002,
                Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, BaseType = Corlib("Object") };
            var boxed = variant == "typed-reference" ? Corlib("TypedReference") : new DefinitionRef(value, []);
            var method = new MethodDef { Index = 0, Owner = owner, Name = "Create", Token = 0x06000001,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1,
                ReturnType = Corlib("Object"), Parameters = [new("value", boxed, 0, null, false)] };
            owner.Methods = [method];
            var coreAssembly = new AssemblyDef { Name = "mscorlib.dll", AssemblyName = "mscorlib", Version = new(4, 0, 0, 0), Culture = "", PublicKey = [], Types = [.. core, marker] };
            var fixture = new AssemblyDef { Name = value.Assembly, AssemblyName = assemblyName, Version = new(1, 0, 0, 0), Culture = "", PublicKey = [], Types = [value, owner] };
            var model = new ProgramModel { Image = ImageDocument.Parse(bytes), MetadataVersion = 31, Assemblies = [coreAssembly, fixture], Types = [.. core, marker, value, owner],
                Methods = [method, attribute], Fields = value.Fields, RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var types = new ManagedTypes(model, new FieldLayouts(model)); var skeleton = new Skeleton(model);
            ManagedValue expression = variant == "restricted-array" ? new NewArrayValue(new(boxed, 1), new ConstantValue(1, types.Int32, 32))
                : new BoxValue(new ArgumentValue(0, boxed, 0), boxed, types.Object);
            var body = new ManagedBody(MethodRef.Open(method), [new(0x1000, [new ManagedReturn(0x1000, expression)])]);
            var problems = new BodyEmitter(skeleton, types).Check([body]);
            if (variant == "ordinary")
            {
                if (problems.Count != 0) throw new InvalidOperationException("普通值类型装箱不应受限：" + string.Join(';', problems.Values));
                continue;
            }
            if (problems.Count != 1 || problems[body].Kind != EmissionProblemKind.Unsupported)
                throw new InvalidOperationException("受限值类型必须在发射前明确拒绝：" + variant);
            var output = Path.Combine(Path.GetTempPath(), "Cpp2CS-managed-check-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(output);
            try
            {
                var result = new MethodRecoveryResult(MethodRef.Open(method), 0x180001000, body, []);
                ReportStage.WriteManagedChecks(output, new ProgramFacts { Model = model }, [result], [], new HashSet<MethodDef>(), skeleton, problems);
                using var diagnostic = JsonDocument.Parse(File.ReadAllText(Path.Combine(output, "managed-check-diagnostics.jsonl")));
                var row = diagnostic.RootElement;
                if (row.GetProperty("status").GetString() != "failed" || row.GetProperty("published").GetBoolean()
                    || row.GetProperty("methodIndex").GetInt32() != method.Index || row.GetProperty("reason").GetString() != problems[body].Message)
                    throw new InvalidOperationException("静态失败诊断必须保留真实方法、失败原因和未发布状态");
            }
            finally { Directory.Delete(output, true); }
        }
        Console.WriteLine("受限值类型检查及失败报告通过：普通装箱、IsByRefLike 装箱／数组及 TypedReference 拒绝");
    }
}

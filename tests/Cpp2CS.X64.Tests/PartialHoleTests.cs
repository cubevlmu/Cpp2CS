using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Managed;
using Cpp2CS.Model;
using Cpp2CS.Output;

namespace Cpp2CS.X64.Tests;

internal static class PartialHoleTests
{
    internal static void Run(TypeDef[] original, byte[] bytes)
    {
        foreach (var variant in new[] { "reference", "pointer", "ref-struct", "throw" })
        {
            var core = original.Select(t => new TypeDef { Index = t.Index, Assembly = t.Assembly, Namespace = t.Namespace, Name = t.Name,
                Token = t.Token, Attributes = t.Attributes, IsValueType = t.IsValueType, IsEnum = false, Size = t.Size }).ToList();
            TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
            if (core.All(t => t.Name != "Exception")) core.Add(new() { Index = core.Count, Assembly = "mscorlib.dll", Namespace = "System", Name = "Exception",
                Token = 0x02000100, Attributes = TypeAttributes.Public, BaseType = Corlib("Object"), IsValueType = false, IsEnum = false, Size = 16 });
            var marker = new TypeDef { Index = core.Count, Assembly = "mscorlib.dll", Namespace = "System.Runtime.CompilerServices", Name = "IsByRefLikeAttribute",
                Token = 0x02000101, Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, BaseType = Corlib("Object") };
            var attribute = new MethodDef { Index = 2, Owner = marker, Name = ".ctor", Token = 0x06000100,
                Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void") };
            marker.Methods = [attribute]; core.Add(marker);
            var assemblyName = "PartialHole" + variant;
            var module = new TypeDef { Index = core.Count, Assembly = assemblyName + ".dll", Namespace = "", Name = "<Module>", Token = 0x02000001,
                Attributes = TypeAttributes.NotPublic, IsValueType = false, IsEnum = false };
            var item = new TypeDef { Index = core.Count + 1, Assembly = assemblyName + ".dll", Namespace = "Fixture", Name = "Item", Token = 0x02000002,
                Attributes = TypeAttributes.Public | TypeAttributes.SequentialLayout, IsValueType = true, IsEnum = false, BaseType = Corlib("ValueType"), Size = 4,
                CustomAttributes = [new(attribute, [], [], [])] };
            item.Fields = [new() { Index = 0, Owner = item, Name = "Number", Type = Corlib("Int32"), Attributes = FieldAttributes.Public, Offset = 0 }];
            var owner = new TypeDef { Index = core.Count + 2, Assembly = item.Assembly, Namespace = "Fixture", Name = "Reader", Token = 0x02000003,
                Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, BaseType = Corlib("Object") };
            TypeRef returned = variant switch { "reference" => new ByRefRef(Corlib("Int32")), "pointer" => new PointerRef(Corlib("Int32")),
                "ref-struct" => new DefinitionRef(item, []), _ => Corlib("Void") };
            MethodDef Method(int index, string name, TypeRef result) => new() { Index = index, Owner = owner, Name = name,
                Token = (uint)(0x06000001 + index), Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = result };
            var value = Method(0, "Value", returned); var probe = Method(1, "Probe", Corlib("Void")); owner.Methods = [value, probe];
            var fixture = new AssemblyDef { Name = item.Assembly, AssemblyName = assemblyName, Version = new(1, 0, 0, 0), Culture = "", PublicKey = [], Types = [module, item, owner] };
            var corlib = new AssemblyDef { Name = "mscorlib.dll", AssemblyName = "mscorlib", Version = new(4, 0, 0, 0), Culture = "", PublicKey = [], Types = core.ToArray() };
            var model = new ProgramModel { Image = ImageDocument.Parse(bytes), MetadataVersion = 31, Assemblies = [corlib, fixture], Types = [.. core, module, item, owner],
                Methods = [value, probe, attribute], Fields = item.Fields, RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var types = new ManagedTypes(model, new FieldLayouts(model)); var skeleton = new Skeleton(model); var emitter = new BodyEmitter(skeleton, types);
            var body = new ManagedBody(MethodRef.Open(value), [new(0x1000, [variant == "throw"
                ? new ManagedThrow(0x1000, new HoleValue("unknown exception", types.Object, 64))
                : new ManagedReturn(0x1000, new HoleValue("unknown value", returned, types.ValueWidth(returned)))])]);
            foreach (var policy in new[] { EmissionPolicy.Checked, EmissionPolicy.Recovered, EmissionPolicy.Source })
                if (emitter.Check([body], policy).Count != 1) throw new InvalidOperationException("缺口不能计为完整写出");
            if (emitter.Emit([body], EmissionPolicy.Partial).Count != 0) throw new InvalidOperationException("封闭受限返回类型的部分体应使用显式抛出标记");
            var probeBody = new ManagedBody(MethodRef.Open(probe), [new(0x2000, [new ManagedCall(0x2000,
                new ManagedInvocation(MethodRef.Open(value), null, [], false), null), new ManagedReturn(0x2001, null)])]);
            if (emitter.Emit([probeBody]).Count != 0) throw new InvalidOperationException("占位探针调用必须通过 CIL 检查");
            var directory = Path.Combine(Path.GetTempPath(), "Cpp2CS-partial-hole-" + Guid.NewGuid().ToString("N"));
            var assemblies = Path.Combine(directory, "assemblies"); skeleton.Write(assemblies);
            void Execute(Assembly loaded)
            {
                try { loaded.GetType("Fixture.Reader", true)!.GetMethod("Probe")!.Invoke(null, null); }
                catch (TargetInvocationException exception) when (exception.InnerException is NullReferenceException) { return; }
                throw new InvalidOperationException("部分体缺口必须抛出，不能提供虚假值");
            }
            Execute(Assembly.Load(File.ReadAllBytes(Path.Combine(assemblies, item.Assembly))));
            SourceProject.Write(Path.Combine(assemblies, item.Assembly), assemblies, Path.Combine(directory, "src"), _ => true);
            if (SourceCompilation.Check(directory, assemblyName) is { } compiled) Execute(Assembly.Load(File.ReadAllBytes(compiled)));
        }
        Console.WriteLine("部分体标记 CIL／源码编译／CLR 检查通过：ref、指针、ref struct 和未知异常均保持显式失败，完整写出策略拒绝缺口");
    }
}

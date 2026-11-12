using System.Buffers.Binary;
using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Model;
using Cpp2CS.Output;
using Cpp2CS.Recovery;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class GenericScopeTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        foreach (var onMethod in new[] { false, true })
        {
            const ulong address = 0x180001000;
            var bytes = original.ToArray();
            Convert.FromHexString("488BC1C3").CopyTo(bytes, 0x200);
            bytes[0x220] = 0xc3;
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x124), 0);
            var names = new[] { "Void", "Boolean", "Char", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64", "Single", "Double",
                "String", "TypedReference", "IntPtr", "UIntPtr", "Object", "ValueType", "RuntimeTypeHandle", "RuntimeFieldHandle", "RuntimeMethodHandle", "NullReferenceException" };
            var core = names.Select((name, i) => new TypeDef { Index = i, Assembly = "mscorlib.dll", Namespace = "System", Name = name,
                Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public, IsValueType = name is not ("String" or "Object" or "ValueType" or "NullReferenceException"),
                IsEnum = false, Size = name == "Int32" ? 4 : 8 }).ToArray();
            TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
            var exception = core.Single(t => t.Name == "NullReferenceException");
            var exceptionCtor = new MethodDef { Index = 3, Owner = exception, Name = ".ctor", Token = 0x06000001,
                Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void") };
            exception.Methods = [exceptionCtor];
            var assemblyName = "GenericScope" + (onMethod ? "Method" : "Type");
            var module = new TypeDef { Index = core.Length, Assembly = assemblyName + ".dll", Namespace = "", Name = "<Module>", Token = 0x02000001,
                Attributes = TypeAttributes.NotPublic, IsValueType = false, IsEnum = false, Size = 0 };
            var parameter = new GenericParameterDef { Name = "T", Position = 0, Attributes = GenericParameterAttributes.ReferenceTypeConstraint };
            var generic = new GenericParameterRef("T", onMethod, 0) { Parameter = parameter };
            var owner = new TypeDef { Index = core.Length + 1, Assembly = module.Assembly, Namespace = "Fixture", Name = onMethod ? "Identity" : "Identity`1", Token = 0x02000002,
                Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16, BaseType = Corlib("Object"), GenericParameters = onMethod ? [] : [parameter] };
            var definition = new MethodDef { Index = 0, Owner = owner, Name = "Copy", Token = 0x06000001, Address = 0,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = generic,
                GenericParameters = onMethod ? [parameter] : [], Parameters = [new("value", generic, 0, null, false)] };
            var padding = new MethodDef { Index = 1, Owner = owner, Name = "Boundary", Token = 0x06000002, Address = address + 0x20,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void") };
            var missing = new MethodDef { Index = 2, Owner = owner, Name = "Missing", Token = 0x06000003, Address = 0,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void") };
            owner.Methods = [definition, padding, missing];
            MethodRef Instance(string name) => new(definition, onMethod ? [] : [Corlib(name)], onMethod ? [Corlib(name)] : []);
            var registered = new[] { new CodeEntry(address, EntryKind.GenericMethod, Instance("String"), 0, null),
                new CodeEntry(address, EntryKind.GenericMethod, Instance("Object"), 0, null),
                new CodeEntry(address + 0x10, EntryKind.AdjustorThunk, MethodRef.Open(missing), 0, null) };
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = registered,
                ByAddress = registered.GroupBy(e => e.Address).ToDictionary(g => g.Key, g => g.ToArray()), Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
                MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var coreAssembly = new AssemblyDef { Name = "mscorlib.dll", AssemblyName = "mscorlib", Version = new(4, 0, 0, 0), Culture = "", PublicKey = [], Types = core };
            var fixture = new AssemblyDef { Name = module.Assembly, AssemblyName = assemblyName, Version = new(1, 0, 0, 0), Culture = "", PublicKey = [], Types = [module, owner] };
            var image = ImageDocument.Parse(bytes);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [coreAssembly, fixture], Types = [.. core, module, owner],
                Methods = [definition, padding, missing, exceptionCtor], Fields = [], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var layouts = new FieldLayouts(model); var types = new ManagedTypes(model, layouts);
            var entries = new MethodEntries(model, registrations, types);
            var selected = entries.Definitions.Where(e => e.Instance.Method.Owner.Assembly == module.Assembly).ToArray();
            Check(selected.Count(e => e.Instance.Method == definition) == 1 && entries.ForDefinition(missing) is null,
                "同地址实例只选择一个方法定义，调整桩不能冒充方法本体");
            var code = CodeMap.BuildPe(image, model.Methods.Select(m => m.Address).Concat(registered
                .Where(e => e.Kind is EntryKind.Method or EntryKind.GenericMethod).Select(e => e.Address)));
            var scan = CodeScan.Unscanned(code);
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = scan, Registrations = registrations, Layouts = layouts,
                Helpers = RuntimeHelpers.Unclassified(code, scan), Usages = UsageSlots.Build(model, code, scan), Checks = new(), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var native = entries.ForDefinition(definition)!;
            var result = new RecoveryTarget(native.Instance, native.Address).Recover(new MethodDecompiler(facts, types));
            Check(result.Body is not null && result.Method.Method == definition, "注册实例须复用现有开放泛型恢复：" + string.Join(';', result.Holes.Select(h => h.Reason)));
            var skeleton = new Skeleton(model);
            Check(new BodyEmitter(skeleton, types).Emit([result.Body!]).Count == 0, "开放泛型须通过 CIL 写出检查");
            var method = skeleton.Method(definition);
            Check(method.Parameters[0].ParameterType is Mono.Cecil.GenericParameter && method.ReturnType is Mono.Cecil.GenericParameter,
                "原生见证不能把开放签名改写成选定的实参类型");
            using var stream = new MemoryStream(); skeleton.Assembly(module.Assembly).Write(stream);
            var loaded = Assembly.Load(stream.ToArray());
            foreach (var type in new[] { typeof(string), typeof(object) })
            {
                var clrOwner = loaded.GetType("Fixture." + owner.Name, true)!;
                if (!onMethod) clrOwner = clrOwner.MakeGenericType(type);
                var copy = clrOwner.GetMethod("Copy")!; if (onMethod) copy = copy.MakeGenericMethod(type);
                foreach (var value in new object?[] { null, "identity", onMethod ? "method" : "class" })
                    Check(ReferenceEquals(copy.Invoke(null, [value]), value), "两个登记的引用共享实例须保持对象身份与空引用");
            }
        }
        Console.WriteLine("泛型注册范围/开放 CIL/CLR 对照通过：类与方法泛型、重复实例、调整桩拒绝，12 组引用与空值输入");
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

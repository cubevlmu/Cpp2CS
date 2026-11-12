using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Managed;
using Cpp2CS.Model;
using Cpp2CS.Output;
using Mono.Cecil.Cil;

namespace Cpp2CS.X64.Tests;

internal static class StructGetterEmissionTests
{
    internal static void Run(byte[] imageBytes)
    {
        foreach (var reference in new[] { false, true })
        foreach (var local in new[] { false, true })
        {
            var names = new[] { "Void", "Boolean", "Char", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64", "Single", "Double",
                "String", "TypedReference", "IntPtr", "UIntPtr", "Object", "ValueType", "RuntimeTypeHandle", "RuntimeFieldHandle", "RuntimeMethodHandle" };
            var core = names.Select((name, i) => new TypeDef { Index = i, Assembly = "mscorlib.dll", Namespace = "System", Name = name,
                Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public, IsValueType = name is not ("String" or "Object" or "ValueType"),
                IsEnum = false, Size = name == "Int32" ? 4 : 8 }).ToArray();
            TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
            var assemblyName = "AccessorFixture" + (reference ? "Ref" : "Value") + (local ? "Local" : "Argument");
            var module = new TypeDef { Index = core.Length, Assembly = assemblyName + ".dll", Namespace = "", Name = "<Module>", Token = 0x02000001,
                Attributes = TypeAttributes.NotPublic, IsValueType = false, IsEnum = false, Size = 0 };
            var structure = new TypeDef { Index = core.Length + 1, Assembly = assemblyName + ".dll", Namespace = "Fixture", Name = "Item", Token = 0x02000020,
                Attributes = TypeAttributes.Public | TypeAttributes.SequentialLayout | TypeAttributes.Sealed, IsValueType = true, IsEnum = false,
                Size = 4, BaseType = Corlib("ValueType") };
            var owner = new TypeDef { Index = core.Length + 2, Assembly = structure.Assembly, Namespace = "Fixture", Name = "Reader", Token = 0x02000021,
                Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16, BaseType = Corlib("Object") };
            var type = new DefinitionRef(structure, []);
            var field = new FieldDef { Index = 0, Owner = structure, Name = "value", Type = Corlib("Int32"), Attributes = FieldAttributes.Private, Offset = 0 };
            structure.Fields = [field];
            var getter = MethodRef.Open(new MethodDef { Index = 0, Owner = structure, Name = "Read", Token = 0x06000001, Attributes = MethodAttributes.Public,
                ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Int32") });
            var parameterType = reference ? (TypeRef)new ByRefRef(type) : type;
            var caller = MethodRef.Open(new MethodDef { Index = 1, Owner = owner, Name = "Read", Token = 0x06000002,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Int32"),
                Parameters = [new("item", parameterType, 0, null, false)] });
            structure.Methods = [getter.Method]; owner.Methods = [caller.Method];
            var coreAssembly = new AssemblyDef { Name = "mscorlib.dll", AssemblyName = "mscorlib", Version = new(4, 0, 0, 0), Culture = "", PublicKey = [], Types = core };
            var fixture = new AssemblyDef { Name = structure.Assembly, AssemblyName = assemblyName, Version = new(1, 0, 0, 0), Culture = "", PublicKey = [], Types = [module, structure, owner] };
            var model = new ProgramModel { Image = ImageDocument.Parse(imageBytes), MetadataVersion = 31, Assemblies = [coreAssembly, fixture], Types = [.. core, module, structure, owner],
                Methods = [getter.Method, caller.Method], Fields = [field], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [],
                Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var types = new ManagedTypes(model, new FieldLayouts(model)); var skeleton = new Skeleton(model);
            var nativeGetter = skeleton.Method(getter.Method).Body.GetILProcessor(); nativeGetter.Body.Instructions.Clear();
            nativeGetter.Emit(OpCodes.Ldarg_0); nativeGetter.Emit(OpCodes.Ldfld, skeleton.Field(field)); nativeGetter.Emit(OpCodes.Ret);
            var argument = new ArgumentValue(0, parameterType, reference ? 64 : 0);
            var receiver = local ? (ManagedValue)new LocalValue(new Variable(Storage.Temp(1000), 1), parameterType, argument.Width) : argument;
            var value = new FieldValue(receiver, new(field, type), Corlib("Int32"), 32) { Accessor = new(getter, new(field, type), Corlib("Int32"), 32, false) };
            var statements = new List<ManagedStatement>();
            if (local) statements.Add(new ManagedAssignment(0x1000, (LocalValue)receiver, argument));
            statements.Add(new ManagedReturn(0x1001, value));
            var body = new ManagedBody(caller, [new(0x1000, statements)]);
            var emitter = new BodyEmitter(skeleton, types);
            Check(emitter.Emit([body]).Count == 0, "结构体访问器须通过写出检查");
            var instructions = skeleton.Method(caller.Method).Body.Instructions;
            var at = instructions.ToList().FindIndex(i => i.OpCode == OpCodes.Call);
            var receiverCode = instructions[at - 1].OpCode;
            Check(receiverCode == (reference ? local ? OpCodes.Ldloc : OpCodes.Ldarg : local ? OpCodes.Ldloca : OpCodes.Ldarga),
                "ref 接收者复用原地址，值接收者只取一次地址");
            using var stream = new MemoryStream(); skeleton.Assembly(structure.Assembly).Write(stream);
            var loaded = Assembly.Load(stream.ToArray());
            var itemType = loaded.GetType("Fixture.Item", true)!;
            var read = loaded.GetType("Fixture.Reader", true)!.GetMethod("Read")!;
            var instance = Activator.CreateInstance(itemType)!;
            var storage = itemType.GetField("value", BindingFlags.Instance | BindingFlags.NonPublic)!;
            foreach (var number in new[] { int.MinValue, -1, 0, 1, 0x12345678, int.MaxValue })
            {
                storage.SetValue(instance, number);
                Check((int)read.Invoke(null, [instance])! == number, "实际 CLR 执行必须读取结构体字段，而不是托管引用槽");
            }
        }
        Console.WriteLine("结构体访问器 CIL/CLR 对照通过：值/ref 参数与局部，24 组输入");
    }

    private static void Check(bool condition, string reason) { if (!condition) throw new InvalidOperationException(reason); }
}

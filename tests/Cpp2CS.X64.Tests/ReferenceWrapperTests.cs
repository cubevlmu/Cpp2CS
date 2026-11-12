using System.Buffers.Binary;
using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Model;
using Cpp2CS.Output;
using Cpp2CS.Recovery;
using Cpp2CS.X64;
using Mono.Cecil.Cil;

namespace Cpp2CS.X64.Tests;

internal static class ReferenceWrapperTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        foreach (var variant in new[] { "public", "nested", "field", "field-nested", "private", "readonly", "offset" })
        {
            const ulong basis = 0x180000000;
            var bytes = original.ToArray(); BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x124), 0);
            // 返回的托管地址不变，随后经同址内层结构体写入高字段。
            Convert.FromHexString("534883EC20488BDAE873000000488BC8488BD34533C0E8A50000004883C4205BC3").CopyTo(bytes, 0x200);
            var fromField = variant.StartsWith("field", StringComparison.Ordinal);
            var nested = variant.EndsWith("nested", StringComparison.Ordinal);
            if (fromField) Convert.FromHexString("534883EC20488BDA488D4910488BD34533C0E8A90000004883C4205BC3").CopyTo(bytes, 0x200);
            Convert.FromHexString("488BC1C3").CopyTo(bytes, 0x280);
            Convert.FromHexString("48895108C3").CopyTo(bytes, 0x2c0);
            var names = new[] { "Void", "Boolean", "Char", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64", "Single", "Double",
                "String", "TypedReference", "IntPtr", "UIntPtr", "Object", "ValueType", "RuntimeTypeHandle", "RuntimeFieldHandle", "RuntimeMethodHandle", "NullReferenceException" };
            var core = names.Select((name, i) => new TypeDef { Index = i, Assembly = "mscorlib.dll", Namespace = "System", Name = name,
                Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public, IsValueType = name is not ("String" or "Object" or "ValueType" or "NullReferenceException"),
                IsEnum = false, Size = name == "Int32" ? 4 : 8 }).ToArray();
            TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
            var assemblyName = "ReferenceWrapper" + variant;
            TypeDef Define(int i, string name, bool value) => new() { Index = core.Length + i, Assembly = assemblyName + ".dll", Namespace = i == 0 ? "" : "Fixture", Name = name,
                Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public | (value ? TypeAttributes.SequentialLayout | TypeAttributes.Sealed : 0),
                IsValueType = value, IsEnum = false, Size = i == 5 ? 32 : variant == "offset" && i == 2 ? 24 : 16, BaseType = Corlib(value ? "ValueType" : "Object") };
            var module = Define(0, "<Module>", false); var leaf = Define(1, "Leaf", true); var wrapper = Define(2, "Wrapper", true);
            var outer = Define(3, "Outer", true); var owner = Define(4, "Writer", false); var holder = Define(5, "Holder", false);
            var leafType = new DefinitionRef(leaf, []); var wrapperType = new DefinitionRef(wrapper, []); var outerType = new DefinitionRef(outer, []);
            FieldDef Field(int i, TypeDef type, string name, TypeRef fieldType, int offset, FieldAttributes access = FieldAttributes.Public) => new() {
                Index = i, Owner = type, Name = name, Type = fieldType, Offset = offset, Attributes = access };
            leaf.Fields = [Field(0, leaf, "Low", Corlib("UInt64"), 0), Field(1, leaf, "High", Corlib("UInt64"), 8)];
            wrapper.Fields = [Field(2, wrapper, "Item", leafType, variant == "offset" ? 8 : 0,
                variant == "private" ? FieldAttributes.Private : FieldAttributes.Public | (variant == "readonly" ? FieldAttributes.InitOnly : 0))];
            outer.Fields = [Field(3, outer, "Item", wrapperType, 0)];
            TypeRef container = nested ? outerType : wrapperType;
            holder.Fields = [Field(4, holder, "Item", container, 16)];
            var reference = new ByRefRef(container);
            var run = new MethodDef { Index = 0, Owner = owner, Name = "Run", Token = 0x06000001, Address = basis + 0x1000,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void"),
                Parameters = [new("item", fromField ? new DefinitionRef(holder, []) : reference, 0, null, false), new("value", Corlib("UInt64"), 0, null, false)] };
            var identity = new MethodDef { Index = 1, Owner = owner, Name = "Identity", Token = 0x06000002, Address = basis + 0x1080,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = reference,
                Parameters = [new("item", reference, 0, null, false)] };
            var setter = new MethodDef { Index = 2, Owner = leaf, Name = "Write", Token = 0x06000003, Address = basis + 0x10c0,
                Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void"),
                Parameters = [new("value", Corlib("UInt64"), 0, null, false)] };
            var exception = core.Single(t => t.Name == "NullReferenceException");
            var exceptionCtor = new MethodDef { Index = 3, Owner = exception, Name = ".ctor", Token = 0x06000001,
                Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void") };
            owner.Methods = [run, identity]; leaf.Methods = [setter]; exception.Methods = [exceptionCtor];
            TypeDef[] fixtureTypes = [module, leaf, wrapper, outer, owner, holder];
            var coreAssembly = new AssemblyDef { Name = "mscorlib.dll", AssemblyName = "mscorlib", Version = new(4, 0, 0, 0), Culture = "", PublicKey = [], Types = core };
            var fixture = new AssemblyDef { Name = module.Assembly, AssemblyName = assemblyName, Version = new(1, 0, 0, 0), Culture = "", PublicKey = [], Types = fixtureTypes };
            var image = ImageDocument.Parse(bytes);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [coreAssembly, fixture], Types = [.. core, .. fixtureTypes],
                Methods = [run, identity, setter, exceptionCtor], Fields = [.. leaf.Fields, .. wrapper.Fields, .. outer.Fields, .. holder.Fields], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [],
                Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var registered = model.Methods.Where(m => m.Address != 0).Select(m => new CodeEntry(m.Address, EntryKind.Method, MethodRef.Open(m), 0, null)).ToArray();
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = registered,
                ByAddress = registered.GroupBy(e => e.Address).ToDictionary(g => g.Key, g => g.ToArray()), Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
                MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var code = CodeMap.BuildPe(image, registered.Select(e => e.Address)); var scan = CodeScan.Unscanned(code);
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = scan, Registrations = registrations, Layouts = new FieldLayouts(model),
                Helpers = RuntimeHelpers.Unclassified(code, scan), Usages = UsageSlots.Build(model, code, scan), Checks = new(), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var types = new ManagedTypes(model, facts.Layouts); var result = new MethodDecompiler(facts, types).Recover(MethodRef.Open(run), run.Address);
            Check(result.Body is not null, "返回的结构体地址须完成恢复：" + variant + ": " + string.Join(';', result.Holes.Select(h => h.Reason)));
            var skeleton = new Skeleton(model);
            var identityIl = skeleton.Method(identity).Body.GetILProcessor(); identityIl.Body.Instructions.Clear(); identityIl.Emit(OpCodes.Ldarg_0); identityIl.Emit(OpCodes.Ret);
            var setterIl = skeleton.Method(setter).Body.GetILProcessor(); setterIl.Body.Instructions.Clear();
            setterIl.Emit(OpCodes.Ldarg_0); setterIl.Emit(OpCodes.Ldarg_1); setterIl.Emit(OpCodes.Stfld, skeleton.Field(leaf.Fields[1])); setterIl.Emit(OpCodes.Ret);
            Check(new BodyEmitter(skeleton, types).Emit([result.Body!]).Count == 0, "地址字段投影须通过 CIL 写出检查");
            var addresses = skeleton.Method(run).Body.Instructions.Count(i => i.OpCode == OpCodes.Ldflda);
            var accepted = variant is "public" or "nested" or "field" or "field-nested";
            Check(accepted ? addresses == (nested ? 2 : 1) + (fromField ? 1 : 0) : addresses == 0, "只按同址、完整表示链及可写直接字段建立 ref 投影：" + variant);
            if (!accepted) continue;
            using var stream = new MemoryStream(); skeleton.Assembly(module.Assembly).Write(stream);
            var loaded = Assembly.Load(stream.ToArray()); var execute = loaded.GetType("Fixture.Writer", true)!.GetMethod("Run")!;
            var clrLeaf = loaded.GetType("Fixture.Leaf", true)!; var clrWrapper = loaded.GetType("Fixture.Wrapper", true)!;
            var clrOuter = loaded.GetType("Fixture.Outer", true)!;
            var clrHolder = loaded.GetType("Fixture.Holder", true)!;
            foreach (var low in new ulong[] { 0, 1, 0xdeadbeef12345678, ulong.MaxValue })
            foreach (var high in new ulong[] { 0, 1, 0x8000000000000000, ulong.MaxValue })
            {
                var item = Activator.CreateInstance(clrLeaf)!; clrLeaf.GetField("Low")!.SetValue(item, low); clrLeaf.GetField("High")!.SetValue(item, ~high);
                var wrapped = Activator.CreateInstance(clrWrapper)!; clrWrapper.GetField("Item")!.SetValue(wrapped, item);
                var input = wrapped;
                if (nested) { input = Activator.CreateInstance(clrOuter)!; clrOuter.GetField("Item")!.SetValue(input, wrapped); }
                if (fromField) { var instance = System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(clrHolder); clrHolder.GetField("Item")!.SetValue(instance, input); input = instance; }
                object?[] arguments = [input, high]; execute.Invoke(null, arguments);
                var storage = fromField ? clrHolder.GetField("Item")!.GetValue(arguments[0])! : arguments[0]!;
                var updated = nested ? clrOuter.GetField("Item")!.GetValue(storage)! : storage;
                var actual = clrWrapper.GetField("Item")!.GetValue(updated)!;
                Check((ulong)clrLeaf.GetField("Low")!.GetValue(actual)! == low && (ulong)clrLeaf.GetField("High")!.GetValue(actual)! == high,
                    "ref 字段视图必须修改原位置且保留相邻字段，不能修改副本");
            }
        }
        Console.WriteLine("同址结构体 ref 字段完整恢复/CIL/CLR 对照通过：64 组原位置写入，返回引用/对象字段、单层/嵌套包装；私有、只读及非零偏移拒绝投影");
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

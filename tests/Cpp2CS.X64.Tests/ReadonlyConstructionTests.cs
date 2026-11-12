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

internal static class ReadonlyConstructionTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        foreach (var variant in new[] { "public", "private", "registered", "compact", "inaccessible", "integer-guard", "reference", "extra-effect", "mismatched-flag", "static-init" })
        {
            const ulong basis = 0x180000000;
            var bytes = original.ToArray();
            var runBytes = Convert.FromHexString("8BC148C1E220480BC2C3");
            // RCX 为 this，EDX 为首字段，R8 为按值传入的八字节包装值。
            var ctorBytes = Convert.FromHexString("89114584C0740949C1E82044894104C3C7410407000000C3");
            var wrapperBytes = Convert.FromHexString(variant == "mismatched-flag" ? "C60100895104C3" : "C60101895104C3");
            if (variant == "compact") wrapperBytes = Convert.FromHexString("885101C60101C3");
            // 另一分支上的调用也必须接受效果检查，不能把整个构造体当成纯赋值。
            if (variant == "extra-effect") ctorBytes = [.. ctorBytes[..^1], .. Convert.FromHexString("E844000000C3")];
            runBytes.CopyTo(bytes, 0x200); ctorBytes.CopyTo(bytes, 0x280); wrapperBytes.CopyTo(bytes, 0x2c0);
            Convert.FromHexString("0F31C3").CopyTo(bytes, 0x2e0);
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            var ranges = new[] { (0x1000, runBytes.Length, 0x3140), (0x1080, ctorBytes.Length, 0x3150),
                (0x10c0, wrapperBytes.Length, 0x3160), (0x10e0, 3, 0x3170) }.Where(r => variant != "registered" || r.Item1 != 0x10c0).ToArray();
            U32(0x124, (uint)ranges.Length * 12);
            for (var i = 0; i < ranges.Length; i++)
            {
                var (rva, length, unwind) = ranges[i]; var table = 0x700 + i * 12;
                U32(table, (uint)rva); U32(table + 4, (uint)(rva + length)); U32(table + 8, (uint)unwind);
                bytes[unwind - 0x2a00] = 1;
            }
            var names = new[] { "Void", "Boolean", "Char", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64", "Single", "Double",
                "String", "TypedReference", "IntPtr", "UIntPtr", "Object", "ValueType", "RuntimeTypeHandle", "RuntimeFieldHandle", "RuntimeMethodHandle", "NullReferenceException" };
            var core = names.Select((name, i) => new TypeDef { Index = i, Assembly = "mscorlib.dll", Namespace = "System", Name = name,
                Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public, IsValueType = name is not ("String" or "Object" or "ValueType" or "NullReferenceException"),
                IsEnum = false, Size = name == "Boolean" ? 1 : name == "Int32" ? 4 : 8 }).ToArray();
            TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
            var exception = core.Single(t => t.Name == "NullReferenceException");
            var exceptionCtor = new MethodDef { Index = 4, Owner = exception, Name = ".ctor", Token = 0x06000001,
                Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void") };
            exception.Methods = [exceptionCtor];
            var assemblyName = "ReadonlyConstruction" + variant;
            TypeDef Define(int i, string name, bool value) => new() { Index = core.Length + i, Assembly = assemblyName + ".dll", Namespace = i == 0 ? "" : "Fixture", Name = name,
                Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public | (value ? TypeAttributes.SequentialLayout | TypeAttributes.Sealed : 0),
                IsValueType = value, IsEnum = false, Size = variant == "compact" && i == 2 ? 2 : 8, BaseType = Corlib(value ? "ValueType" : "Object") };
            var module = Define(0, "<Module>", false);
            var pair = Define(1, "Pair", true); var wrapper = Define(2, "Payload", true); var owner = Define(3, "Factory", false);
            var pairType = new DefinitionRef(pair, []); var wrapperType = new DefinitionRef(wrapper, []);
            var fieldAccess = variant == "private" ? FieldAttributes.Private : FieldAttributes.Public;
            FieldDef Field(int index, TypeDef declaring, string name, TypeRef type, int offset, FieldAttributes attributes) => new()
                { Index = index, Owner = declaring, Name = name, Type = type, Offset = offset, Attributes = attributes };
            pair.Fields = [Field(0, pair, "first", Corlib("Int32"), 0, fieldAccess | FieldAttributes.InitOnly),
                Field(1, pair, "second", Corlib("Int32"), 4, fieldAccess | FieldAttributes.InitOnly)];
            wrapper.Fields = [Field(2, wrapper, "present", Corlib(variant == "integer-guard" ? "Byte" : "Boolean"), 0, FieldAttributes.Public | FieldAttributes.InitOnly),
                Field(3, wrapper, "payload", Corlib(variant == "compact" ? "Boolean" : "Int32"), variant == "compact" ? 1 : 4, FieldAttributes.Public | FieldAttributes.InitOnly)];
            var factory = new MethodDef { Index = 0, Owner = owner, Name = "Create", Token = 0x06000001, Address = basis + 0x1000,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = pairType,
                Parameters = [new("first", Corlib("Int32"), 0, null, false), new("second", Corlib("Int32"), 0, null, false)] };
            var ctor = new MethodDef { Index = 1, Owner = pair, Name = ".ctor", Token = 0x06000002, Address = basis + 0x1080,
                Attributes = (variant == "inaccessible" ? MethodAttributes.Private : MethodAttributes.Public) | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
                ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void"),
                Parameters = [new("first", Corlib("Int32"), 0, null, false), new("value", variant == "reference" ? new ByRefRef(wrapperType) : wrapperType, 0, null, false)] };
            var payloadCtor = new MethodDef { Index = 2, Owner = wrapper, Name = ".ctor", Token = 0x06000003, Address = variant == "registered" ? 0 : basis + 0x10c0,
                Attributes = MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void"),
                Parameters = [new("value", Corlib(variant == "compact" ? "Boolean" : "Int32"), 0, null, false)] };
            var effect = new MethodDef { Index = 3, Owner = owner, Name = "Effect", Token = 0x06000004, Address = basis + 0x10e0,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void") };
            var initializer = new MethodDef { Index = 5, Owner = pair, Name = ".cctor", Token = 0x06000005,
                Attributes = MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
                ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void") };
            owner.Methods = [factory, effect]; pair.Methods = [ctor]; wrapper.Methods = [payloadCtor];
            if (variant == "static-init") pair.Methods = [ctor, initializer];
            var image = ImageDocument.Parse(bytes);
            var coreAssembly = new AssemblyDef { Name = "mscorlib.dll", AssemblyName = "mscorlib", Version = new(4, 0, 0, 0), Culture = "", PublicKey = [], Types = core };
            var fixture = new AssemblyDef { Name = pair.Assembly, AssemblyName = assemblyName, Version = new(1, 0, 0, 0), Culture = "", PublicKey = [], Types = [module, pair, wrapper, owner] };
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [coreAssembly, fixture], Types = [.. core, module, pair, wrapper, owner],
                Methods = variant == "static-init" ? [factory, ctor, payloadCtor, effect, exceptionCtor, initializer] : [factory, ctor, payloadCtor, effect, exceptionCtor],
                Fields = [.. pair.Fields, .. wrapper.Fields], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [],
                Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var entries = model.Methods.Where(m => m.Address != 0).Select(m => new CodeEntry(m.Address, EntryKind.Method, MethodRef.Open(m), 0, null))
                .Concat(variant == "registered" ? [new CodeEntry(basis + 0x10c0, EntryKind.Method, MethodRef.Open(payloadCtor), 0, null)] : []).ToArray();
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries,
                ByAddress = entries.ToDictionary(e => e.Address, e => new[] { e }), Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
                MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var code = CodeMap.BuildPe(image, model.Methods.Select(m => m.Address).Concat(entries
                .Where(e => e.Kind is EntryKind.Method or EntryKind.GenericMethod).Select(e => e.Address)));
            var scan = CodeScan.Unscanned(code);
            if (variant == "registered") Check(code.At(basis + 0x10c0)?.Evidence == BoundaryEvidence.SymbolCandidate,
                "无元数据定义地址和展开表的注册入口须参与建图，终点仍须控制流验证");
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = scan, Registrations = registrations, Layouts = new FieldLayouts(model),
                Helpers = RuntimeHelpers.Unclassified(code, scan), Usages = UsageSlots.Build(model, code, scan), Checks = new(), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var types = new ManagedTypes(model, facts.Layouts); var recovery = new MethodDecompiler(facts, types);
            if (variant == "compact")
            {
                var compact = recovery.Recover(MethodRef.Open(payloadCtor), payloadCtor.Address);
                Check(compact.Body is not null, "合并的 this 初始化不得递归依赖正在证明的构造函数：" + string.Join(';', compact.Holes.Select(h => h.Reason)));
                var compactSkeleton = new Skeleton(model);
                Check(new BodyEmitter(compactSkeleton, types).Emit([compact.Body!]).Count == 0, "紧凑只读字段初始化须通过 CIL 检查");
                using var compactStream = new MemoryStream(); compactSkeleton.Assembly(pair.Assembly).Write(compactStream);
                var compactType = Assembly.Load(compactStream.ToArray()).GetType("Fixture.Payload", true)!;
                foreach (var flag in new[] { false, true })
                {
                    var value = Activator.CreateInstance(compactType, [flag])!;
                    Check((bool)compactType.GetField("present")!.GetValue(value)! && (bool)compactType.GetField("payload")!.GetValue(value)! == flag,
                        "紧凑 this 初始化须保持两个独立布尔字段");
                }
                continue;
            }
            var result = recovery.Recover(MethodRef.Open(factory), factory.Address);
            if (variant is not ("public" or "private" or "registered"))
            {
                Check(result.Body is null && result.Holes.Count > 0, "无法证明的只读字段构造须拒绝：" + variant);
                continue;
            }
            Check(result.Body is not null, "按值条件构造须完成恢复：" + variant + ": " + string.Join(';', result.Holes.Select(h => h.Reason)));
            var skeleton = new Skeleton(model);
            // 被调用构造函数的 CIL 独立编写，避免用恢复器自身作为执行对照。
            var payloadIl = skeleton.Method(payloadCtor).Body.GetILProcessor(); payloadIl.Body.Instructions.Clear();
            payloadIl.Emit(OpCodes.Ldarg_0); payloadIl.Emit(OpCodes.Ldc_I4_1); payloadIl.Emit(OpCodes.Stfld, skeleton.Field(wrapper.Fields[0]));
            payloadIl.Emit(OpCodes.Ldarg_0); payloadIl.Emit(OpCodes.Ldarg_1); payloadIl.Emit(OpCodes.Stfld, skeleton.Field(wrapper.Fields[1])); payloadIl.Emit(OpCodes.Ret);
            var il = skeleton.Method(ctor).Body.GetILProcessor(); il.Body.Instructions.Clear();
            il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ldarg_1); il.Emit(OpCodes.Stfld, skeleton.Field(pair.Fields[0]));
            il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ldarga, il.Body.Method.Parameters[1]); il.Emit(OpCodes.Ldfld, skeleton.Field(wrapper.Fields[0]));
            var absent = Instruction.Create(OpCodes.Ldc_I4_7); var store = Instruction.Create(OpCodes.Stfld, skeleton.Field(pair.Fields[1]));
            il.Emit(OpCodes.Brfalse, absent); il.Emit(OpCodes.Ldarga, il.Body.Method.Parameters[1]); il.Emit(OpCodes.Ldfld, skeleton.Field(wrapper.Fields[1]));
            il.Emit(OpCodes.Br, store); il.Append(absent); il.Append(store); il.Emit(OpCodes.Ret);
            Check(new BodyEmitter(skeleton, types).Emit([result.Body!]).Count == 0, "只读构造须通过 CIL 写出检查");
            var emitted = skeleton.Method(factory).Body.Instructions;
            Check(emitted.Count(i => i.OpCode == OpCodes.Newobj) == 2 && emitted.All(i => i.OpCode != OpCodes.Stfld), "须调用两个已证明的构造，不越权逐字段写入");
            using var stream = new MemoryStream(); skeleton.Assembly(pair.Assembly).Write(stream);
            var loaded = Assembly.Load(stream.ToArray()); var create = loaded.GetType("Fixture.Factory", true)!.GetMethod("Create")!;
            var pairClr = loaded.GetType("Fixture.Pair", true)!;
            foreach (var first in new[] { int.MinValue, -1, 0, 1, 7, int.MaxValue })
            foreach (var second in new[] { int.MinValue, -1, 0, 1, 7, int.MaxValue })
            {
                var actual = create.Invoke(null, [first, second])!;
                const BindingFlags access = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance;
                Check((int)pairClr.GetField("first", access)!.GetValue(actual)! == first && (int)pairClr.GetField("second", access)!.GetValue(actual)! == second,
                    "条件构造与原生寄存器打包的两个字段必须一致");
            }
        }
        Console.WriteLine("只读结构体条件构造完整恢复/CIL/CLR 对照通过：110 组输入，含紧凑 this 初始化及无展开表注册入口；权限、非布尔条件、ref、额外调用、静态初始化及构造约束变异拒绝");
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

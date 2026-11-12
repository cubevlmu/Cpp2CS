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

internal static class CallWrapperTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        foreach (var variant in new[] { "static", "instance", "nullable-instance", "static-init", "virtual-override", "inaccessible", "extra-call", "constant-argument", "different-callee" })
        {
            const ulong basis = 0x180000000;
            var bytes = original.ToArray(); var instance = variant is "instance" or "nullable-instance" or "static-init" or "virtual-override";
            var runBytes = Convert.FromHexString(instance ? "03D24883EC28E8750000004883C42883C005C3" : "03C94883EC28E8750000004883C42883C005C3");
            if (variant is "instance" or "static-init" or "virtual-override") runBytes = Convert.FromHexString("4885C9741303D24883EC28E8700000004883C42883C005C3B89CFFFFFFC3");
            var helperBytes = Convert.FromHexString(instance ? "8D4207C3" : "8D4107C3");
            var wrapperBytes = Convert.FromHexString(instance ? "03D24883EC28E8B5FFFFFF4883C428C3" : "03C94883EC28E8B5FFFFFF4883C428C3");
            if (variant == "constant-argument") wrapperBytes = Convert.FromHexString("B9070000004883EC28E8B2FFFFFF4883C428C3");
            if (variant == "different-callee") BinaryPrimitives.WriteInt32LittleEndian(wrapperBytes.AsSpan(7), 0x15);
            if (variant == "extra-call") wrapperBytes = Convert.FromHexString("03C94883EC28E8B5FFFFFF89442420E82C0000008B4424204883C428C3");
            runBytes.CopyTo(bytes, 0x200); helperBytes.CopyTo(bytes, 0x280); wrapperBytes.CopyTo(bytes, 0x2c0);
            Convert.FromHexString("0F31C3").CopyTo(bytes, 0x300);
            helperBytes.CopyTo(bytes, 0x2e0);
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            var ranges = new[] { (0x1000, runBytes.Length), (0x1080, helperBytes.Length), (0x10c0, wrapperBytes.Length), (0x10e0, helperBytes.Length), (0x1100, 3) };
            U32(0x124, (uint)ranges.Length * 12);
            for (var i = 0; i < ranges.Length; i++) { U32(0x700 + 12 * i, (uint)ranges[i].Item1); U32(0x704 + 12 * i, (uint)(ranges[i].Item1 + ranges[i].Item2)); U32(0x708 + 12 * i, (uint)(0x3180 + i * 8)); bytes[0x780 + i * 8] = 1; }
            var names = new[] { "Void", "Boolean", "Char", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64", "Single", "Double", "String", "TypedReference", "IntPtr", "UIntPtr", "Object", "ValueType", "RuntimeTypeHandle", "RuntimeFieldHandle", "RuntimeMethodHandle", "NullReferenceException" };
            var core = names.Select((name, i) => new TypeDef { Index = i, Assembly = "mscorlib.dll", Namespace = "System", Name = name, Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public,
                IsValueType = name is not ("String" or "Object" or "ValueType" or "NullReferenceException"), IsEnum = false, Size = name == "Int32" ? 4 : 8 }).ToArray();
            TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
            var assemblyName = "CallWrapper" + variant;
            TypeDef Define(int i, string name, TypeRef? parent = null) => new() { Index = core.Length + i, Assembly = assemblyName + ".dll", Namespace = i == 0 ? "" : "Fixture", Name = name, Token = (uint)(0x02000001 + i),
                Attributes = TypeAttributes.Public | (variant == "static-init" && i == 1 ? 0 : TypeAttributes.BeforeFieldInit), IsValueType = false, IsEnum = false, BaseType = parent ?? Corlib("Object") };
            var module = Define(0, "<Module>"); var ops = Define(1, "Operations"); var consumer = Define(2, "Consumer"); var opsType = new DefinitionRef(ops, []);
            var derived = Define(3, "Derived", opsType);
            var helper = new MethodDef { Index = 0, Owner = ops, Name = "Hidden", Token = 0x06000001, Address = basis + 0x1080, Attributes = MethodAttributes.Private | (instance ? 0 : MethodAttributes.Static),
                ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Int32"), Parameters = [new("n", Corlib("Int32"), 0, null, false)] };
            var wrapper = new MethodDef { Index = 1, Owner = ops, Name = "Scale", Token = 0x06000002, Address = basis + 0x10c0, Attributes = (variant == "inaccessible" ? MethodAttributes.Private : MethodAttributes.Public) | (instance && variant != "static-init" ? 0 : MethodAttributes.Static) | (variant == "virtual-override" ? MethodAttributes.Virtual | MethodAttributes.NewSlot : 0),
                ImplAttributes = 0, Slot = variant == "virtual-override" ? 0 : -1, ReturnType = Corlib("Int32"), Parameters = variant == "static-init" ? [new("ops", opsType, 0, null, false), .. helper.Parameters] : helper.Parameters };
            var run = new MethodDef { Index = 2, Owner = consumer, Name = "Run", Token = 0x06000003, Address = basis + 0x1000, Attributes = MethodAttributes.Public | MethodAttributes.Static,
                ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Int32"), Parameters = instance ? [new("ops", opsType, 0, null, false), .. helper.Parameters] : helper.Parameters };
            var other = new MethodDef { Index = 3, Owner = ops, Name = "Other", Token = 0x06000004, Address = basis + 0x10e0, Attributes = helper.Attributes, ImplAttributes = 0, Slot = -1, ReturnType = helper.ReturnType, Parameters = helper.Parameters };
            var effect = new MethodDef { Index = 4, Owner = ops, Name = "Effect", Token = 0x06000005, Address = basis + 0x1100, Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void") };
            var exception = core.Single(t => t.Name == "NullReferenceException");
            var exceptionCtor = new MethodDef { Index = 5, Owner = exception, Name = ".ctor", Token = 0x06000001, Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void") }; exception.Methods = [exceptionCtor];
            var initializer = new MethodDef { Index = 6, Owner = ops, Name = ".cctor", Token = 0x06000006, Attributes = MethodAttributes.Private | MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void") };
            var overridden = new MethodDef { Index = 7, Owner = derived, Name = "Scale", Token = 0x06000007, Attributes = MethodAttributes.Public | MethodAttributes.Virtual, ImplAttributes = 0, Slot = 0, ReturnType = wrapper.ReturnType, Parameters = helper.Parameters };
            if (variant == "virtual-override") derived.Methods = [overridden];
            ops.Methods = variant == "static-init" ? [helper, wrapper, other, effect, initializer] : [helper, wrapper, other, effect]; consumer.Methods = [run];
            var image = ImageDocument.Parse(bytes);
            var coreAssembly = new AssemblyDef { Name = "mscorlib.dll", AssemblyName = "mscorlib", Version = new(4, 0, 0, 0), Culture = "", PublicKey = [], Types = core };
            var fixture = new AssemblyDef { Name = ops.Assembly, AssemblyName = assemblyName, Version = new(1, 0, 0, 0), Culture = "", PublicKey = [], Types = [module, ops, consumer, derived] };
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [coreAssembly, fixture], Types = [.. core, module, ops, consumer, derived], Methods = variant == "static-init" ? [helper, wrapper, run, other, effect, exceptionCtor, initializer] : variant == "virtual-override" ? [helper, wrapper, run, other, effect, exceptionCtor, overridden] : [helper, wrapper, run, other, effect, exceptionCtor],
                Fields = [], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var entries = model.Methods.Where(m => m.Address != 0).Select(m => new CodeEntry(m.Address, EntryKind.Method, MethodRef.Open(m), 0, null)).ToArray();
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries, ByAddress = entries.ToDictionary(e => e.Address, e => new[] { e }), Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(), MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var code = CodeMap.BuildPe(image, entries.Select(e => e.Address)); var scan = CodeScan.Unscanned(code);
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = scan, Registrations = registrations, Layouts = new FieldLayouts(model), Helpers = RuntimeHelpers.Unclassified(code, scan), Usages = UsageSlots.Build(model, code, scan), Checks = new(), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var types = new ManagedTypes(model, facts.Layouts); var recovery = new MethodDecompiler(facts, types); var result = recovery.Recover(MethodRef.Open(run), run.Address);
            var wrapperResult = recovery.Recover(MethodRef.Open(wrapper), wrapper.Address);
            Check(wrapperResult.Body is not null, "变异须保留完整包装体以检查等价性：" + variant + ":" + string.Join(';', wrapperResult.Holes.Select(h => h.Reason)));
            Check(result.Body is not null, "调用区域须保留可检查的方法体：" + variant + ":" + string.Join(';', result.Holes.Select(h => h.Reason)));
            var calls = result.Body!.Blocks.SelectMany(b => b.Statements).OfType<Cpp2CS.Managed.ManagedCall>().ToArray();
            var valid = variant is "static" or "instance";
            Check(calls.Any(c => c.Invocation.Method.Method == wrapper) == valid, "包装证明或变异拒绝不符：" + variant);
            if (!valid) continue;
            var skeleton = new Skeleton(model);
            // 独立编写公共 API 的 CIL，执行时不依赖它的恢复体。
            var helperIl = skeleton.Method(helper).Body.GetILProcessor(); helperIl.Body.Instructions.Clear();
            helperIl.Emit(instance ? OpCodes.Ldarg_1 : OpCodes.Ldarg_0); helperIl.Emit(OpCodes.Ldc_I4_7); helperIl.Emit(OpCodes.Add); helperIl.Emit(OpCodes.Ret);
            var wrapperIl = skeleton.Method(wrapper).Body.GetILProcessor(); wrapperIl.Body.Instructions.Clear();
            if (instance) wrapperIl.Emit(OpCodes.Ldarg_0);
            wrapperIl.Emit(instance ? OpCodes.Ldarg_1 : OpCodes.Ldarg_0); wrapperIl.Emit(OpCodes.Ldc_I4_2); wrapperIl.Emit(OpCodes.Mul); wrapperIl.Emit(OpCodes.Call, skeleton.Method(helper)); wrapperIl.Emit(OpCodes.Ret);
            Check(new BodyEmitter(skeleton, types).Emit([result.Body]).Count == 0, "包装调用须通过 CIL 检查");
            using var stream = new MemoryStream(); skeleton.Assembly(ops.Assembly).Write(stream); var loaded = Assembly.Load(stream.ToArray());
            var invoke = loaded.GetType("Fixture.Consumer", true)!.GetMethod("Run")!;
            var receiver = instance ? System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(loaded.GetType("Fixture.Operations", true)!) : null;
            foreach (var n in new[] { int.MinValue, -101, -1, 0, 1, 17, int.MaxValue })
                Check((int)invoke.Invoke(null, instance ? [receiver, n] : [n])! == unchecked(n * 2 + 12), "包装恢复须保持调用参数和后继算术");
            if (instance) Check((int)invoke.Invoke(null, [null, 17])! == -100, "空接收者须保留原来的分支返回");
        }
        Console.WriteLine("公共调用包装完整恢复/CIL/CLR 对照通过：静态与实例调用，15 组整数及空值输入；权限、额外调用、常量参数、方法身份、额外判空、虚重写和精确静态初始化变异拒绝");
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

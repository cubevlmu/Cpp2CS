using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.InteropServices;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Model;
using Cpp2CS.Output;
using Cpp2CS.Recovery;
using Mono.Cecil.Cil;

namespace Cpp2CS.X64.Tests;

internal static class ConstructorPrefixTests
{
    [UnmanagedFunctionPointer(System.Runtime.InteropServices.CallingConvention.Cdecl)]
    private delegate void NativeConstructor(nint instance, int input);

    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        const ulong basis = 0x180000000, empty = basis + 0x1180, helper = basis + 0x11c0;
        foreach (var variant in new[] { "call", "branch", "late", "barrier", "fake-barrier", "escape", "read", "bypass", "duplicate", "receiver", "callee-read", "exception" })
        {
            var bytes = original.ToArray(); var code = new List<byte>();
            void Emit(string hex) => code.AddRange(System.Convert.FromHexString(hex));
            void Call(ulong target)
            {
                Emit("E8"); var displacement = new byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(displacement, checked((int)((long)target - (long)(basis + 0x1000 + (ulong)code.Count + 4))));
                code.AddRange(displacement);
            }
            Emit("534883EC20488BD9");
            if (variant == "late") code.AddRange(Enumerable.Repeat((byte)0x90, 272));
            if (variant == "branch") Emit("85D27D02F7DA");
            if (variant == "read") Emit("8B4B10");
            else if (variant != "escape") Emit("8BCA");
            Call(helper); Emit("894310");
            if (variant is "barrier" or "fake-barrier") { Emit("48C7431800000000488D4B18"); Call(basis + 0x11e0); }
            Emit("488BCB33D2");
            if (variant == "receiver") Emit("31C9");
            if (variant == "bypass") Emit("85C07405");
            Call(empty);
            if (variant == "duplicate") { Emit("488BCB33D2"); Call(empty); }
            Emit("4883C4205BC3");
            var callerBytes = code.ToArray(); callerBytes.CopyTo(bytes, 0x200);
            var emptyBytes = System.Convert.FromHexString(variant == "callee-read" ? "8B4110C3" : "C3"); emptyBytes.CopyTo(bytes, 0x380);
            var helperBytes = System.Convert.FromHexString(variant == "escape" ? "8B4110C3" : "8D4101C3"); helperBytes.CopyTo(bytes, 0x3c0);
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            U32(0x124, 48); bytes[0x3e0] = 0xc3;
            foreach (var (index, entry, length) in new[] { (0, 0x1000, callerBytes.Length), (1, 0x1180, emptyBytes.Length), (2, 0x11c0, helperBytes.Length), (3, 0x11e0, 1) })
            {
                U32(0x700 + index * 12, (uint)entry); U32(0x704 + index * 12, (uint)(entry + length));
                U32(0x708 + index * 12, (uint)(0x3140 + index * 8)); bytes[0x740 + index * 8] = 1;
            }
            if (variant == "exception") { bytes[0x748] = 9; U32(0x74c, 0x11c0); }
            var names = new[] { "Void", "Boolean", "Char", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64", "Single", "Double",
                "String", "TypedReference", "IntPtr", "UIntPtr", "Object", "ValueType", "RuntimeTypeHandle", "RuntimeFieldHandle", "RuntimeMethodHandle", "NullReferenceException" };
            var core = names.Select((name, i) => new TypeDef { Index = i, Assembly = "mscorlib.dll", Namespace = "System", Name = name,
                Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public, IsValueType = name is not ("String" or "Object" or "ValueType" or "NullReferenceException"),
                IsEnum = false, Size = name == "Int32" ? 4 : 8 }).ToArray();
            TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
            var assembly = "ConstructorPrefix" + variant;
            var module = new TypeDef { Index = core.Length, Assembly = assembly + ".dll", Namespace = "", Name = "<Module>", Token = 0x02000001,
                Attributes = TypeAttributes.NotPublic, IsValueType = false, IsEnum = false, Size = 0 };
            var owner = new TypeDef { Index = core.Length + 1, Assembly = module.Assembly, Namespace = "Fixture", Name = "Child", Token = 0x02000002,
                Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 32, BaseType = Corlib("Object") };
            var ownerType = new DefinitionRef(owner, []);
            var field = new FieldDef { Index = 0, Owner = owner, Name = "Number", Type = Corlib("Int32"), Attributes = FieldAttributes.Public, Offset = 16 };
            owner.Fields = [field, new() { Index = 1, Owner = owner, Name = "Other", Type = Corlib("Object"), Attributes = FieldAttributes.Public, Offset = 24 }];
            MethodDef Method(int index, TypeDef type, string name, ulong entry, bool isStatic, TypeRef result, TypeRef[] args) => new() {
                Index = index, Owner = type, Name = name, Address = entry, Token = (uint)(0x06000001 + index), Slot = -1, ImplAttributes = 0,
                Attributes = MethodAttributes.Public | (isStatic ? MethodAttributes.Static : 0)
                    | (name == ".ctor" ? MethodAttributes.SpecialName | MethodAttributes.RTSpecialName : 0), ReturnType = result,
                Parameters = args.Select((t, i) => new ParameterDef("p" + i, t, 0, null, false)).ToArray() };
            var caller = Method(0, owner, ".ctor", basis + 0x1000, false, Corlib("Void"), [Corlib("Int32")]);
            var bump = Method(1, owner, "Bump", helper, true, Corlib("Int32"), variant == "escape" ? [ownerType, Corlib("Int32")] : [Corlib("Int32")]);
            var objectCtor = Method(2, core.Single(t => t.Name == "Object"), ".ctor", empty, false, Corlib("Void"), []);
            var alias = Method(3, owner, "Empty", empty, true, Corlib("Void"), []);
            owner.Methods = [caller, bump, alias]; objectCtor.Owner.Methods = [objectCtor];
            var nullCtor = Method(4, core.Single(t => t.Name == "NullReferenceException"), ".ctor", 0, false, Corlib("Void"), []); nullCtor.Owner.Methods = [nullCtor];
            var image = ImageDocument.Parse(bytes);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Types = [.. core, module, owner], Fields = owner.Fields, Methods = [caller, bump, objectCtor, alias, nullCtor],
                Assemblies = [new() { Name = "mscorlib.dll", AssemblyName = "mscorlib", Version = new(4, 0, 0, 0), Culture = "", PublicKey = [], Types = core },
                    new() { Name = module.Assembly, AssemblyName = assembly, Version = new(1, 0, 0, 0), Culture = "", PublicKey = [], Types = [module, owner] }],
                RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var entries = new[] { caller, bump, objectCtor, alias }.Select(m => new CodeEntry(m.Address, EntryKind.Method, MethodRef.Open(m), m.Index, null)).ToArray();
            var map = CodeMap.BuildPe(image, entries.Select(e => e.Address)); var scan = CodeScan.Unscanned(map);
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries,
                ByAddress = entries.GroupBy(e => e.Address).ToDictionary(g => g.Key, g => g.ToArray()), Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
                MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var helpers = RuntimeHelpers.FromEvidence(map, scan, [new(basis + 0x11e0, variant == "fake-barrier" ? HelperKind.Export : HelperKind.GcNotification,
                null, "独立非捕获通知契约", 1)]);
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = map, Scan = scan, Registrations = registrations, Layouts = new(model),
                Usages = UsageSlots.Build(model, map, scan), Helpers = helpers, Checks = new(), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var types = new ManagedTypes(model, facts.Layouts); var recovery = new MethodDecompiler(facts, types);
            var recovered = recovery.Recover(MethodRef.Open(caller), caller.Address);
            if (variant is not ("call" or "branch" or "late" or "barrier"))
            {
                Check(recovered.Body is null, "构造前 this 泄漏、读取、绕过、重复、其他接收者和未知目标效果必须拒绝：" + variant); continue;
            }
            Check(recovered.Body is not null && recovered.Holes.Count == 0, "复杂前缀的空基类构造必须完整恢复：" + variant + " " + string.Join(';', recovered.Holes.Select(h => h.Reason)));
            if (OperatingSystem.IsWindows() && RuntimeInformation.ProcessArchitecture == System.Runtime.InteropServices.Architecture.X64)
                HardwareTests.WithCode(bytes.AsSpan(0x200, 0x200).ToArray(), pointer =>
                {
                    var invoke = Marshal.GetDelegateForFunctionPointer<NativeConstructor>(pointer);
                    var instance = Marshal.AllocHGlobal(32);
                    try
                    {
                        foreach (var input in Inputs)
                        {
                            Marshal.WriteInt32(instance + 16, -999); invoke(instance, input);
                            var value = variant == "branch" && input < 0 ? unchecked(-input) : input;
                            Check(Marshal.ReadInt32(instance + 16) == unchecked(value + 1), "原生构造函数保持字段写入和前缀调用");
                        }
                    }
                    finally { Marshal.FreeHGlobal(instance); }
                });
            var skeleton = new Skeleton(model); var il = skeleton.Method(bump).Body.GetILProcessor(); il.Body.Instructions.Clear();
            il.Emit(OpCodes.Ldarg_0); il.Emit(OpCodes.Ldc_I4_1); il.Emit(OpCodes.Add); il.Emit(OpCodes.Ret);
            Check(new BodyEmitter(skeleton, types).Emit([recovered.Body!]).Count == 0, "恢复体必须通过原有构造初始化及 CIL 检查");
            var calls = skeleton.Method(caller).Body.Instructions.Where(i => i.OpCode == OpCodes.Call && i.Operand is Mono.Cecil.MethodReference)
                .Select(i => ((Mono.Cecil.MethodReference)i.Operand).Name).ToArray();
            Check(calls.Count(n => n == "Bump") == 1 && calls.Count(n => n == ".ctor") == 1 && Array.IndexOf(calls, "Bump") < Array.IndexOf(calls, ".ctor"),
                "前缀调用与基类初始化各保留一次，顺序不变");
            using var stream = new MemoryStream(); skeleton.Assembly(module.Assembly).Write(stream);
            var generated = Assembly.Load(stream.ToArray()).GetType("Fixture.Child", true)!;
            foreach (var input in Inputs)
            {
                var instance = Activator.CreateInstance(generated, [input])!;
                var value = variant == "branch" && input < 0 ? unchecked(-input) : input;
                Check((int)generated.GetField("Number")!.GetValue(instance)! == unchecked(value + 1), "构造字段与前缀调用保留计算结果和顺序");
            }
        }
        Console.WriteLine("Win64 构造前缀：非 this 调用、分支、长前缀和已证明 GC 通知原生/CIL/CLR 28 组输入；伪通知、this 泄漏／读取、绕过初始化、重复调用、错误接收者和异常效果拒绝");
    }

    private static readonly int[] Inputs = [int.MinValue, -10, -1, 0, 1, 42, int.MaxValue];

    private static void Check(bool valid, string reason) { if (!valid) throw new InvalidOperationException(reason); }
}

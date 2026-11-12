using System.Buffers.Binary;
using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Model;
using Cpp2CS.Output;
using Cpp2CS.Recovery;
using Cpp2CS.X64;
using Mono.Cecil.Cil;
using Cpp2CS.Machine.Lifting;
using Cpp2CS.Recovery.Calls;
using Cpp2CS.Ir;

namespace Cpp2CS.X64.Tests;

internal static class ConstantLeafTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        const ulong basis = 0x180000000;
        Cpp2CS.Facts.Derived.NativeCallSummary? previous = null;
        foreach (var variant in new[] { "false", "true", "integer", "memory", "partial", "unregistered-alias", "unregistered-add", "unregistered-cmov", "unregistered-write", "unregistered-trap", "registered-alias", "registered-add", "registered-cmov", "registered-alias-unsigned" })
        {
            var unregistered = variant.StartsWith("unregistered-", StringComparison.Ordinal);
            var registered = variant.StartsWith("registered-", StringComparison.Ordinal);
            var nativePattern = unregistered || registered;
            var projected = registered && variant != "registered-alias-unsigned";
            var bytes = original.ToArray();
            var callerBytes = System.Convert.FromHexString("4883EC28E8770000004883C428C3");
            var body = System.Convert.FromHexString(variant switch { "false" => "669032C0C3", "true" => "B001C3", "integer" => "B8EFBEADDEC3", "partial" => "32C0C3",
                "unregistered-alias" or "registered-alias" or "registered-alias-unsigned" => "4889C8C3", "unregistered-add" or "registered-add" => "488D0411C3", "unregistered-cmov" or "registered-cmov" => "4885C94889D0480F45C1C3",
                "unregistered-write" => "4889114889C8C3", "unregistered-trap" => "CC4889C8C3", _ => "8B01C3" });
            callerBytes.CopyTo(bytes, 0x200); body.CopyTo(bytes, 0x280);
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            U32(0x124, 24); U32(0x700, 0x1000); U32(0x704, (uint)(0x1000 + callerBytes.Length)); U32(0x708, 0x3140);
            U32(0x70c, 0x1080); U32(0x710, (uint)(0x1080 + body.Length)); U32(0x714, 0x3150); bytes[0x740] = 1; bytes[0x750] = 1;
            var names = new[] { "Void", "Boolean", "Char", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64", "Single", "Double",
                "String", "TypedReference", "IntPtr", "UIntPtr", "Object", "ValueType", "RuntimeTypeHandle", "RuntimeFieldHandle", "RuntimeMethodHandle", "NullReferenceException" };
            var core = names.Select((name, i) => new TypeDef { Index = i, Assembly = "mscorlib.dll", Namespace = "System", Name = name,
                Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public, IsValueType = name is not ("String" or "Object" or "ValueType" or "NullReferenceException"),
                IsEnum = false, Size = name == "Int32" ? 4 : 8 }).ToArray();
            TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
            var assembly = "ConstantLeaf" + variant;
            var module = new TypeDef { Index = core.Length, Assembly = assembly + ".dll", Namespace = "", Name = "<Module>", Token = 0x02000001,
                Attributes = TypeAttributes.NotPublic, IsValueType = false, IsEnum = false, Size = 0 };
            var owner = new TypeDef { Index = core.Length + 1, Assembly = module.Assembly, Namespace = "Fixture", Name = "Reader", Token = 0x02000002,
                Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16, BaseType = Corlib("Object") };
            var returned = Corlib(nativePattern ? "Int64" : variant is "integer" or "memory" or "partial" ? "Int32" : "Boolean");
            var caller = new MethodDef { Index = 0, Owner = owner, Name = "Run", Token = 0x06000001, Address = basis + 0x1000,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = returned,
                Parameters = nativePattern ? [new("left", returned, 0, null, false), new("right", returned, 0, null, false)]
                    : [new("value", Corlib("IntPtr"), 0, null, false)] };
            MethodDef Candidate(int index, bool parameter) => new() { Index = index, Owner = owner, Name = parameter ? "WithInput" : "WithoutInput",
                Token = (uint)(0x06000001 + index), Address = basis + 0x1080, Attributes = MethodAttributes.Public | MethodAttributes.Static,
                ImplAttributes = 0, Slot = -1, ReturnType = returned, Parameters = registered ? caller.Parameters : parameter ? [new("value", Corlib("Int32"), 0, null, false)] : [] };
            var first = Candidate(1, false); var second = Candidate(2, true); owner.Methods = [caller, first, second];
            if (variant == "registered-alias-unsigned") second.ReturnType = Corlib("UInt64");
            var image = ImageDocument.Parse(bytes);
            var fixture = new AssemblyDef { Name = module.Assembly, AssemblyName = assembly, Version = new(1, 0, 0, 0), Culture = "", PublicKey = [], Types = [module, owner] };
            var corlib = new AssemblyDef { Name = "mscorlib.dll", AssemblyName = "mscorlib", Version = new(4, 0, 0, 0), Culture = "", PublicKey = [], Types = core };
            var nullType = core.Single(t => t.Name == "NullReferenceException");
            var nullConstructor = new MethodDef { Index = 3, Owner = nullType, Name = ".ctor", Token = 0x06000001,
                Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1 };
            nullType.Methods = [nullConstructor];
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [corlib, fixture], Types = [.. core, module, owner],
                Methods = [.. owner.Methods, nullConstructor], Fields = [], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var code = CodeMap.BuildPe(image, [caller.Address]); var scan = CodeScan.Unscanned(code);
            var entries = owner.Methods.Where(m => !unregistered || m == caller).Select(m => new CodeEntry(m.Address, EntryKind.Method, MethodRef.Open(m), 0, null)).ToArray();
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = scan, Layouts = new FieldLayouts(model),
                Registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries, ByAddress = entries.GroupBy(e => e.Address).ToDictionary(g => g.Key, g => g.ToArray()),
                    Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(), MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() },
                Helpers = RuntimeHelpers.Unclassified(code, scan), Usages = UsageSlots.Build(model, code, scan), Checks = new(), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var types = new ManagedTypes(model, facts.Layouts);
            if (variant is "unregistered-alias" or "unregistered-add" or "unregistered-cmov")
            {
                var summary = facts.NativeCalls.At(basis + 0x1080);
                Check(summary is not null && !ReferenceEquals(summary, previous), "相同地址的不同映像必须重新证明，不能串用原生摘要");
                previous = summary;
                var nativeCall = new Call(caller.Address + 4, CallKind.Direct, Expr.C(basis + 0x1080, 64));
                var shape = new CallShapes(facts, facts.CreateAbi(), (_, _) => false).Of(nativeCall);
                Check(shape.Candidates.Count == 0 && shape.Signature is null && ReferenceEquals(shape.NativeSummary, summary),
                    "独立机器摘要不能虚构托管身份或托管 ABI");
                var calls = new FactsCallModel(facts, facts.CreateMachine().Convention);
                Check(calls.Signature(basis + 0x1080) is { Source: "proven-native-straight-line" } contract
                    && contract.Reads.ToHashSet().SetEquals(variant == "unregistered-alias" ? new[] { Storage.Gpr(1) } : new[] { Storage.Gpr(1), Storage.Gpr(2) })
                    && calls.Clobbers(nativeCall).Contains(Storage.Gpr(0)), "精确输入与 ABI volatile clobber 分别保留");
                if (variant == "unregistered-alias")
                {
                    var inputs = new Cpp2CS.Facts.Derived.NativeCalleeFacts(facts, false);
                    Check(inputs.UnusedInput(basis + 0x1080, Storage.Gpr(2)) && !inputs.UnusedInput(basis + 0x1080, Storage.Gpr(1))
                        && inputs.UnusedInput(caller.Address, Storage.Gpr(2)), "有完整边界的无身份原生体和调用包装可证明输入；不能虚构托管身份");
                }
            }
            var result = new MethodDecompiler(facts, types).Recover(MethodRef.Open(caller), caller.Address);
            if (variant is "memory" or "partial" or "unregistered-write" or "unregistered-trap")
            { Check(result.Body is null && result.Holes.Count > 0, "未知访存、陷阱或未覆盖的返回高位不能冒充无效果恢复：" + variant); continue; }
            Check(result.Body is not null && result.Holes.Count == 0, "共享常量体完整恢复：" + string.Join(';', result.Holes.Select(h => h.Reason)));
            var bodies = new List<Cpp2CS.Managed.ManagedBody> { result.Body! };
            if (projected)
            {
                Check(result.Calls.Any(c => c.Status == "native-equivalent-projection"), "完整恢复必须保留等价投影依据");
                foreach (var candidate in new[] { first, second })
                {
                    var recovered = new MethodDecompiler(facts, types).Recover(MethodRef.Open(candidate), candidate.Address);
                    Check(recovered.Body is not null && recovered.Holes.Count == 0, "等价声明本身必须可完整恢复");
                    bodies.Add(recovered.Body!);
                }
            }
            var skeleton = new Skeleton(model);
            Check(new BodyEmitter(skeleton, types).Emit(bodies).Count == 0, "常量体 CIL 写出检查");
            Check(skeleton.Method(caller).Body.Instructions.Any(i => i.OpCode == OpCodes.Call || i.OpCode == OpCodes.Callvirt) == projected, "只有证明等价的已登记声明才投影为托管调用");
            using var stream = new MemoryStream(); skeleton.Assembly(module.Assembly).Write(stream);
            var loaded = Assembly.Load(stream.ToArray()); var run = loaded.GetType("Fixture.Reader", true)!.GetMethod("Run")!;
            if (nativePattern)
            {
                Check(projected || result.NativeExpansions.Any(e => e.Caller == caller.Address && e.CallSite == caller.Address + 4 && e.Inlinee == basis + 0x1080),
                    "完整恢复必须保留 caller、call site 和无身份原生体的来源链");
                var values = new[] { long.MinValue, long.MinValue + 1, -4294967296, -65536, -1, 0, 1, 255, 65536, 4294967296, long.MaxValue - 1, long.MaxValue };
                foreach (var left in values)
                foreach (var right in values)
                {
                    var expected = variant.EndsWith("-add", StringComparison.Ordinal) ? unchecked(left + right) : variant.EndsWith("-cmov", StringComparison.Ordinal) && left == 0 ? right : left;
                    Check((long)run.Invoke(null, [left, right])! == expected, "无托管身份的完整机器语义保持模加法、返回别名和条件选择：" + variant);
                }
                continue;
            }
            foreach (var input in new nint[] { 0, 1, -1, nint.MaxValue })
            {
                var actual = run.Invoke(null, [input]);
                Check(variant == "integer" ? (int)actual! == unchecked((int)0xdeadbeef) : (bool)actual! == (variant == "true"), "CLR 保持原生常量位型");
            }
        }
        Console.WriteLine("短原生体完整恢复/CIL/CLR 对照通过：共享常量、无身份／歧义身份展开及等价声明调用 1008 组输入，未知读取、存储和陷阱拒绝");
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

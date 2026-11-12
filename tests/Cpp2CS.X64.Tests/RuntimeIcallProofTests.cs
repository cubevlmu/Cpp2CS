using System.Buffers.Binary;
using System.Reflection;
using System.Text;
using Cpp2CS.Facts;
using Cpp2CS.Facts.Derived;
using Cpp2CS.Image;
using Cpp2CS.Model;
using Cpp2CS.X64;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Lifting;

namespace Cpp2CS.X64.Tests;

internal static class RuntimeIcallProofTests
{
    internal static void Run(byte[] original, SleighDecoder decoder, TypeDef[] core)
    {
        var bytes = original.ToArray();
        void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
        void Relative(int at, int target) => BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(at), target - (at + 0xe00) - 4);
        U32(0x108, 0x2000); U32(0x10c, 0x200);
        Array.Clear(bytes, 0x400, 0x200);
        U32(0x414, 1); U32(0x418, 1); U32(0x41c, 0x2040); U32(0x420, 0x2044); U32(0x424, 0x2048);
        U32(0x440, 0x1100); U32(0x444, 0x2060);
        Encoding.ASCII.GetBytes("il2cpp_resolve_icall\0").CopyTo(bytes, 0x460);
        System.Convert.FromHexString("40534883EC20488B05000000008BD94885C07513488D0D00000000E800000000488905000000008BCB4883C4205B48FFE0").CopyTo(bytes, 0x200);
        Relative(0x209, 0x20c0); Relative(0x217, 0x30c0); Relative(0x21c, 0x1080); Relative(0x223, 0x20c0);
        System.Convert.FromHexString("40534883EC20488BD9E8000000004885C074064883C4205BC3488BCBE800000000488BC833D2E800000000CC").CopyTo(bytes, 0x280);
        Relative(0x28a, 0x1100); Relative(0x29d, 0x1120); Relative(0x2a7, 0x1140); bytes[0x300] = 0xc3;
        U32(0x704, 0x1031); U32(0x710, 0x10ac);
        Encoding.ASCII.GetBytes("Fixture.Api::Hidden(System.Int32)\0").CopyTo(bytes, 0x6c0);
        var integer = new DefinitionRef(core.Single(t => t.Name == "Int32"), []);
        var owner = new TypeDef { Index = core.Length, Assembly = "Fixture.dll", Namespace = "Fixture", Name = "Api", Token = 0x02000020,
            Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 };
        MethodRef Method(int index, bool internalCall, ulong address, bool boolean) => MethodRef.Open(new MethodDef { Index = index, Owner = owner, Name = internalCall ? "Hidden" : "Visible",
            Address = address, Token = (uint)(0x06000001 + index), Attributes = MethodAttributes.Static | (internalCall ? MethodAttributes.Private : MethodAttributes.Public),
            ImplAttributes = internalCall ? MethodImplAttributes.InternalCall : 0, Slot = -1, ReturnType = integer,
            Parameters = [new("value", boolean ? new DefinitionRef(core.Single(t => t.Name == "Boolean"), []) : integer, 0, null, false)] });
        bool Prove(byte[] data, ulong basis = 0x180000000, bool internalCall = true, bool? bindingExpected = null, bool boolean = false, bool unusedExpected = true)
        {
            var candidates = new[] { Method(0, internalCall, basis + 0x1000, boolean), Method(1, false, basis + 0x1000, boolean) };
            var image = ImageDocument.Parse(data); var code = CodeMap.BuildPe(image, [basis + 0x1000]);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [], Types = [.. core, owner], Fields = [],
                Methods = candidates.Select(m => m.Method).ToArray(), RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [],
                Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var entries = candidates.Select(m => new CodeEntry(m.Method.Address, EntryKind.Method, m, 0, null)).ToArray();
            var scan = CodeScan.Unscanned(code);
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Layouts = new FieldLayouts(model), Scan = scan,
                Helpers = RuntimeHelpers.Unclassified(code, scan),
                Registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries,
                    ByAddress = entries.GroupBy(e => e.Address).ToDictionary(g => g.Key, g => g.ToArray()),
                    Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(), MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() },
                MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            if (bindingExpected is { } expected)
            {
                var lifted = new FunctionLifter(facts).Lift(basis + 0x1000, new Intrinsic("return", [new Read(Storage.Gpr(0), 64)], 64), simplify: false);
                var bindings = facts.NativeIcalls.Inputs(lifted.Function);
                var tails = lifted.Function.Blocks.SelectMany(b => b.Statements).OfType<Call>().Where(c => c.Kind == CallKind.TailIndirect).ToArray();
                Check(expected ? tails.Length == 1 && bindings.TryGetValue(tails[0], out var inputs) && inputs.Keys.ToHashSet().SetEquals([Storage.Gpr(1)])
                    : tails.All(t => !bindings.ContainsKey(t)),
                    "缓存内部调用的 SSA 目标必须连接完整名称对应的精确输入，不包含 MethodInfo");
                if (expected)
                {
                    var tail = tails.Single();
                    Check(bindings[tails[0]][Storage.Gpr(1)] == (boolean ? 8 : 32), "内部调用输入必须保留原生消费位宽");
                    Check(new NativeCalleeFacts(facts, false).UnusedInput(basis + 0x1000, Storage.Gpr(2)) == unusedExpected,
                        "完整输入分析应按实际消费的低位及显式读取核对 MethodInfo");
                    var block = lifted.Function.Blocks.Single(b => b.Statements.Contains(tail));
                    var unknownStore = new Store(tail.Address, new Use(new Variable(Storage.Gpr(2), 0), 64), Expr.C(0, 64));
                    block.Statements.Insert(0, unknownStore);
                    Check(!facts.NativeIcalls.Inputs(lifted.Function).ContainsKey(tail), "未知别名写入可能覆盖缓存，不能继续绑定");
                    block.Statements.Remove(unknownStore);
                    var index = block.Statements.IndexOf(tail);
                    block.Statements[index] = tail with { Target = Expr.C(basis + 0x1200, 64) };
                    Check(!facts.NativeIcalls.Inputs(lifted.Function).ContainsKey((Call)block.Statements[index]), "解析结果没有流向实际调用时不能建立绑定");
                }
            }
            return RuntimeIcallProof.IgnoresMethodInfo(facts, basis + 0x1000, candidates, facts.CreateAbi().Machine(candidates[0], out _)!);
        }
        Check(Prove(bytes, bindingExpected: true), "解析导出、完整 icall 签名及参数转发共同证明不读取 MethodInfo");
        Check(!Prove(bytes, internalCall: false, bindingExpected: false), "普通方法不能冒充内部调用桩");
        foreach (var at in new[] { 0x213, 0x21c, 0x223, 0x227, 0x230, 0x28a, 0x292, 0x4c0, 0x6c0, 0x460 })
        {
            var changed = bytes.ToArray(); changed[at] ^= 1;
            Check(!Prove(changed, bindingExpected: at is 0x213 or 0x21c or 0x223 or 0x28a or 0x292 or 0x4c0 or 0x6c0 or 0x460 ? false : null),
                "缓存、分支、名称、导出或参数转发变化时拒绝");
        }
        var moved = bytes.ToArray(); BinaryPrimitives.WriteUInt64LittleEndian(moved.AsSpan(0xb0), 0x190000000);
        Check(Prove(moved, 0x190000000, bindingExpected: true), "内部调用证明不依赖固定基址");
        var savedInputs = bytes.ToArray();
        Array.Copy(bytes, 0x20f, savedInputs, 0x211, 0x22);
        savedInputs[0x20f] = 0x8b; savedInputs[0x210] = 0xf9;
        void MovedRelative(int at, int target) => BinaryPrimitives.WriteInt32LittleEndian(savedInputs.AsSpan(at), target - (at + 0xe00) - 4);
        MovedRelative(0x219, 0x30c0); MovedRelative(0x21e, 0x1080); MovedRelative(0x225, 0x20c0);
        BinaryPrimitives.WriteUInt32LittleEndian(savedInputs.AsSpan(0x704), 0x1033);
        _ = Prove(savedInputs, bindingExpected: true);
        var byteInput = bytes.ToArray();
        System.Convert.FromHexString("40534883EC20488B0500000000488BDA4885C07513488D0D00000000E80000000048890500000000488BCBB1014883C4205B48FFE0").CopyTo(byteInput, 0x200);
        void ByteRelative(int at, int target) => BinaryPrimitives.WriteInt32LittleEndian(byteInput.AsSpan(at), target - (at + 0xe00) - 4);
        ByteRelative(0x209, 0x20c0); ByteRelative(0x218, 0x30c0); ByteRelative(0x21d, 0x1080); ByteRelative(0x224, 0x20c0);
        BinaryPrimitives.WriteUInt32LittleEndian(byteInput.AsSpan(0x704), 0x1035);
        Encoding.ASCII.GetBytes("Fixture.Api::Hidden(System.Boolean)\0").CopyTo(byteInput, 0x6c0);
        _ = Prove(byteInput, bindingExpected: true, boolean: true);
        byteInput[0x22b] = 0xb5;
        _ = Prove(byteInput, bindingExpected: true, boolean: true, unusedExpected: false);
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

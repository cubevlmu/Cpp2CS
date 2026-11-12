using System.Buffers.Binary;
using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Facts.Derived;
using Cpp2CS.Image;
using Cpp2CS.Idioms;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Lifting;
using Cpp2CS.Machine.Ssa;
using Cpp2CS.Model;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class GuardedCopyTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        const ulong basis = 0x180000000;
        foreach (var invalid in new[] { "", "return", "store", "unused-read", "callee-saved", "guard-value", "guard-direction", "metadata", "helper", "exception" })
        {
            var bytes = original.ToArray();
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            byte[] Body(uint entry, uint flag, uint slot)
            {
                var code = System.Convert.FromHexString("534883EC20488BD9803D00000000007513488D0D00000000E800000000C6050000000001909090488BC34883C4205BC3");
                void Relative(int at, uint next, uint target) => BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(at), unchecked((int)(target - next)));
                Relative(10, entry + 15, flag); Relative(20, entry + 24, slot); Relative(25, entry + 29, 0x10f0); Relative(31, entry + 36, flag);
                return code;
            }
            var candidate = Body(0x1000, 0x2000, 0x2010);
            var witness = Body(0x1080, 0x2001, 0x2018);
            if (invalid == "return") System.Convert.FromHexString("31C090").CopyTo(candidate, 39);
            if (invalid == "store") System.Convert.FromHexString("488907").CopyTo(candidate, 39);
            if (invalid == "unused-read") System.Convert.FromHexString("448B17").CopyTo(candidate, 36);
            if (invalid == "callee-saved") candidate[46] = 0x5f;
            if (invalid == "guard-value") candidate[35] = 2;
            if (invalid == "guard-direction") candidate[15] = 0x74;
            candidate.CopyTo(bytes, 0x200); witness.CopyTo(bytes, 0x280); bytes[0x2f0] = 0xc3;
            U32(0x124, 24); U32(0x700, 0x1000); U32(0x704, (uint)(0x1000 + candidate.Length)); U32(0x708, 0x3140);
            U32(0x70c, 0x1080); U32(0x710, (uint)(0x1080 + witness.Length)); U32(0x714, 0x3140); bytes[0x740] = 1;
            if (invalid == "exception") { bytes[0x740] = 9; U32(0x744, 0x10f0); }
            var owner = new TypeDef { Index = 0, Assembly = "Fixture.dll", Namespace = "", Name = "Owner", Token = 0x02000001,
                Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 };
            var other = new TypeDef { Index = 1, Assembly = "Fixture.dll", Namespace = "", Name = "Other", Token = 0x02000002,
                Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 };
            var type = new DefinitionRef(owner, []);
            var method = MethodRef.Open(new MethodDef { Index = 0, Owner = owner, Name = "Identity", Token = 0x06000001, Address = basis + 0x1080,
                Attributes = MethodAttributes.Static | MethodAttributes.Public, ImplAttributes = 0, Slot = -1,
                ReturnType = type, Parameters = [new("value", type, 0, null, false)] });
            var image = ImageDocument.Parse(bytes);
            var map = CodeMap.BuildPe(image, [basis + 0x1000, basis + 0x1080]);
            var scan = CodeScan.Unscanned(map);
            CodeEntry[] entries = [new(basis + 0x1080, EntryKind.Method, method, 0, null)];
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries,
                ByAddress = new Dictionary<ulong, CodeEntry[]> { [basis + 0x1080] = entries }, Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
                MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [], Types = [owner, other], Methods = [method.Method],
                Fields = [], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var usages = new UsageSlots { Slots = new Dictionary<ulong, UsageSlot> {
                [basis + 0x2010] = new(basis + 0x2010, new(UsageKind.TypeInfo, 0, type), 1, 1),
                [basis + 0x2018] = new(basis + 0x2018, new(UsageKind.TypeInfo, 1, invalid == "metadata" ? new DefinitionRef(other, []) : type), 1, 1),
            }, SlotAddressBeforeCall = new Dictionary<ulong, int>(), UnreferencedDecodable = new Dictionary<ulong, Usage>() };
            RuntimeHelper[] helpers = invalid == "helper" ? [] : [new(basis + 0x10f0, HelperKind.InitMetadata, null, "独立初始化契约", 1)];
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = map, Scan = scan, Registrations = registrations, Usages = usages,
                Helpers = RuntimeHelpers.FromEvidence(map, scan, helpers), Layouts = new FieldLayouts(model), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var proof = new GuardedNativeCopyProof(facts);
            var matched = proof.Matches(basis + 0x1000, basis + 0x1080, [method]);
            Check(matched == (invalid == ""),
                "只接受完整守卫归一后的副本；返回、堆写入、非易失寄存器、标志、槽身份、helper 和异常差异均拒绝：" + invalid);
            Check((new NativeCopyProof(facts).At(basis + 0x1000) is [{ Method: var actual }] && actual == method) == (invalid == ""),
                "副本索引须复用相同证明边界：" + invalid);
            if (invalid is "" or "guard-value" or "helper" or "unused-read")
            {
                var lifted = new FunctionLifter(facts).Lift(basis + 0x1000, new Read(Storage.Gpr(0), 64), simplify: false);
                Check(lifted.Succeeded, "独立守卫夹具须完整提升");
                foreach (var block in lifted.Function.Blocks)
                    for (var i = 0; i < block.Statements.Count; i++)
                        if (block.Statements[i] is Define d && ExprMap.Walk(d.Value).Any(e => e is Load)) block.Statements[i] = d with { PreserveRead = true };
                Propagate.Run(lifted.Function, Dominators.Compute(lifted.Function));
                var result = new IdiomRewriter(facts) { RecordFilter = _ => false }.Run(lifted.Function);
                var completed = invalid is "" or "unused-read";
                Check(result.Hits.GetValueOrDefault(Template.MetadataInitGuard) > 0 == completed, "只按完整守卫证明解除读取：" + invalid);
                var retained = lifted.Function.Blocks.SelectMany(b => b.Statements).OfType<Define>().Where(d => d.PreserveRead).ToArray();
                Check(retained.Any(d => ExprMap.Walk(d.Value).OfType<Load>().Any(l => l.Address is Const c && c.Value == basis + 0x2000)) != completed,
                    "守卫证明失败时不能删除标志读取");
                if (invalid == "unused-read") Check(retained.Any(d => ExprMap.Walk(d.Value).OfType<Load>().Any(l => l.Address is not Const)),
                    "元数据守卫成功不能解除额外堆读取");
            }
        }
    }

    private static void Check(bool condition, string reason) { if (!condition) throw new InvalidOperationException(reason); }
}

using System.Buffers.Binary;
using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Lifting;
using Cpp2CS.Model;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class RuntimeForwardingTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        const ulong basis = 0x180000000;
        foreach (var invalid in new[] { "", "load", "store", "saved", "stack", "unknown", "managed", "exception", "boundary", "unproved" })
        {
            var bytes = original.ToArray();
            var prefix = invalid switch {
                "load" => "488B12", "store" => "488911", "saved" => "4889D3", "stack" => "488BD4", _ => "8BD2",
            };
            var wrapper = System.Convert.FromHexString(prefix + "E900000000");
            BinaryPrimitives.WriteInt32LittleEndian(wrapper.AsSpan(wrapper.Length - 4), (invalid == "unknown" ? 0x10e0 : 0x10c0) - (0x1080 + wrapper.Length));
            System.Convert.FromHexString("E87B000000C3").CopyTo(bytes, 0x200); wrapper.CopyTo(bytes, 0x280); bytes[0x2c0] = 0xc3;
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            U32(0x124, 24); U32(0x700, 0x1000); U32(0x704, 0x1006); U32(0x708, 0x3140);
            U32(0x70c, 0x1080); U32(0x710, (uint)(invalid == "boundary" ? 0x1081 : 0x1080 + wrapper.Length)); U32(0x714, 0x3160);
            bytes[0x740] = 1; bytes[0x760] = (byte)(invalid == "exception" ? 9 : 1); U32(0x764, 0x10f0);
            var owner = new TypeDef { Index = 0, Assembly = "Fixture.dll", Namespace = "", Name = "Owner", Token = 0x02000001,
                Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 };
            var image = ImageDocument.Parse(bytes);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [], Types = [owner], Methods = [], Fields = [],
                RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var code = CodeMap.BuildPe(image, invalid == "managed" ? [basis + 0x1000, basis + 0x1080] : [basis + 0x1000]);
            var scan = CodeScan.Unscanned(code); var machine = new PcodeMachine(image, decoder);
            RuntimeHelper[] helpers = invalid == "unproved" ? [] : [new(basis + 0x10c0, HelperKind.NewArray, null, "独立数组分配契约", 1)];
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = scan,
                Helpers = RuntimeHelpers.FromEvidence(code, scan, helpers), Layouts = new FieldLayouts(model), MachineFactory = () => machine }, new());
            var function = new CfgBuilder(machine, code).Build(basis + 0x1000);
            var originalCall = function.Blocks.SelectMany(b => b.Statements).OfType<Call>().Single();
            Check(new RuntimeForwarding(facts, machine).Run(function) == (invalid == "" ? 1 : 0), "转换跳板的效果、边界和独立契约：" + invalid);
            if (invalid != "") continue;
            var call = function.Blocks.SelectMany(b => b.Statements).OfType<Call>().Single();
            Check(call.Target is Const { Value: basis + 0x10c0 } && ReferenceEquals(call.Site, originalCall.Site), "保留调用身份并绑定已证明目标");
            var assignments = function.Blocks.SelectMany(b => b.Statements).OfType<Assign>().Cast<Stmt>().ToArray();
            foreach (var input in new ulong[] { 0, 1, 0xffffffff, 0x100000000, 0x1234567887654321, ulong.MaxValue })
            {
                var state = new Evaluator(); state.Registers[Storage.Gpr(2)] = input;
                state.Run(assignments, basis + 0x1000, basis + 0x1005);
                Check(state.Failure is null && state.Get(Storage.Gpr(2)) == (uint)input, "必须先清除长度高 32 位，不能整体假定包装与目标同 ABI");
            }
            Check(new RuntimeForwarding(facts, machine).Run(function) == 0, "直接契约目标不重复展开");
        }
    }

    private static void Check(bool condition, string reason) { if (!condition) throw new InvalidOperationException(reason); }
}

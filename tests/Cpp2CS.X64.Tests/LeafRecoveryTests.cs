using System.Buffers.Binary;
using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Managed;
using Cpp2CS.Model;
using Cpp2CS.Recovery;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class LeafRecoveryTests
{
    internal static void Run(byte[] original, SleighDecoder decoder, TypeDef[] core)
    {
        const ulong basis = 0x180000000;
        foreach (var changedOffset in new[] { false, true })
        foreach (var nativeBody in new[] { false, true })
        {
            var bytes = original.ToArray();
            var callerBytes = System.Convert.FromHexString("4883EC28E8770000004883C428C3");
            var leafBytes = System.Convert.FromHexString(changedOffset ? "8B0289018B42088941048B42048941084889C8C390CCCC" : "8B0289018B42048941048B42088941084889C8C390CCCC");
            if (nativeBody)
            {
                callerBytes = System.Convert.FromHexString("534883EC40488BD9488D4C2420E86E000000488B4424204889038B442428894308488BC34883C4405BC3");
                leafBytes = System.Convert.FromHexString("534883EC20488BD9" + (changedOffset
                    ? "8B0289038B42088943048B4204894308" : "8B0289038B42048943048B4208894308") + "488BC34883C4205BC3");
            }
            callerBytes.CopyTo(bytes, 0x200); leafBytes.CopyTo(bytes, 0x280);
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            U32(0x124, 24); U32(0x700, 0x1000); U32(0x704, (uint)(0x1000 + callerBytes.Length)); U32(0x708, 0x3140);
            U32(0x70c, 0x1080); U32(0x710, (uint)(0x1080 + leafBytes.Length)); U32(0x714, 0x3140); bytes[0x740] = 1;
            var integer = new DefinitionRef(core.Single(t => t.Name == "Int32"), []);
            var aggregate = new TypeDef { Index = 30, Assembly = "Fixture.dll", Namespace = "", Name = "Triple", Token = 0x0200001f,
                Attributes = TypeAttributes.Public | TypeAttributes.SequentialLayout, IsValueType = true, IsEnum = false, Size = 12 };
            aggregate.Fields = Enumerable.Range(0, 3).Select(i => new FieldDef { Index = i, Owner = aggregate, Name = "p" + i, Type = integer,
                Attributes = FieldAttributes.Public, Offset = i * 4 }).ToArray();
            var type = new DefinitionRef(aggregate, []);
            var owner = new TypeDef { Index = 31, Assembly = "Fixture.dll", Namespace = "", Name = "Owner", Token = 0x02000020,
                Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 };
            MethodRef Method(int index, ulong entry, bool reference) => MethodRef.Open(new MethodDef { Index = index, Owner = owner, Name = "Copy" + index,
                Token = (uint)(0x06000001 + index), Address = entry, Attributes = MethodAttributes.Public | MethodAttributes.Static,
                ImplAttributes = 0, Slot = -1, ReturnType = type, Parameters = [new("value", reference ? new ByRefRef(type) : type, 0, null, false)] });
            var caller = Method(0, basis + 0x1000, false);
            var candidates = new[] { Method(1, basis + 0x1080, false), Method(2, basis + 0x1080, true) };
            owner.Methods = nativeBody ? [caller.Method] : [caller.Method, .. candidates.Select(c => c.Method)];
            var image = ImageDocument.Parse(bytes);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [], Types = [.. core, aggregate, owner],
                Methods = owner.Methods, Fields = aggregate.Fields, RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [],
                Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var code = CodeMap.BuildPe(image, owner.Methods.Select(m => m.Address)); var scan = CodeScan.Unscanned(code);
            var entries = nativeBody ? [] : candidates.Select(c => new CodeEntry(c.Method.Address, EntryKind.Method, c, 0, null)).ToArray();
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries,
                ByAddress = entries.GroupBy(e => e.Address).ToDictionary(g => g.Key, g => g.ToArray()), Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
                MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = scan, Registrations = registrations,
                Helpers = RuntimeHelpers.Unclassified(code, scan), Usages = UsageSlots.Build(model, code, scan), Layouts = new FieldLayouts(model),
                Checks = new(), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var result = new MethodDecompiler(facts, new ManagedTypes(model, facts.Layouts)).Recover(caller, caller.Method.Address);
            Check(result.Body is not null && result.Holes.Count == 0, "混合签名搬运体须经过完整恢复管线：" + string.Join(';', result.Holes.Select(h => h.Reason)));
            var returns = result.Body!.Blocks.SelectMany(b => b.Statements).OfType<ManagedReturn>().ToArray();
            Check(!changedOffset ? returns is [{ Value: ArgumentValue { Index: 0 } }]
                : returns is [{ Value: ComposedValue { Leaves.Count: 3 } composed }]
                    && composed.Leaves.Select(l => l.Value).OfType<FieldValue>().Select(f => f.Field.Field.Index).SequenceEqual([0, 2, 1]),
                "恢复后的字段来源必须保留真实偏移，包括重排变体：" + string.Join(';', returns.Select(r => r.Value)));
        }
    }

    private static void Check(bool condition, string reason) { if (!condition) throw new InvalidOperationException(reason); }
}

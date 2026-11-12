using System.Buffers.Binary;
using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Lifting;
using Cpp2CS.Machine.Ssa;
using Cpp2CS.Managed;
using Cpp2CS.Model;
using Cpp2CS.Recovery;
using Cpp2CS.Recovery.Calls;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class ResultBufferTests
{
    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        const ulong basis = 0x180000000;
        var bytes = original.ToArray();
        var callerCode = System.Convert.FromHexString("4883EC38488D4C242033D2E8700000008B40084883C438C3");
        var producerCode = System.Convert.FromHexString("4889C8C70101000000C7410402000000C7410803000000C7410C04000000C3");
        callerCode.CopyTo(bytes, 0x200); producerCode.CopyTo(bytes, 0x280);
        void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
        U32(0x124, 24); U32(0x704, (uint)(0x1000 + callerCode.Length)); U32(0x708, 0x3140);
        U32(0x70c, 0x1080); U32(0x710, (uint)(0x1080 + producerCode.Length)); U32(0x714, 0x3140); bytes[0x740] = 1;
        var coreNames = new[] { "Object", "String", "Boolean", "Char", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64",
            "Single", "Double", "IntPtr", "RuntimeTypeHandle", "RuntimeFieldHandle", "RuntimeMethodHandle", "NullReferenceException" };
        var core = coreNames.Select((name, i) => new TypeDef { Index = i, Assembly = "mscorlib.dll", Namespace = "System", Name = name,
            Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public, IsValueType = name is not ("Object" or "String" or "NullReferenceException"),
            IsEnum = false, Size = name is "Int32" or "Single" ? 4 : 8 }).ToArray();
        var integer = new DefinitionRef(core.Single(t => t.Name == "Int32"), []);
        var aggregate = new TypeDef { Index = 19, Assembly = "Fixture.dll", Namespace = "", Name = "Aggregate", Token = 0x02000014,
            Attributes = TypeAttributes.Public | TypeAttributes.SequentialLayout, IsValueType = true, IsEnum = false, Size = 16 };
        aggregate.Fields = Enumerable.Range(0, 4).Select(i => new FieldDef { Index = i, Owner = aggregate, Name = "p" + i, Type = integer,
            Attributes = FieldAttributes.Public, Offset = i * 4 }).ToArray();
        var owner = new TypeDef { Index = 20, Assembly = "Fixture.dll", Namespace = "", Name = "Owner", Token = 0x02000015,
            Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 };
        MethodDef Method(int index, string name, ulong address, TypeRef returned) => new() { Index = index, Owner = owner, Name = name,
            Token = (uint)(0x06000001 + index), Address = address, Attributes = MethodAttributes.Public | MethodAttributes.Static,
            ImplAttributes = 0, Slot = -1, ReturnType = returned };
        var caller = MethodRef.Open(Method(0, "Read", basis + 0x1000, integer));
        var producer = MethodRef.Open(Method(1, "Make", basis + 0x1080, new DefinitionRef(aggregate, [])));
        var nullReference = core.Single(t => t.Name == "NullReferenceException");
        var nullConstructor = new MethodDef { Index = 2, Owner = nullReference, Name = ".ctor", Token = 0x06000003,
            Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1 };
        nullReference.Methods = [nullConstructor];
        owner.Methods = [caller.Method, producer.Method];
        var image = ImageDocument.Parse(bytes);
        var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [], Types = [.. core, aggregate, owner],
            Fields = aggregate.Fields, Methods = [.. owner.Methods, nullConstructor], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [],
            Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
        var code = CodeMap.BuildPe(image, owner.Methods.Select(m => m.Address));
        CodeEntry[] entries = [new(producer.Method.Address, EntryKind.Method, producer, 0, null)];
        var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries,
            ByAddress = entries.GroupBy(e => e.Address).ToDictionary(g => g.Key, g => g.ToArray()), Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
            MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
        var machine = new PcodeMachine(image, decoder); var scan = CodeScan.Unscanned(code);
        var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = scan, Registrations = registrations,
            Layouts = new FieldLayouts(model), Checks = new(), Usages = UsageSlots.Build(model, code, scan),
            Helpers = RuntimeHelpers.Unclassified(code, scan), MachineFactory = () => machine }, new());
        var abi = facts.CreateAbi();
        Check(new FactsCallModel(facts, machine.Convention).Results(new Call(basis + 0x100b, CallKind.Direct, Expr.C(producer.Method.Address, 64)))
            .Contains(Storage.Gpr(0)), "SSA 必须保留回传缓冲区地址的 RAX");
        var shapes = new CallShapes(facts, abi, (_, _) => false);
        foreach (var invalid in new[] { "", "contract", "source", "runtime", "tail" })
        {
            var returned = new Variable(Storage.Gpr(0), 1);
            var call = new Call(0x1000, invalid == "tail" ? CallKind.Tail : CallKind.Direct, Expr.C(producer.Method.Address, 64)) {
                Sources = invalid == "source" ? [] : [Storage.Gpr(1)],
                Arguments = invalid == "source" ? [] : [new FrameAddress(-32)], Results = [Storage.Gpr(0)], Defines = [returned] };
            var block = new Block(0x1000) { End = 0x1002, Statements = [call, new Return(0x1001) { Value = new Use(returned, 64) }] };
            var function = new MachineFunction { Entry = block.Start, Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            CallShape Shape(Call c) => invalid == "runtime" ? new(c with { Op = new(OpKind.NewObject, null) }, [], abi.Machine(producer, out _))
                : new(c, [producer], abi.Machine(producer, out _)! with { BufferPointerResult = invalid == "contract" ? null : Storage.Gpr(0) });
            Check(CallResultAliases.Run(function, Shape) == (invalid == ""), "仅显式 ABI 契约、正常托管调用和已知来源可建立别名");
            Check(!CallResultAliases.Run(function, Shape), "别名归一须幂等");
            Check(SsaCheck.Verify(function, Dominators.Compute(function)).Count == 0, "别名定义保持 SSA 不变量");
        }
        var recovery = new MethodDecompiler(facts, new ManagedTypes(model, facts.Layouts));
        var result = recovery.Recover(caller, caller.Method.Address);
        Check(result.Body is not null && result.Holes.Count == 0, "原生调用后的 [RAX+8] 须经过公共内存提升恢复：" + string.Join(";", result.Holes.Select(h => h.Reason)));
        Check(result.Body!.Blocks.SelectMany(b => b.Statements).SelectMany(ManagedValues.Of).SelectMany(ManagedValues.Walk)
            .OfType<FieldValue>().Any(f => f.Field.Field == aggregate.Fields[2]), "读取须对应返回结构的第三个字段，不能丢弃偏移");
        IcfAliasTests.Run(bytes, decoder, core);
        RuntimeIcallProofTests.Run(bytes, decoder, core);
        FreshConstructorTests.Run(bytes, decoder, core);
        StateComparisonTests.Run(core);
        StateConstantTests.Run(core);
        TypedReceiverTests.Run(bytes, decoder, core);
        LeafRecoveryTests.Run(bytes, decoder, core);
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

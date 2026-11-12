using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Model;
using Cpp2CS.Recovery;
using Cpp2CS.Recovery.Calls;
using Cpp2CS.Recovery.Typing;
using Cpp2CS.Recovery.Values;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class TypedReceiverTests
{
    internal static void Run(byte[] original, SleighDecoder decoder, TypeDef[] core)
    {
        const ulong entry = 0x180001080;
        foreach (var valueReceiver in new[] { false, true })
        foreach (var buffered in new[] { false, true })
        foreach (var invalid in new[] { "", "owner", "byref-reference", "register", "unknown", "metadata-read", "ambiguous", "exception" })
        {
            var bytes = original.ToArray();
            var code = invalid == "metadata-read" ? buffered ? "4C89C0C3" : "4889D0C3"
                : buffered ? "4889C848891148C7410800000000C3" : valueReceiver ? "8B4108C3" : "4889C8C3";
            System.Convert.FromHexString(code).CopyTo(bytes, 0x280);
            if (invalid == "exception") { bytes[0x740] = 9; System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x744), 0x1080); }
            TypeDef Type(int index, string name, bool value = false) => new() { Index = index, Assembly = "Fixture.dll", Namespace = "", Name = name,
                Token = (uint)(0x02000001 + index), Attributes = TypeAttributes.Public, IsValueType = value, IsEnum = false, Size = 16 };
            var owner = Type(core.Length, "Owner", valueReceiver); var other = Type(core.Length + 1, "Other"); var pair = Type(core.Length + 2, "Pair", true);
            var reference = new DefinitionRef(owner, []);
            var integer = new DefinitionRef(core.Single(t => t.Name == "Int32"), []);
            if (valueReceiver) owner.Fields = Enumerable.Range(0, 4).Select(i => new FieldDef { Index = i + 2, Owner = owner, Name = "v" + i,
                Type = integer, Attributes = FieldAttributes.Public, Offset = i * 4 }).ToArray();
            pair.Fields = Enumerable.Range(0, 2).Select(i => new FieldDef { Index = i, Owner = pair, Name = "p" + i, Type = reference,
                Attributes = FieldAttributes.Public, Offset = i * 8 }).ToArray();
            var target = MethodRef.Open(new MethodDef { Index = 0, Owner = owner, Name = "Read", Token = 0x06000001, Address = entry,
                Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1, ReturnType = buffered ? new DefinitionRef(pair, []) : valueReceiver ? integer : reference });
            var alternative = MethodRef.Open(new MethodDef { Index = 1, Owner = invalid == "ambiguous" ? owner : other, Name = "OtherRead", Token = 0x06000002, Address = entry,
                Attributes = MethodAttributes.Public | (invalid == "ambiguous" ? 0 : MethodAttributes.Static), ImplAttributes = 0, Slot = -1,
                ReturnType = target.Method.ReturnType });
            var caller = MethodRef.Open(new MethodDef { Index = 2, Owner = other, Name = "Caller", Token = 0x06000003,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1,
                Parameters = [new("value", invalid == "owner" ? new DefinitionRef(other, [])
                    : invalid == "byref-reference" ? valueReceiver ? reference : new ByRefRef(reference)
                    : valueReceiver ? new ByRefRef(reference) : reference, 0, null, false)] });
            var image = ImageDocument.Parse(bytes); var map = CodeMap.BuildPe(image, [entry]); var scan = CodeScan.Unscanned(map);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [], Types = [.. core, owner, other, pair],
                Methods = [target.Method, alternative.Method, caller.Method], Fields = [.. pair.Fields, .. owner.Fields], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [],
                StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            CodeEntry[] entries = [new(entry, EntryKind.Method, target, 0, null), new(entry, EntryKind.Method, alternative, 1, null)];
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries,
                ByAddress = new Dictionary<ulong, CodeEntry[]> { [entry] = entries }, Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
                MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = map, Scan = scan, Layouts = new FieldLayouts(model),
                Registrations = registrations, Helpers = RuntimeHelpers.Unclassified(map, scan), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var abi = facts.CreateAbi(); var shapes = new CallShapes(facts, abi, (_, _) => false);
            var environment = new MethodEnvironment(caller, abi.Machine(caller, out _)!, shapes);
            Expr receiver = invalid == "unknown" ? Expr.C(0, 64) : new Use(new Variable(Storage.Gpr(1), 0), 64);
            var arguments = buffered ? new Expr[] { new FrameAddress(-32), receiver, Expr.C(0, 64) } : [receiver, Expr.C(0, 64), Expr.C(0, 64)];
            if (invalid == "register") (arguments[buffered ? 1 : 0], arguments[2]) = (Expr.C(0, 64), receiver);
            var call = new Call(0x1000, CallKind.Direct, Expr.C(entry, 64)) { Sources = [Storage.Gpr(1), Storage.Gpr(2), Storage.Gpr(8)], Arguments = arguments };
            var block = new Block(0x1000) { End = 0x1002, Statements = [call, new Return(0x1001)] };
            var function = new MachineFunction { Entry = block.Start,
                Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            var values = ValueModel.Build(function, environment);
            var oracle = new TypeOracle(new ManagedTypes(model, facts.Layouts), facts, caller, _ => new(call, [target, alternative], null), values);
            var targets = DispatchResolution.Find(function, values, oracle);
            Check(invalid == "" ? targets.TryGetValue(call.Site, out var actual) && actual == target : targets.Count == 0,
                "混合签名消歧须核对 RCX/RDX、独立类型及未读 MethodInfo；错误类型、位置、歧义和异常均拒绝：" + invalid);
        }
    }

    private static void Check(bool condition, string reason) { if (!condition) throw new InvalidOperationException(reason); }
}

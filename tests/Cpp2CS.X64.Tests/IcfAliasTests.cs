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

internal static class IcfAliasTests
{
    internal static void Run(byte[] original, SleighDecoder decoder, TypeDef[] core)
    {
        const ulong entry = 0x180001080;
        foreach (var isStatic in new[] { false, true })
        foreach (var invalid in new[] { "", "metadata-read", "signature", "owner", "owner-no-init", "exception" })
        foreach (var reverse in new[] { false, true })
        foreach (var exact in new[] { false, true })
        {
            var bytes = original.ToArray();
            System.Convert.FromHexString(invalid == "metadata-read" ? "4889D0C3" : "4889C8C3").CopyTo(bytes, 0x280);
            if (invalid == "exception")
            {
                bytes[0x740] = 9;
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x744), 0x1080);
            }
            TypeDef Type(int index, string name, string assembly) => new() { Index = index, Assembly = assembly, Namespace = "", Name = name,
                Token = (uint)(0x02000001 + index), Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 };
            var owner = Type(core.Length, "Owner", "Library.dll");
            var callerOwner = Type(core.Length + 1, "Caller", "Caller.dll");
            var other = Type(core.Length + 2, "Other", "Library.dll");
            var reference = new DefinitionRef(owner, []);
            if (invalid == "owner") other.Methods = [new MethodDef { Index = 3, Owner = other, Name = ".cctor", Token = 0x06000004,
                Attributes = MethodAttributes.Static, ImplAttributes = 0, Slot = -1 }];
            MethodDef Method(int index, string name, bool accessible) => new() { Index = index, Owner = accessible && invalid is "owner" or "owner-no-init" ? other : owner, Name = name, Address = entry,
                Token = (uint)(0x06000001 + index), Attributes = (accessible ? MethodAttributes.Public : MethodAttributes.Private) | (isStatic ? MethodAttributes.Static : 0),
                ImplAttributes = 0, Slot = -1, ReturnType = reference,
                Parameters = isStatic ? [new("value", reference, 0, null, false)] : [] };
            var hidden = MethodRef.Open(Method(0, "Hidden", false));
            var visible = MethodRef.Open(Method(1, "Visible", true));
            if (invalid == "signature") visible.Method.ReturnType = new DefinitionRef(other, []);
            owner.Methods = [hidden.Method, visible.Method];
            var caller = MethodRef.Open(new MethodDef { Index = 2, Owner = callerOwner, Name = "Caller", Token = 0x06000003,
                Attributes = MethodAttributes.Static | MethodAttributes.Public, ImplAttributes = 0, Slot = -1, ReturnType = reference,
                Parameters = [new("value", reference, 0, null, false)] });
            var image = ImageDocument.Parse(bytes);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [], Types = [.. core, owner, callerOwner, other],
                Methods = [hidden.Method, visible.Method, caller.Method], Fields = [], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [],
                Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var map = CodeMap.BuildPe(image, [entry]);
            CodeEntry[] entries = [new(entry, EntryKind.Method, hidden, 0, null), new(entry, EntryKind.Method, visible, 1, null)];
            if (reverse) Array.Reverse(entries);
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries,
                ByAddress = new Dictionary<ulong, CodeEntry[]> { [entry] = entries }, Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
                MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = map, Scan = CodeScan.Unscanned(map), Registrations = registrations,
                Layouts = new FieldLayouts(model), Helpers = RuntimeHelpers.Unclassified(map, CodeScan.Unscanned(map)),
                MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var abi = facts.CreateAbi();
            var shapes = new CallShapes(facts, abi, (_, _) => false);
            var environment = new MethodEnvironment(caller, abi.Machine(caller, out _)!, shapes);
            var call = new Call(0x1000, CallKind.Direct, Expr.C(entry, 64)) {
                Sources = [Storage.Gpr(1), Storage.Gpr(2)],
                Arguments = [new Use(new Variable(Storage.Gpr(1), 0), 64), exact ? new Symbol(SymbolKind.Method, hidden) : Expr.C(0, 64)] };
            var block = new Block(0x1000) { End = 0x1002, Statements = [call, new Return(0x1001)] };
            var function = new MachineFunction { Entry = block.Start, Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            var values = ValueModel.Build(function, environment);
            var oracle = new TypeOracle(new ManagedTypes(model, facts.Layouts), facts, caller, environment.Shape, values);
            var actual = oracle.Callee(call);
            var expected = invalid == "" || isStatic && invalid == "owner-no-init" ? visible
                : exact || !isStatic && invalid is "owner" or "owner-no-init" ? hidden : null;
            Check(actual == expected, $"仅 MethodInfo 未用、同声明类型和同托管签名的原生等价候选可投影为合法调用：static={isStatic}, invalid={invalid}, reverse={reverse}, exact={exact}, actual={actual?.Method.Name ?? "null"}");
            if (!exact && (invalid == "" || isStatic && invalid == "owner-no-init")) Check(oracle.CallResolutions().Single().Status == "native-equivalent-projection",
                "没有确切 MethodInfo 时，报告必须区分等价投影与原始方法身份");
        }
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

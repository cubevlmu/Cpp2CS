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

internal static class FreshConstructorTests
{
    internal static void Run(byte[] original, SleighDecoder decoder, TypeDef[] core)
    {
        const ulong entry = 0x180001080;
        foreach (var inherited in new[] { false, true })
        foreach (var invalid in new[] { "", "thunk", "thunk-read", "thunk-this", "thunk-nonzero", "thunk-cycle", "receiver", "register", "native", "exception", "parameter", "owner", "entry", "signature" })
        {
            var bytes = original.ToArray();
            System.Convert.FromHexString(invalid == "native" ? "C60101C3" : "C3").CopyTo(bytes, 0x280);
            if (invalid.StartsWith("thunk", StringComparison.Ordinal))
            {
                var body = System.Convert.FromHexString(invalid switch {
                    "thunk-read" => "8B0233D2E937000000",
                    "thunk-this" => "33C9E939000000",
                    "thunk-nonzero" => "BA01000000E936000000",
                    "thunk-cycle" => "33D2E9F9FFFFFF",
                    _ => "33D2E939000000",
                });
                body.CopyTo(bytes, 0x280); bytes[0x2c0] = 0xc3;
            }
            if (invalid == "exception")
            {
                bytes[0x740] = 9;
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x744), 0x1080);
            }
            TypeDef Type(int index, string name) => new() { Index = index, Assembly = "Fixture.dll", Namespace = "", Name = name,
                Token = (uint)(0x02000001 + index), Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 };
            var owner = Type(core.Length, "Owner");
            var parent = Type(core.Length + 1, "Parent");
            var other = Type(core.Length + 2, "Other");
            owner.BaseType = new DefinitionRef(parent, []);
            var constructor = MethodRef.Open(new MethodDef { Index = 0, Owner = invalid == "owner" ? other : inherited ? parent : owner,
                Name = ".ctor", Address = invalid == "entry" ? entry + 1 : entry, Token = 0x06000001,
                Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1,
                Parameters = invalid == "parameter" ? [new("value", new DefinitionRef(owner, []), 0, null, false)] : [] });
            var caller = MethodRef.Open(new MethodDef { Index = 1, Owner = owner, Name = "Make", Token = 0x06000002,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1 });
            var image = ImageDocument.Parse(bytes);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [], Types = [.. core, owner, parent, other],
                Methods = [constructor.Method, caller.Method], Fields = [], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [],
                Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var map = CodeMap.BuildPe(image, [entry, entry + 0x40]);
            var scan = CodeScan.Unscanned(map);
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = map, Scan = scan, Layouts = new FieldLayouts(model),
                Helpers = RuntimeHelpers.Unclassified(map, scan), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var abi = facts.CreateAbi();
            var shapes = new CallShapes(facts, abi, (_, _) => false);
            var environment = new MethodEnvironment(caller, abi.Machine(caller, out _)!, shapes);
            var allocated = new Variable(Storage.Gpr(0), 1);
            var allocation = new Call(0x1000, CallKind.Direct, Expr.C(0x2000, 64)) { Op = new(OpKind.NewObject, new DefinitionRef(owner, [])),
                Results = [Storage.Gpr(0)], Defines = [allocated] };
            var call = new Call(0x1001, CallKind.Direct, Expr.C(entry, 64)) { Sources = [Storage.Gpr(1), Storage.Gpr(2)],
                Arguments = invalid == "register" ? [Expr.C(0, 64), new Use(allocated, 64)]
                    : [invalid == "receiver" ? new Use(new Variable(Storage.Gpr(1), 0), 64) : new Use(allocated, 64), Expr.C(0, 64)] };
            var block = new Block(0x1000) { End = 0x1003, Statements = [allocation, call, new Return(0x1002)] };
            var function = new MachineFunction { Entry = block.Start,
                Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            var values = ValueModel.Build(function, environment);
            CallShape Shape(Call c) => ReferenceEquals(c, call)
                ? new(c, [constructor], invalid == "signature" ? abi.Machine(constructor, out _) : null) : environment.Shape(c);
            var oracle = new TypeOracle(new ManagedTypes(model, facts.Layouts), facts, caller, Shape, values);
            var targets = DispatchResolution.Find(function, values, oracle);
            Check(invalid is "" or "thunk" ? targets.TryGetValue(call.Site, out var actual) && actual == constructor : !targets.ContainsKey(call.Site),
                "共享空构造须核对新分配结果、RCX、确切继承链、无参签名、原生入口及异常边界：" + invalid);
        }
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

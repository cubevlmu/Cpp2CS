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

internal static class GenericReceiverSelectionTests
{
    internal static void Run(byte[] original, SleighDecoder decoder, TypeDef[] core)
    {
        foreach (var variant in new[] { "valid", "tail", "inherited", "reverse", "missing", "thunk", "address", "noncanonical", "indirect", "dispatch", "argument", "unknown", "exact", "ambiguous", "ambiguous-reverse" })
        {
            const ulong entry = 0x180001080;
            var bytes = original.ToArray(); bytes[0x280] = 0xc3;
            TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
            TypeDef Define(int i, string name) => new() { Index = core.Length + i, Assembly = "Fixture.dll", Namespace = "Fixture", Name = name,
                Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16, BaseType = Corlib("Object") };
            var box = Define(0, "Box`1"); var other = Define(1, "Other"); var callerOwner = Define(2, "Caller"); var child = Define(3, "Child");
            var parameter = new GenericParameterDef { Name = "T", Position = 0, Attributes = GenericParameterAttributes.ReferenceTypeConstraint };
            box.GenericParameters = [parameter];
            var exactOwner = new DefinitionRef(box, [Corlib("String")]); child.BaseType = exactOwner;
            MethodDef Use(int index, TypeDef owner, TypeRef argument) => new() { Index = index, Owner = owner, Name = "Use", Token = (uint)(0x06000001 + index),
                Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void"), Parameters = [new("value", argument, 0, null, false)] };
            var wrong = MethodRef.Open(Use(0, other, Corlib("Object")));
            var alias = MethodRef.Open(Use(3, other, Corlib("Object")));
            if (variant.StartsWith("ambiguous", StringComparison.Ordinal)) exactOwner = new DefinitionRef(other, []);
            var definition = Use(1, box, new GenericParameterRef("T", false, 0) { Parameter = parameter });
            var canonical = new MethodRef(definition, [Corlib(variant == "noncanonical" ? "String" : "Object")], []);
            if (variant == "noncanonical") exactOwner = new DefinitionRef(box, [new DefinitionRef(callerOwner, [])]);
            var caller = MethodRef.Open(new MethodDef { Index = 2, Owner = callerOwner, Name = "Run", Token = 0x06000003,
                Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = Corlib("Void"),
                Parameters = [new("receiver", variant == "unknown" ? Corlib("Object") : variant == "inherited" ? new DefinitionRef(child, []) : exactOwner, 0, null, false),
                    new("value", Corlib(variant == "argument" ? "Object" : "String"), 0, null, false)] });
            var entries = variant == "missing" ? Array.Empty<CodeEntry>() : new[] {
                new CodeEntry(variant == "address" ? entry + 1 : entry, variant == "thunk" ? EntryKind.AdjustorThunk : EntryKind.GenericMethod, canonical, 0, null) };
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries,
                ByAddress = entries.GroupBy(e => e.Address).ToDictionary(g => g.Key, g => g.ToArray()), Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
                MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() };
            var image = ImageDocument.Parse(bytes); var code = CodeMap.BuildPe(image, [entry]);
            var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [], Types = [.. core, box, other, callerOwner, child],
                Methods = [wrong.Method, definition, caller.Method, alias.Method], Fields = [], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [],
                Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = code, Scan = CodeScan.Unscanned(code), Registrations = registrations,
                Layouts = new FieldLayouts(model), MachineFactory = () => new PcodeMachine(image, decoder) }, new());
            var abi = facts.CreateAbi(); var shapes = new CallShapes(facts, abi, (_, _) => false);
            var environment = new MethodEnvironment(caller, abi.Machine(caller, out _)!, shapes);
            var call = new Call(0x1000, variant == "tail" ? CallKind.Tail : variant == "indirect" ? CallKind.Indirect : CallKind.Direct, Expr.C(entry, 64)) {
                Sources = [Storage.Gpr(1), Storage.Gpr(2), Storage.Gpr(8)],
                Arguments = [new Use(new Variable(Storage.Gpr(1), 0), 64), new Use(new Variable(Storage.Gpr(2), 0), 64),
                    variant == "exact" ? new Symbol(SymbolKind.Method, wrong) : Expr.C(0, 64)],
                Op = variant == "dispatch" ? new(OpKind.CallMethodPointer, canonical) : null };
            var block = new Block(0x1000) { End = 0x1002, Statements = [call, new Return(0x1001)] };
            var function = new MachineFunction { Entry = block.Start, Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            var values = ValueModel.Build(function, environment);
            MethodRef[] candidates = variant == "reverse" ? [canonical, wrong] : [wrong, canonical];
            if (variant.StartsWith("ambiguous", StringComparison.Ordinal)) candidates = variant == "ambiguous" ? [wrong, alias] : [alias, wrong];
            var oracle = new TypeOracle(new ManagedTypes(model, facts.Layouts), facts, caller, c => new(c, candidates, abi.Machine(wrong, out _)), values);
            var chosen = oracle.Callee(call);
            var expected = variant is "valid" or "tail" or "inherited" or "reverse";
            Check(expected ? chosen?.Method == definition && chosen.TypeArguments.Single().Equals(Corlib("String")) : variant == "exact" ? chosen == wrong : chosen is null,
                "普通泛型实例候选须先核对共享注册与 ABI，再保留参数兼容性及确切 MethodInfo 优先级：" + variant);
        }
        Console.WriteLine("普通泛型接收者选择测试通过：继承、尾调用和候选顺序；缺少登记、调整桩、错误地址、非共享实参、间接分派、参数冲突及未知类型拒绝，确切 MethodInfo 优先");
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

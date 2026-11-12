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

namespace Cpp2CS.X64.Tests;

internal static class DispatchTests
{
    internal static void Run(BaseFacts basis)
    {
        TypeDef Type(int index, string name, bool value, int size, bool iface = false) => new() {
            Index = index, Assembly = "Fixture.dll", Namespace = "", Name = name, Token = (uint)(0x02000001 + index),
            Attributes = TypeAttributes.Public | (iface ? TypeAttributes.Interface | TypeAttributes.Abstract : 0), IsValueType = value, IsEnum = false, Size = size };
        var owner = Type(0, "Owner", false, 16);
        var pair = Type(1, "Pair", true, 16);
        var contract = Type(20, "Contract", false, 16, true);
        var interfaceMethod = new MethodDef { Index = 2, Owner = contract, Name = "Read", Token = 0x06000003,
            Attributes = MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.Abstract, ImplAttributes = 0, Slot = 0 };
        contract.Methods = [interfaceMethod]; owner.Interfaces = [new DefinitionRef(contract, [])];
        var coreNames = new[] { "Object", "String", "Boolean", "Char", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64",
            "Single", "Double", "IntPtr", "RuntimeTypeHandle", "RuntimeFieldHandle", "RuntimeMethodHandle" };
        var core = coreNames.Select((name, i) => new TypeDef { Index = i + 2, Assembly = "mscorlib.dll", Namespace = "System", Name = name,
            Token = (uint)(0x02000003 + i), Attributes = TypeAttributes.Public, IsValueType = name is not ("Object" or "String"),
            IsEnum = false, Size = 8 }).ToArray();
        pair.Fields = Enumerable.Range(0, 2).Select(i => new FieldDef { Index = i, Owner = pair, Name = "p" + i,
            Type = new PointerRef(new PrimitiveRef("void")), Attributes = FieldAttributes.Public, Offset = i * 8 }).ToArray();
        var virtualMethod = new MethodDef { Index = 0, Owner = owner, Name = "Read", Token = 0x06000001,
            Attributes = MethodAttributes.Public | MethodAttributes.Virtual, ImplAttributes = 0, Slot = 0 };
        owner.Methods = [virtualMethod];
        var caller = new MethodRef(new MethodDef { Index = 1, Owner = owner, Name = "Caller", Token = 0x06000002,
            Attributes = MethodAttributes.Static, ImplAttributes = 0, Slot = -1,
            Parameters = [new("value", new DefinitionRef(owner, []), 0, null, false)] }, [], []);
        var model = new ProgramModel { Image = basis.Model.Image, MetadataVersion = 31, Assemblies = [], Types = [owner, pair, contract, .. core],
            Fields = pair.Fields, Methods = [virtualMethod, caller.Method, interfaceMethod], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [],
            StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
        foreach (var buffered in new[] { false, true })
        foreach (var invalid in new[] { "", "receiver", "layout", "method-info" })
        {
            virtualMethod.ReturnType = buffered ? new DefinitionRef(pair, []) : new PrimitiveRef("void");
            var facts = new ProgramFacts(basis with { Model = model, Layouts = new FieldLayouts(model),
                RuntimeOffsets = new(null, null, "独立布局见证") { ClassVtable = invalid == "layout" ? null : 0x180 } }, new());
            var abi = facts.CreateAbi();
            var expected = abi.Machine(new MethodRef(virtualMethod, [], []), out _)!.This!.Pieces[0].Register;
            Check(expected == Storage.Gpr(buffered ? 2 : 1), "Win64 返回缓冲区决定 this 位置");
            var shapes = new CallShapes(facts, abi, (_, _) => false);
            var environment = new MethodEnvironment(caller, abi.Machine(caller, out _)!, shapes);
            Expr receiver = new Use(new Variable(Storage.Gpr(1), 0), 64);
            var sources = new[] { Storage.Gpr(0), Storage.Gpr(1), Storage.Gpr(2) };
            var call = new Call(0x1000, CallKind.Indirect,
                new Load(new Binary(BinOp.Add, new Load(receiver, 64), Expr.C(invalid == "method-info" ? 0x188UL : 0x180UL, 64), 64), 64)) {
                Sources = sources, Arguments = sources.Select(s => s == Storage.Gpr(0) || s == expected && invalid != "receiver" ? receiver : Expr.C(0, 64)).ToArray() };
            var block = new Block(0x1000) { End = 0x1002 };
            block.Statements.Add(call); block.Statements.Add(new Return(0x1001));
            var function = new MachineFunction { Entry = block.Start,
                Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            var values = ValueModel.Build(function, environment);
            var resolved = DispatchResolution.Find(function, values, new TypeOracle(new ManagedTypes(model, facts.Layouts), facts, caller, environment.Shape, values));
            Check(invalid == "" ? resolved.TryGetValue(call.Site, out var method) && method.Method == virtualMethod : resolved.Count == 0,
                "虚表对象与 ABI 实参必须相同；拒绝 RAX 假接收者、未知布局和 MethodInfo 槽调用");
        }
        var interfaceFacts = new ProgramFacts(basis with { Model = model, Layouts = new FieldLayouts(model) }, new());
        var interfaceAbi = interfaceFacts.CreateAbi();
        foreach (var same in new[] { true, false })
        {
            var shapes = new CallShapes(interfaceFacts, interfaceAbi, (_, _) => false);
            var environment = new MethodEnvironment(caller, interfaceAbi.Machine(caller, out _)!, shapes);
            Expr instance = new Use(new Variable(Storage.Gpr(1), 0), 64);
            var data = new Variable(Storage.Gpr(0), 1);
            var lookup = new Call(0x1000, CallKind.Direct, Expr.C(0x2000, 64)) {
                Op = new RuntimeOp(OpKind.InterfaceInvokeData, ((object?)new DefinitionRef(contract, []), 0)),
                Arguments = [instance, new Symbol(SymbolKind.Class, new DefinitionRef(contract, [])), Expr.C(0, 16)],
                Results = [Storage.Gpr(0)], Defines = [data] };
            var invoke = new Call(0x1001, CallKind.Indirect, new Load(new Use(data, 64), 64)) {
                Sources = [Storage.Gpr(0), Storage.Gpr(1)], Arguments = [instance, same ? instance : Expr.C(0, 64)] };
            var block = new Block(0x1000) { End = 0x1003 };
            block.Statements.AddRange([lookup, invoke, new Return(0x1002)]);
            var function = new MachineFunction { Entry = block.Start,
                Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            var values = ValueModel.Build(function, environment);
            var targets = DispatchResolution.Find(function, values, new TypeOracle(new ManagedTypes(model, interfaceFacts.Layouts), interfaceFacts, caller, environment.Shape, values));
            Check(same ? targets.ContainsKey(invoke.Site) : targets.Count == 0, "接口查找对象必须与最终 ABI 的 this 一致");
        }
        MethodRef Direct(int index, bool parameter) => MethodRef.Open(new MethodDef { Index = index, Owner = owner, Name = "Direct" + index,
            Token = (uint)(0x06000001 + index), Attributes = MethodAttributes.Static | MethodAttributes.Public, ImplAttributes = 0, Slot = -1,
            Parameters = parameter ? [new("value", new DefinitionRef(owner, []), 0, null, false)] : [] });
        var directA = Direct(3, false); var directB = Direct(4, true);
        foreach (var invalid in new[] { "", "caller", "register", "conflict" })
        {
            var temporary = new Variable(Storage.Temp(2000), 1);
            var call = new Call(0x1001, CallKind.Direct, Expr.C(0x2000, 64)) { Sources = [Storage.Gpr(1), Storage.Gpr(2)],
                Arguments = invalid == "register" ? [new Use(temporary, 64), Expr.C(0, 64)]
                    : [invalid == "conflict" ? new Symbol(SymbolKind.Method, directA) : Expr.C(0, 64), new Use(temporary, 64)] };
            var block = new Block(0x1000) { End = 0x1003, Statements = [new Define(0x1000, temporary,
                new Symbol(SymbolKind.Method, invalid == "caller" ? caller : directB)), call, new Return(0x1002)] };
            var function = new MachineFunction { Entry = block.Start, Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            var shapes = new CallShapes(interfaceFacts, interfaceAbi, (_, _) => false);
            var values = ValueModel.Build(function, new MethodEnvironment(caller, interfaceAbi.Machine(caller, out _)!, shapes));
            var oracle = new TypeOracle(new ManagedTypes(model, interfaceFacts.Layouts), interfaceFacts, caller, c => new(c, [directA, directB], null), values);
            var targets = DispatchResolution.Find(function, values, oracle);
            Check(invalid == "" ? targets.TryGetValue(call.Site, out var selected) && selected == directB : targets.Count == 0,
                "SSA 中的确切 MethodInfo 须属于候选且位于其隐藏参数寄存器；调用者残值、错误位置及多重身份拒绝");
        }
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.InteropServices;
using Cpp2CS.Facts;
using Cpp2CS.Idioms;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Model;
using Cpp2CS.Output;
using Cpp2CS.Recovery;
using Cpp2CS.Recovery.Calls;
using Mono.Cecil.Cil;

namespace Cpp2CS.X64.Tests;

internal static class InvokerTests
{
    [UnmanagedFunctionPointer(System.Runtime.InteropServices.CallingConvention.Cdecl)]
    private delegate void NativeInvoker(nint pointer, nint info, nint receiver, nint arguments, nint output);

    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        const ulong basis = 0x180000000;
        var invokerCode = System.Convert.FromHexString("534883EC20488B5C24504989CB498B018B0841FFD389034883C4205BC3");
        var targetCode = System.Convert.FromHexString("8D444907C3");
        var refInvokerCode = System.Convert.FromHexString("4883EC284989CB498B0941FFD34883C428C3");
        var refTargetCode = System.Convert.FromHexString("83010BC3");
        if (OperatingSystem.IsWindows() && RuntimeInformation.ProcessArchitecture == System.Runtime.InteropServices.Architecture.X64)
            foreach (var byref in new[] { false, true })
            HardwareTests.WithCode(byref ? refTargetCode : targetCode, target => HardwareTests.WithCode(byref ? refInvokerCode : invokerCode, invoke =>
            {
                var allocation = Marshal.AllocHGlobal(24);
                try
                {
                    var native = Marshal.GetDelegateForFunctionPointer<NativeInvoker>(invoke);
                    Marshal.WriteIntPtr(allocation, allocation + 8);
                    foreach (var number in Numbers)
                    {
                        Marshal.WriteInt32(allocation + 8, number); Marshal.WriteInt32(allocation + 16, -123);
                        native(target, 0, 0, allocation, allocation + 16);
                        Check(byref ? Marshal.ReadInt32(allocation + 8) == unchecked(number + 11) && Marshal.ReadInt32(allocation + 16) == -123
                            : Marshal.ReadInt32(allocation + 16) == unchecked(number * 3 + 7), "原生 invoker 分别保持 ref 写入与独立返回存储");
                    }
                }
                finally { Marshal.FreeHGlobal(allocation); }
            }));

        foreach (var variant in new[] { "direct", "indirect", "ref-void", "wrong-pointer", "wrong-info", "unknown-layout", "wrong-invoker", "wrong-version" })
        {
            var byref = variant == "ref-void";
            var invokerBody = byref ? refInvokerCode : invokerCode;
            var targetBody = byref ? refTargetCode : targetCode;
            var bytes = original.ToArray();
            var code = new List<byte>();
            void Emit(string hex) => code.AddRange(System.Convert.FromHexString(hex));
            void Relative(string opcode, ulong target)
            {
                Emit(opcode); var after = basis + 0x1000 + (ulong)code.Count + 4;
                var displacement = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(displacement, checked((int)((long)target - (long)after)));
                code.AddRange(displacement);
            }
            // 参数副本、参数数组和返回存储是三个不同的局部；第五参数放在调用点 SP+32。
            Emit("4883EC58894C2438488D4424384889442430488D44244048894424204C8D4C24304533C0");
            Relative("488B15", basis + (variant == "wrong-info" ? 0x2008UL : 0x2000UL));
            if (variant == "wrong-pointer") Emit("31C9");
            else if (variant is "indirect" or "unknown-layout") Emit("488B0A");
            else Relative("488D0D", basis + 0x1100);
            if (variant == "indirect" || variant == "unknown-layout") Emit("FF5210");
            else Relative("E8", basis + 0x1080);
            Emit(byref ? "8B4424384883C458C3" : "8B4424404883C458C3");
            var callerCode = code.ToArray(); callerCode.CopyTo(bytes, 0x200); invokerBody.CopyTo(bytes, 0x280); targetBody.CopyTo(bytes, 0x300);
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            U32(0x124, 36);
            foreach (var (index, start, length) in new[] { (0, 0x1000, callerCode.Length), (1, 0x1080, invokerBody.Length), (2, 0x1100, targetBody.Length) })
            {
                U32(0x700 + index * 12, (uint)start); U32(0x704 + index * 12, (uint)(start + length)); U32(0x708 + index * 12, (uint)(0x3140 + index * 8));
                bytes[0x740 + index * 8] = 1;
            }
            var names = new[] { "Void", "Boolean", "Char", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64", "Single", "Double",
                "String", "TypedReference", "IntPtr", "UIntPtr", "Object", "ValueType", "RuntimeTypeHandle", "RuntimeFieldHandle", "RuntimeMethodHandle", "NullReferenceException" };
            var core = names.Select((name, i) => new TypeDef { Index = i, Assembly = "mscorlib.dll", Namespace = "System", Name = name,
                Token = (uint)(0x02000001 + i), Attributes = TypeAttributes.Public, IsValueType = name is not ("String" or "Object" or "ValueType" or "NullReferenceException"),
                IsEnum = false, Size = name == "Int32" ? 4 : 8 }).ToArray();
            TypeRef Corlib(string name) => new DefinitionRef(core.Single(t => t.Name == name), []);
            var name = "Invoker" + variant;
            var module = new TypeDef { Index = core.Length, Assembly = name + ".dll", Namespace = "", Name = "<Module>", Token = 0x02000001,
                Attributes = TypeAttributes.NotPublic, IsValueType = false, IsEnum = false, Size = 0 };
            var owner = new TypeDef { Index = core.Length + 1, Assembly = module.Assembly, Namespace = "Fixture", Name = "Reader", Token = 0x02000002,
                Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16, BaseType = Corlib("Object") };
            MethodDef Method(int index, string methodName, ulong entry) => new() { Index = index, Owner = owner, Name = methodName, Address = entry,
                Token = (uint)(0x06000001 + index), Attributes = MethodAttributes.Public | MethodAttributes.Static, ImplAttributes = 0, Slot = -1,
                ReturnType = Corlib("Int32"), Parameters = [new("number", Corlib("Int32"), 0, null, false)] };
            var caller = Method(0, "Run", basis + 0x1000); var callee = Method(1, "Transform", basis + 0x1100);
            if (byref)
            {
                callee.ReturnType = Corlib("Void");
                callee.Parameters = [new("number", new ByRefRef(Corlib("Int32")), 0, null, false)];
            }
            owner.Methods = [caller, callee];
            var nullType = core.Single(t => t.Name == "NullReferenceException");
            var nullConstructor = new MethodDef { Index = 2, Owner = nullType, Name = ".ctor", Token = 0x06000001,
                Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1 };
            nullType.Methods = [nullConstructor];
            var image = ImageDocument.Parse(bytes);
            var model = new ProgramModel { Image = image, MetadataVersion = variant == "wrong-version" ? 29 : 31,
                Assemblies = [new() { Name = "mscorlib.dll", AssemblyName = "mscorlib", Version = new(4, 0, 0, 0), Culture = "", PublicKey = [], Types = core },
                    new() { Name = module.Assembly, AssemblyName = name, Version = new(1, 0, 0, 0), Culture = "", PublicKey = [], Types = [module, owner] }],
                Types = [.. core, module, owner], Methods = [caller, callee, nullConstructor], Fields = [], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [],
                Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
            CodeEntry[] entries = [new(caller.Address, EntryKind.Method, MethodRef.Open(caller), 0, null), new(callee.Address, EntryKind.Method, MethodRef.Open(callee), 1, null),
                new(basis + 0x1080, EntryKind.Invoker, null, 7, null)];
            var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = entries,
                ByAddress = entries.GroupBy(e => e.Address).ToDictionary(g => g.Key, g => g.ToArray()),
                Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(), MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(),
                InvokerOf = new Dictionary<MethodDef, int> { [callee] = variant == "wrong-invoker" ? 8 : 7 } };
            var map = CodeMap.BuildPe(image, [caller.Address, callee.Address]); var scan = CodeScan.Unscanned(map);
            var usages = new UsageSlots { Slots = new Dictionary<ulong, UsageSlot> {
                [basis + 0x2000] = new(basis + 0x2000, new(UsageKind.MethodDef, 1, MethodRef.Open(callee)), 1, 0),
                [basis + 0x2008] = new(basis + 0x2008, new(UsageKind.MethodDef, 0, MethodRef.Open(caller)), 1, 0) },
                UnreferencedDecodable = new Dictionary<ulong, Usage>(), SlotAddressBeforeCall = new Dictionary<ulong, int>() };
            var facts = new ProgramFacts(new BaseFacts { Model = model, Code = map, Scan = scan, Registrations = registrations, Usages = usages,
                Layouts = new(model), Helpers = RuntimeHelpers.Unclassified(map, scan), Checks = new(), MachineFactory = () => new PcodeMachine(image, decoder),
                RuntimeOffsets = variant == "unknown-layout" ? null : new(null, null, "独立 MethodInfo 布局契约") { MethodPointer = 0, MethodVirtualPointer = 8, MethodInvoker = 16 } }, new());
            var types = new ManagedTypes(model, facts.Layouts); var recovery = new MethodDecompiler(facts, types);
            Contracts(facts, types, MethodRef.Open(callee));
            if (variant == "direct") DispatchContracts(facts, types);
            var result = recovery.Recover(MethodRef.Open(caller), caller.Address);
            if (variant is not ("direct" or "indirect" or "ref-void"))
            {
                Check(result.Body is null && result.Holes.Count > 0, "未证明的 invoker 绑定必须保留洞：" + variant); continue;
            }
            Check(result.Body is not null && result.Holes.Count == 0, "invoker 完整恢复：" + variant + " " + string.Join(';', result.Holes.Select(h => h.Reason)));
            var skeleton = new Skeleton(model);
            var targetIl = skeleton.Method(callee).Body.GetILProcessor(); targetIl.Body.Instructions.Clear();
            targetIl.Emit(OpCodes.Ldarg_0);
            if (byref)
            {
                targetIl.Emit(OpCodes.Dup); targetIl.Emit(OpCodes.Ldind_I4); targetIl.Emit(OpCodes.Ldc_I4, 11); targetIl.Emit(OpCodes.Add); targetIl.Emit(OpCodes.Stind_I4);
            }
            else { targetIl.Emit(OpCodes.Ldc_I4_3); targetIl.Emit(OpCodes.Mul); targetIl.Emit(OpCodes.Ldc_I4_7); targetIl.Emit(OpCodes.Add); }
            targetIl.Emit(OpCodes.Ret);
            Check(new BodyEmitter(skeleton, types).Emit([result.Body!]).Count == 0, "公共 CIL 检查通过");
            using var stream = new MemoryStream(); skeleton.Assembly(module.Assembly).Write(stream);
            var run = Assembly.Load(stream.ToArray()).GetType("Fixture.Reader", true)!.GetMethod("Run")!;
            foreach (var number in Numbers) Check((int)run.Invoke(null, [number])! == (byref ? unchecked(number + 11) : unchecked(number * 3 + 7)), "拆包结果保持原生值、ref 效果和独立返回存储");
        }
        Console.WriteLine("Win64 invoker：原生五参数 ABI、直接／间接完整恢复和 CIL/CLR 对照，错误指针／身份／注册／版本／布局拒绝通过");
    }

    private static readonly int[] Numbers = [int.MinValue, -123, -1, 0, 1, 17, int.MaxValue];

    private static void Contracts(ProgramFacts facts, ManagedTypes types, MethodRef method)
    {
        // 拆包后的编号是公共 IR 契约，不应再次套用物理 Win64 寄存器分配。
        var definition = new MethodDef { Index = 7, Owner = method.Method.Owner, Name = "Contract", Token = 0x06000008,
            Attributes = MethodAttributes.Public, ImplAttributes = 0, Slot = -1, ReturnType = types.String,
            Parameters = [new("number", types.Int32, 0, null, false), new("reference", types.Object, 0, null, false),
                new("output", new ByRefRef(types.Single), ParameterAttributes.Out, null, false)] };
        var member = MethodRef.Open(definition);
        var x64 = new ManagedAbi(facts.Layouts, Cpp2CS.Model.Architecture.X64).Invoker(member);
        var arm = new ManagedAbi(facts.Layouts).Invoker(member);
        Check(CallShapes.SameShape(x64, arm), "拆包签名与 ARM64 使用相同公共表示");
        Check(x64.This is { Transfer: Transfer.Value } && x64.Arguments[1] is { Transfer: Transfer.Copy, Size: 4, Access: MemoryAccess.Read }
            && x64.Arguments[2] is { Transfer: Transfer.Value } && x64.Arguments[3] is { Transfer: Transfer.Reference, Size: 4, Access: MemoryAccess.Write }
            && x64.Return is { Transfer: Transfer.ResultBuffer, Size: 8, Access: MemoryAccess.Write }, "引用、值副本、out 和引用返回存储分别保留");
        var abi = new ManagedAbi(facts.Layouts, Cpp2CS.Model.Architecture.X64);
        var constrained = abi.ConstrainedInvoker(types.Int32, member);
        Check(constrained.This is { Transfer: Transfer.Reference, Type: ByRefRef, Size: 4, Access: MemoryAccess.ReadWrite }, "受约束接收者是存储地址");
        definition.ReturnType = new PrimitiveRef("void");
        Check(abi.Invoker(member).Return is null, "void invoker 不制造返回缓冲区");
        definition.Parameters = Enumerable.Range(0, 12).Select(i => new ParameterDef("p" + i, types.Int32, 0, null, false)).ToArray();
        var many = abi.Invoker(member);
        Check(many.Arguments.Length == 13 && many.Arguments.SelectMany(a => a.Pieces).All(p => p.Register.Bank == Bank.Gpr)
            && many.MethodInfo?.Register == Storage.Gpr(13), "拆包参数数量不受四个物理寄存器限制");
    }

    private static void DispatchContracts(ProgramFacts facts, ManagedTypes types)
    {
        var contract = new TypeDef { Index = 70, Assembly = "Fixture.dll", Namespace = "Fixture", Name = "IContract", Token = 0x02000003,
            Attributes = TypeAttributes.Public | TypeAttributes.Interface | TypeAttributes.Abstract, IsValueType = false, IsEnum = false, Size = 16 };
        var type = new DefinitionRef(contract, []);
        var definition = new MethodDef { Index = 70, Owner = contract, Name = "Read", Token = 0x06000003, Slot = 1, ImplAttributes = 0,
            Attributes = MethodAttributes.Public | MethodAttributes.Abstract | MethodAttributes.Virtual, ReturnType = types.Int32,
            Parameters = [new("number", types.Int32, 0, null, false)] };
        contract.Methods = [definition];
        var method = MethodRef.Open(definition);
        Expr Offset(Expr value, int offset) => new Binary(BinOp.Add, value, Expr.C((ulong)offset, 64), 64);
        MachineFunction Function(Block block) => new() { Entry = 0, Range = new(0, 16, CodeRegion.Managed, default), Blocks = [block] };
        foreach (var sameReceiver in new[] { true, false })
        {
            var receiver = new Variable(Storage.Gpr(3), 0); var other = new Variable(Storage.Gpr(6), 0);
            var data = new Variable(Storage.Temp(1800), 1);
            var info = new Load(Offset(new Use(data, 64), RuntimeLayout.VirtualInvokeDataMethod), 64);
            var lookup = new Call(0, CallKind.Direct, Expr.C(0, 64)) { Op = new(OpKind.InterfaceInvokeData, ((object?)type, 1)),
                Arguments = [new Use(receiver, 64), new Symbol(SymbolKind.Class, type), Expr.C(1, 64)], Results = [data.Storage], Defines = [data] };
            // 非默认字段位置用于验证消费的是后端布局契约。
            var call = new Call(4, CallKind.Indirect, new Load(Offset(info, 0x30), 64)) {
                Arguments = [new Load(Offset(info, 0x20), 64), info, new Use(sameReceiver ? receiver : other, 64), new FrameAddress(-32)],
                Sources = [Storage.Gpr(1), Storage.Gpr(2), Storage.Gpr(8), Storage.Gpr(9)], StackPointer = new FrameAddress(-80) };
            var block = new Block(0) { Statements = [lookup, call, new Return(8)] };
            var scoped = new ProgramFacts(facts.Base with { RuntimeOffsets = new(null, null, "独立分派布局契约") {
                MethodPointer = 0, MethodVirtualPointer = 0x20, MethodInvoker = 0x30 } }, new());
            var state = new IdiomState(new IdiomRewriter(scoped), Function(block));
            Check(state.InvokerCalls() == sameReceiver, "分派得到的 MethodInfo 必须用于同一接收者");
            if (sameReceiver)
            {
                var normalized = block.Statements.OfType<Call>().Single(c => c.Op?.Kind == OpKind.InvokeVirtualGeneric);
                var shape = new CallShapes(scoped, scoped.CreateAbi(), (_, _) => false).Of(normalized);
                Check(shape is { IsDispatch: true, IsRuntime: false, Signature.Return.Transfer: Transfer.ResultBuffer }
                    && normalized.Arguments[0] == new Use(receiver, 64)
                    && normalized.Arguments[^1] == new Load(new FrameAddress(-48), 64), "分派保持接收者与 SP+32 的返回存储");
            }
        }
        foreach (var sameConstraint in new[] { true, false })
        {
            const ulong helper = 0x180001080;
            var helpers = RuntimeHelpers.FromEvidence(facts.Code, facts.Scan, [new(helper, HelperKind.ConstrainedCall, null, "独立 helper 契约", 1)]);
            var scoped = new ProgramFacts(facts.Base with { Helpers = helpers }, new());
            var call = new Call(0, CallKind.Direct, Expr.C(helper, 64)) {
                Arguments = [new Symbol(SymbolKind.Class, sameConstraint ? types.Int32 : types.Object), new Symbol(SymbolKind.Constrained, ((TypeRef)types.Int32, method)),
                    new FrameAddress(-64), new FrameAddress(-32)],
                Sources = [Storage.Gpr(1), Storage.Gpr(2), Storage.Gpr(8), Storage.Gpr(9)], StackPointer = new FrameAddress(-80) };
            var block = new Block(0) { Statements = [call, new Return(4)] };
            Check(new IdiomState(new IdiomRewriter(scoped), Function(block)).InvokerCalls() == sameConstraint, "约束类必须与约束方法实体一致");
            if (!sameConstraint) continue;
            var normalized = block.Statements.OfType<Call>().Single();
            Check(normalized.Op?.Kind == OpKind.InvokeConstrainedGeneric
                && normalized.Arguments[0] == new FrameAddress(-32)
                && normalized.Arguments[1] is Load { Address: Load { Address: FrameAddress { Offset: -48 } } }
                && normalized.Arguments[^1] == new Load(new FrameAddress(-40), 64), "受约束调用分别从 SP+32／SP+40 取第五／第六指针");
        }
    }

    private static void Check(bool valid, string reason) { if (!valid) throw new InvalidOperationException(reason); }
}

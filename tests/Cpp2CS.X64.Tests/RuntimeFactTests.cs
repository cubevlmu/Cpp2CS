using System.Buffers.Binary;
using System.Text;
using Cpp2CS.Facts;
using Cpp2CS.Idioms;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Lifting;
using Cpp2CS.Model;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class RuntimeFactTests
{
    public static void Run(byte[] original, SleighDecoder decoder)
    {
        var bytes = original.ToArray();
        var sections = bytes.AsSpan(0x128, 120).ToArray();
        Array.Clear(bytes, 0x128, 80);
        sections.CopyTo(bytes, 0x178);
        void U16(int at, ushort value) => BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(at), value);
        void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
        void U64(int at, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(at), value);
        const ulong basis = 0x180000000;
        U16(0x94, 224); U32(0x104, 14);
        U32(0x108, 0x2000); U32(0x10c, 0xc0);
        U32(0x414, 2); U32(0x418, 2); U32(0x41c, 0x2040); U32(0x420, 0x2048); U32(0x424, 0x2050);
        U32(0x440, 0x10c0); U32(0x444, 0x10e0); U32(0x448, 0x2080); U32(0x44c, 0x20a0);
        U16(0x450, 0); U16(0x452, 1);
        Encoding.ASCII.GetBytes("il2cpp_object_new\0").CopyTo(bytes, 0x480);
        Encoding.ASCII.GetBytes("il2cpp_runtime_class_init\0").CopyTo(bytes, 0x4a0);
        System.Convert.FromHexString("E90B000000").CopyTo(bytes, 0x2c0);
        bytes[0x2d0] = 0xc3;
        System.Convert.FromHexString("B901000000E906000000").CopyTo(bytes, 0x2e0);
        bytes[0x2f0] = 0xc3;
        U32(0x130, 0x20c0); U32(0x134, 12);
        U32(0x4c0, 0x3000); U32(0x4c4, 12); U16(0x4c8, 0xa180);
        U64(0x780, basis + 0x1000);
        U32(0x150, 0x20e0); U32(0x154, 40); U64(0x4f0, basis + 0x31a0);
        U32(0x158, 0x2120); U32(0x15c, 128); U32(0x520, 128);
        U64(0x578, basis + 0x31a8); U64(0x590, basis + 0x31b8);
        U64(0x7b0, BitConverter.DoubleToUInt64Bits(2.5));
        var image = ImageDocument.Parse(bytes);
        var constants = new PeConstants(image);
        Check(constants.Read(basis + 0x31b0, 64) == BitConverter.DoubleToUInt64Bits(2.5), "只读浮点初值");
        foreach (var address in new ulong[] { 0x2000, 0x1000, 0x3090, 0x308f, 0x3180, 0x317f, 0x31a0, 0x31a8, 0x31b8, 0x31ff })
            Check(constants.Read(basis + address, 64) is null, "可写、代码、IAT、重定位、TLS、Load Config 与跨节读取不得折叠");
        ulong[] entries = [basis + 0x10c0, basis + 0x10d0, basis + 0x10e0, basis + 0x10f0];
        var map = CodeMap.BuildPe(image, entries);
        var scan = CodeScan.Unscanned(map);
        var machine = new PcodeMachine(image, decoder);
        var evidence = X64RuntimeHelpers.Identify(map, scan, machine);
        Check(evidence.Any(h => h.Address == entries[1] && h.Kind == HelperKind.ObjectNew), "直接跳转保留导出语义");
        Check(evidence.All(h => h.Address != entries[3]), "改参数包装不得传播语义");
        var model = new ProgramModel { Image = image, MetadataVersion = 31, Assemblies = [], Types = [], Methods = [], Fields = [], RuntimeTypes = [], MethodSpecs = [], FieldRefs = [], StringLiterals = [], Code = new Dictionary<ulong, IReadOnlyList<CodeOwner>>() };
        var facts = new BaseFacts { Model = model, Code = map, Scan = scan, Helpers = RuntimeHelpers.FromEvidence(map, scan, evidence), Layouts = new FieldLayouts(model), MachineFactory = () => machine };
        var calls = new FactsCallModel(facts, machine.Convention);
        Check(calls.Signature(entries[1]) is { Reads: [var argument], Results: [var result] } && argument == Storage.Gpr(1) && result == Storage.Gpr(0), "Win64 导出签名 RCX→RAX");
        Check(calls.Signature(entries[2]) is { Reads: [var klass], Results.Length: 0 } && klass == Storage.Gpr(1), "类初始化不伪造返回值");
        var runtimeMap = CodeMap.BuildPe(image, []);
        var runtimeScan = CodeScan.Unscanned(runtimeMap);
        var runtimeFacts = new BaseFacts { Model = model, Code = runtimeMap, Scan = runtimeScan,
            Helpers = RuntimeHelpers.FromEvidence(runtimeMap, runtimeScan, evidence),
            Layouts = new FieldLayouts(model), MachineFactory = () => machine };
        var block = new Block(basis + 0x1000) { End = basis + 0x1010 };
        var argumentValue = Expr.C(0x1234, 64);
        block.Statements.AddRange([
            new Call(block.Start, CallKind.Direct, Expr.C(entries[1], 64)) { Arguments = [argumentValue], Results = [Storage.Gpr(0)] },
            new Call(block.Start + 1, CallKind.Direct, Expr.C(entries[2], 64)) { Arguments = [argumentValue] },
            new Call(block.Start + 2, CallKind.Direct, Expr.C(entries[3], 64)) { Arguments = [argumentValue] },
        ]);
        var function = new MachineFunction { Entry = block.Start,
            Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
        var rewritten = new IdiomRewriter(runtimeFacts).Run(function);
        Check(block.Statements[0] is Call { Op.Kind: OpKind.NewObject, Arguments: [var value], Results: [var destination] }
            && value == argumentValue && destination == Storage.Gpr(0), "x64 L2 分配保留参数与返回位置");
        Check(block.Statements[1] is Call { Op.Kind: OpKind.RunClassConstructor, Results.Length: 0 }
            && block.Statements[2] is Call { Op: null } && rewritten.Hits.GetValueOrDefault(Template.HelperCall) == 2,
            "x64 L2 类初始化保留效果，未证明的包装仍是普通调用");
        var flagBytes = bytes.ToArray();
        System.Convert.FromHexString("83B924010000007505E8E3FFFFFFC3").CopyTo(flagBytes, 0x2e0);
        var flagImage = ImageDocument.Parse(flagBytes);
        var flagMachine = new PcodeMachine(flagImage, decoder);
        Check(X64RuntimeOffsets.Identify(flagMachine, evidence).ClassCctorFinished == 0x124,
            "类初始化标志从导出代码提取，不固定为某个平台偏移");
        flagBytes[0x2e7] = 0x74;
        Check(X64RuntimeOffsets.Identify(new PcodeMachine(ImageDocument.Parse(flagBytes), decoder), evidence).ClassCctorFinished is null,
            "零值提前返回不符合类初始化完成标志语义");
        var fieldBytes = bytes.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(fieldBytes.AsSpan(0x418), 1);
        Encoding.ASCII.GetBytes("il2cpp_class_get_static_field_data\0").CopyTo(fieldBytes, 0x480);
        System.Convert.FromHexString("488B81D0000000C3").CopyTo(fieldBytes, 0x2c0);
        Check(X64RuntimeOffsets.Identify(new PcodeMachine(ImageDocument.Parse(fieldBytes), decoder), []).ClassStaticFields == 0xd0,
            "静态字段块偏移来自导出访问器");
        fieldBytes[0x2c7] = 0x90;
        Check(X64RuntimeOffsets.Identify(new PcodeMachine(ImageDocument.Parse(fieldBytes), decoder), []).ClassStaticFields is null,
            "访问器后存在其他行为时不推断字段布局");
        GuardChecks(runtimeFacts, basis, entries[1]);
        LateGuardChecks(runtimeFacts, basis, entries[1]);
        ThrowChecks(runtimeFacts, basis, entries[1]);
        AliasChecks(bytes, decoder);
        GcChecks(bytes, decoder, runtimeFacts);
        ClassHelperTests.Run(bytes, decoder);
        CallIdentityTests.Run(runtimeFacts);
        DispatchTests.Run(runtimeFacts);
        InterfaceHelperTests.Run(original, runtimeFacts);
        InterfaceInvokeTests.Run(original, decoder);
        ConstantLeafTests.Run(original, decoder);
        GenericMetadataChecks(runtimeFacts);
        ClassInitializationTests.Run(runtimeFacts);
        BooleanEdgeTests.Run();
        MetadataReturnChecks(runtimeFacts, basis, entries[1]);
        PortablePipelineChecks(runtimeFacts, basis);
        var accessorBytes = bytes.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(accessorBytes.AsSpan(0x418), 1);
        Encoding.ASCII.GetBytes("il2cpp_method_get_class\0").CopyTo(accessorBytes, 0x480);
        System.Convert.FromHexString("E90B000000").CopyTo(accessorBytes, 0x2c0);
        System.Convert.FromHexString("488B4130C3").CopyTo(accessorBytes, 0x2d0);
        var accessorLayout = X64RuntimeOffsets.Identify(new PcodeMachine(ImageDocument.Parse(accessorBytes), decoder), [], 31);
        Check(accessorLayout.MethodClass == 0x30 && accessorLayout.ClassRgctxData is null, "方法声明类偏移来自访问器，布局配置不匹配不启用 RGCTX");
        Encoding.ASCII.GetBytes("il2cpp_class_is_inited\0").CopyTo(accessorBytes, 0x480);
        System.Convert.FromHexString("0FB68155010000D0E82401C3").CopyTo(accessorBytes, 0x2c0);
        Check(X64RuntimeOffsets.Identify(new PcodeMachine(ImageDocument.Parse(accessorBytes), decoder), []).ClassInitializationFlags == 0x155,
            "初始化标志位置来自导出，不沿用固定布局");
        var conflicting = bytes.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(conflicting.AsSpan(0x444), 0x10c0);
        var conflictImage = ImageDocument.Parse(conflicting);
        var conflictMap = CodeMap.BuildPe(conflictImage, entries);
        Check(X64RuntimeHelpers.Identify(conflictMap, CodeScan.Unscanned(conflictMap), new PcodeMachine(conflictImage, decoder)).Length == 0, "相交导出语义冲突必须拒绝");
        // 独立加载配置测试复用导出节，避免越过节边界。
        var configPrefix = bytes.AsSpan(0x520, 128).ToArray();
        foreach (var directory in new[] { 0x108, 0x110, 0x130, 0x150 }) { U32(directory, 0); U32(directory + 4, 0); }
        Array.Clear(bytes, 0x400, 264);
        configPrefix.CopyTo(bytes, 0x400);
        U32(0x158, 0x2000); U32(0x15c, 264); U32(0x400, 264); U64(0x500, basis + 0x3140);
        Check(new PeConstants(ImageDocument.Parse(bytes)).Read(basis + 0x31b0, 64) == BitConverter.DoubleToUInt64Bits(2.5),
            "volatile 访问描述不是加载器写入，不禁止只读常量");
        Check(new PeConstants(ImageDocument.Parse(bytes)).Read(basis + 0x31a8, 64) is null,
            "volatile 描述存在时仍排除实际加载器写入");
        U64(0x4c8, basis + 0x3100);
        Check(new PeConstants(ImageDocument.Parse(bytes)).Read(basis + 0x31b0, 64) is null, "CHPE 未建模时不折叠");
        U64(0x4c8, 0); U64(0x4c0, basis + 0x3100);
        Check(new PeConstants(ImageDocument.Parse(bytes)).Read(basis + 0x31b0, 64) is null, "动态重定位未建模时不折叠");
        Console.WriteLine("运行时导出证据、Win64 helper ABI 与 PE 常量边界测试通过");
    }

    private static void PortablePipelineChecks(BaseFacts facts, ulong basis)
    {
        foreach (var memoryCondition in new[] { false, true })
        {
            var input = new Use(new Variable(Storage.Gpr(1), 0), 64);
            Expr condition = new Compare(Cond.Ne, memoryCondition ? new Load(input, 64) : input, Expr.C(0, 64));
            var result = new Variable(Storage.Gpr(0), 1);
            var block = new Block(basis + 0x1000) { End = basis + 0x1010 };
            var choice = new Select(condition, Expr.C(basis + 0x2000, 64), Expr.C(basis + 0x2010, 64), 64);
            block.Statements.Add(new Define(block.Start, result, new Load(choice, 32)));
            // 后续写入使返回值必须使用读取时的快照，不能在写入后重新读取。
            block.Statements.Add(new Store(block.Start + 1, Expr.C(basis + 0x2000, 64), Expr.C(7, 32)));
            block.Statements.Add(new Return(block.Start + 2) { Value = new Use(result, 32) });
            var function = new MachineFunction { Entry = block.Start,
                Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            function.Renumber();
            var rewritten = new IdiomRewriter(facts).Run(function);
            var nodes = block.Statements.SelectMany(ExprMap.Operands).SelectMany(ExprMap.Walk).ToArray();
            Check(rewritten.Errors.Count == 0, "公共规则接入 x64 后保持 SSA");
            Check(memoryCondition ? nodes.OfType<Load>().Any(l => l.Address is Select)
                : nodes.OfType<Select>().Any(s => s.True is Load && s.False is Load),
                "纯条件地址分解为单臂读取；含内存读取的条件保留原形态");
            Check(block.Statements.OfType<Store>().Count() == 1, "地址归一保留原有写入效果");
        }
    }

    private static void MetadataReturnChecks(BaseFacts basisFacts, ulong basis, ulong helper)
    {
        var usages = new UsageSlots { Slots = new Dictionary<ulong, UsageSlot> {
            [basis + 0x2010] = new(basis + 0x2010, new(UsageKind.StringLiteral, 0, "fixture"), 1, 1) },
            SlotAddressBeforeCall = new Dictionary<ulong, int>(), UnreferencedDecodable = new Dictionary<ulong, Usage>() };
        var facts = basisFacts with { Usages = usages, Helpers = RuntimeHelpers.FromEvidence(basisFacts.Code, basisFacts.Scan,
            [new(helper, HelperKind.InitMetadata, null, "测试中的独立解析器契约", 1)]) };
        foreach (var known in new[] { true, false })
        {
            var result = new Variable(Storage.Gpr(0), 1);
            var block = new Block(basis + 0x1000) { End = basis + 0x1010 };
            block.Statements.Add(new Call(block.Start, CallKind.Direct, Expr.C(helper, 64)) {
                Arguments = [Expr.C(basis + (known ? 0x2010UL : 0x2020UL), 64)], Sources = [Storage.Gpr(1)],
                Results = [Storage.Gpr(0)], Defines = [result] });
            block.Statements.Add(new Return(block.Start + 5) { Value = new Use(result, 64) });
            var function = new MachineFunction { Entry = block.Start, Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            function.Renumber();
            var rewritten = new IdiomRewriter(facts).Run(function);
            Check(rewritten.Errors.Count == 0, "元数据返回值替换保持 SSA");
            Check(known ? block.Statements.OfType<Return>().Single().Value is Symbol { Kind: SymbolKind.String, Value: "fixture" }
                && !block.Statements.OfType<Call>().Any() : block.Statements.OfType<Call>().Count() == 1,
                "已解码初始化结果传播为实体；未知槽位保留调用");
        }
        foreach (var variant in new[] { "same", "rewritten", "duplicate", "slot", "target", "kind", "result" })
        {
            var output = new Variable(Storage.Gpr(0), 1);
            var original = new Call(basis + 0x1000, CallKind.Direct, Expr.C(helper, 64)) {
                Arguments = [Expr.C(basis + 0x2010, 64)], Sources = [Storage.Gpr(1)], Results = [Storage.Gpr(0)], Defines = [output] };
            var block = new Block(original.Address) { End = original.Address + 8,
                Statements = [original, new Return(original.Address + 5) { Value = new Use(output, 64) }] };
            var function = new MachineFunction { Entry = block.Start, Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            function.Renumber();
            var state = new IdiomState(new IdiomRewriter(facts), function);
            state.Direct(block, 0, original);
            Check(state.lazyValues.Count == 1, "独立元数据契约应产生延迟替换证明");
            block.Statements[0] = variant switch {
                "same" => original,
                "duplicate" => original.Duplicate(),
                "slot" => original with { Arguments = [Expr.C(basis + 0x2020, 64)] },
                "target" => original with { Target = Expr.C(helper + 16, 64) },
                "kind" => original with { Kind = CallKind.Indirect },
                "result" => original with { Defines = [new Variable(new Storage(Bank.Temp, 4000, 32), 1)] },
                _ => original with { Arguments = original.Arguments.ToArray() },
            };
            state.ReplaceLazy();
            Check(function.Blocks.SelectMany(b => b.Statements).OfType<Call>().Any() == (variant is not ("same" or "rewritten")),
                "同一 Site 的等价记录改写仍可应用证明，路径复制或参数／目标／结果改变须重新证明：" + variant);
        }
        foreach (var variant in new[] { "reload", "different-value", "different-address", "clobber", "write", "no-initializer" })
        {
            var before = new Variable(Storage.Temp(5000), 1); var reloaded = new Variable(Storage.Temp(5001), 1); var merged = new Variable(Storage.Temp(5002), 1);
            var head = new Block(basis + 0x1000) { End = basis + 0x1010 };
            var slow = new Block(basis + 0x1010) { End = basis + 0x1020 }; var join = new Block(basis + 0x1020) { End = basis + 0x1030 };
            var input = new Use(new Variable(Storage.Gpr(2), 0), 64); var flag = Expr.C(basis + 0x2008, 64);
            head.Statements.Add(new Define(head.Start, before, variant == "different-value" ? Expr.C(7, 64) : new Load(input, 64)));
            if (variant == "clobber") head.Statements.Add(new Call(head.Start + 1, CallKind.Direct, Expr.C(helper + 64, 64)));
            head.Statements.Add(new Branch(head.Start + 2, new Compare(Cond.Ne, new Load(flag, 8), Expr.C(0, 8)), join.Start, slow.Start));
            if (variant != "no-initializer") slow.Statements.Add(new Call(slow.Start, CallKind.Direct, Expr.C(helper, 64)) { Arguments = [Expr.C(basis + 0x2010, 64)] });
            slow.Statements.Add(new Define(slow.Start + 1, reloaded, new Load(variant == "different-address" ? new Binary(BinOp.Add, input, Expr.C(8, 64), 64) : input, 64)));
            slow.Statements.Add(new Store(slow.Start + 2, flag, Expr.C(1, 8)));
            if (variant == "write") slow.Statements.Add(new Store(slow.Start + 3, Expr.C(basis + 0x2020, 64), Expr.C(1, 32)));
            slow.Statements.Add(new Jump(slow.Start + 4, join.Start));
            join.Statements.Add(new Phi(join.Start, merged, [before, reloaded])); join.Statements.Add(new Return(join.Start + 1) { Value = new Use(merged, 64) });
            MachineFunction.AddEdge(head, join); MachineFunction.AddEdge(head, slow); MachineFunction.AddEdge(slow, join);
            var function = new MachineFunction { Entry = head.Start, Range = new(head.Start, join.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [head, slow, join] };
            function.Renumber();
            var originalFunction = function.Copy();
            var state = new IdiomState(new IdiomRewriter(facts), function);
            Check(state.OnceGuards(metadataOnly: true) == (variant == "reload"), "重读必须证明同址、同值、无破坏且两臂效果一致：" + variant
                + ":" + string.Join(';', state.Result.Rejections.Select(r => r.Reason)));
            if (variant != "reload") continue;
            var result = new IdiomRewriter(facts).Run(originalFunction);
            Check(result.Errors.Count == 0 && !originalFunction.Blocks.SelectMany(b => b.Statements).OfType<Call>().Any(),
                "x64 最终直接识别后的已证明初始化调用必须消费，不能残留为未知调用");
        }
    }

    private static void GuardChecks(BaseFacts basisFacts, ulong basis, ulong helper)
    {
        var usages = new UsageSlots { Slots = new Dictionary<ulong, UsageSlot> { [basis + 0x2010] =
            new(basis + 0x2010, new(UsageKind.StringLiteral, 0, "fixture"), 1, 1) },
            SlotAddressBeforeCall = new Dictionary<ulong, int>(), UnreferencedDecodable = new Dictionary<ulong, Usage>() };
        var facts = basisFacts with { Usages = usages, Helpers = RuntimeHelpers.FromEvidence(basisFacts.Code, basisFacts.Scan,
            [new(helper, HelperKind.InitMetadata, null, "测试中的独立辅助函数契约", 1)]) };
        foreach (var extraStore in new[] { false, true })
        {
            var head = new Block(basis + 0x1000) { End = basis + 0x1010 };
            var initialize = new Block(basis + 0x1010) { End = basis + 0x1020 };
            var merge = new Block(basis + 0x1020) { End = basis + 0x1021 };
            var flag = Expr.C(basis + 0x2008, 64);
            head.Statements.Add(new Branch(head.Start, new Compare(Cond.Ne, new Load(flag, 8), Expr.C(0, 8)), merge.Start, initialize.Start));
            initialize.Statements.Add(new Call(initialize.Start, CallKind.Direct, Expr.C(helper, 64)) { Arguments = [Expr.C(basis + 0x2010, 64)] });
            initialize.Statements.Add(new Store(initialize.Start + 5, flag, Expr.C(1, 8)));
            if (extraStore) initialize.Statements.Add(new Store(initialize.Start + 6, Expr.C(basis + 0x2020, 64), Expr.C(7, 32)));
            initialize.Statements.Add(new Jump(initialize.Start + 7, merge.Start));
            merge.Statements.Add(new Return(merge.Start) { Value = Expr.C(42, 32) });
            MachineFunction.AddEdge(head, merge); MachineFunction.AddEdge(head, initialize); MachineFunction.AddEdge(initialize, merge);
            var function = new MachineFunction { Entry = head.Start, Range = new(head.Start, merge.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate),
                Blocks = [head, initialize, merge] };
            function.Renumber();
            var result = new IdiomRewriter(facts).Run(function);
            Check(result.Hits.GetValueOrDefault(Template.MetadataInitGuard) == (extraStore ? 0 : 1),
                "仅消除完整元数据守卫，额外业务写入必须保留");
            Check(function.Blocks.SelectMany(b => b.Statements).OfType<Call>().Any() == extraStore, "拒绝的守卫不得删除初始化调用");
        }
    }

    private static void LateGuardChecks(BaseFacts basisFacts, ulong basis, ulong helper)
    {
        var usages = new UsageSlots { Slots = new Dictionary<ulong, UsageSlot> { [basis + 0x2010] =
            new(basis + 0x2010, new(UsageKind.StringLiteral, 0, "fixture"), 1, 1) },
            SlotAddressBeforeCall = new Dictionary<ulong, int>(), UnreferencedDecodable = new Dictionary<ulong, Usage>() };
        var facts = basisFacts with { Usages = usages, Helpers = RuntimeHelpers.FromEvidence(basisFacts.Code, basisFacts.Scan,
            [new(helper, HelperKind.InitMetadata, null, "独立解析器契约", 1)]) };
        facts = facts with { Registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = [],
            ByAddress = new Dictionary<ulong, CodeEntry[]>(), Rgctx = new Dictionary<(string, uint), RgctxEntry[]>(),
            MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>() } };
        var owner = new TypeDef { Index = 0, Assembly = "Fixture.dll", Namespace = "", Name = "Owner", Token = 0x02000001,
            Attributes = System.Reflection.TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 };
        var method = MethodRef.Open(new MethodDef { Index = 0, Owner = owner, Name = "Run", Token = 0x06000001,
            Attributes = System.Reflection.MethodAttributes.Public | System.Reflection.MethodAttributes.Static, ImplAttributes = 0, Slot = -1 });
        foreach (var known in new[] { false, true })
        foreach (var extraRead in new[] { false, true })
        foreach (var extraStore in new[] { false, true })
        {
            var head = new Block(basis + 0x1000); var initialize = new Block(basis + 0x1010); var merge = new Block(basis + 0x1020);
            var incoming = new Variable(Storage.Gpr(0), extraRead ? 1 : 0);
            var returned = new Variable(Storage.Gpr(0), 2); var joined = new Variable(Storage.Gpr(0), 3);
            var flag = Expr.C(basis + 0x2008, 64);
            if (extraRead) head.Statements.Add(new Define(head.Start, incoming, new Load(new Use(new Variable(Storage.Gpr(9), 0), 64), 64)));
            head.Statements.Add(new Branch(head.Start + 1, new Compare(Cond.Ne, new Load(flag, 8), Expr.C(0, 8)), merge.Start, initialize.Start));
            initialize.Statements = [new Call(initialize.Start, CallKind.Direct, Expr.C(helper, 64)) {
                Arguments = [Expr.C(basis + 0x2010, 64)], Sources = [Storage.Gpr(1)], Results = [Storage.Gpr(0)], Defines = [returned] },
                new Store(initialize.Start + 5, flag, Expr.C(1, 8)), new Jump(initialize.Start + 7, merge.Start)];
            if (extraStore) initialize.Statements.Insert(2, new Store(initialize.Start + 6, Expr.C(basis + 0x2020, 64), Expr.C(7, 32)));
            var target = basis + 0x1040;
            var call = new Call(merge.Start + 1, CallKind.Direct, Expr.C(target, 64)) {
                Arguments = [Expr.C(0, 64), new Use(joined, 64)], Sources = [Storage.Gpr(1), Storage.Gpr(8)] };
            merge.Statements = [new Phi(merge.Start, joined, [incoming, returned]), call, new Return(merge.Start + 2)];
            MachineFunction.AddEdge(head, merge); MachineFunction.AddEdge(head, initialize); MachineFunction.AddEdge(initialize, merge);
            var function = new MachineFunction { Entry = head.Start, Range = new(head.Start, merge.Start + 3, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [head, initialize, merge] };
            function.Renumber();
            var rewriter = new IdiomRewriter(facts); var result = rewriter.Run(function);
            Cpp2CS.Recovery.Calls.CallShape Shape(Call c) => new(c, [], known && c.Target == Expr.C(target, 64)
                ? new MachineSignature([], null, new AbiPiece(Storage.Gpr(1), 64, 0), 0) : null);
            var trimmed = Cpp2CS.Recovery.Calls.CallInputSnapshots.Trim(function, Shape);
            Check(trimmed == (known && !extraRead), "只清除确定签名之外、没有读取来源的快照");
            if (trimmed) rewriter.ResumeGuards(function, method, result);
            Check(result.Errors.Count == 0 && Cpp2CS.Machine.Ssa.SsaCheck.Verify(function, Cpp2CS.Machine.Ssa.Dominators.Compute(function)).Count == 0,
                "签名确定后的守卫复查保持 SSA");
            Check(result.Hits.GetValueOrDefault(Template.MetadataInitGuard) == (known && !extraRead && !extraStore ? 1 : 0),
                $"守卫复查仍拒绝额外读取依赖和业务写入：known={known}, read={extraRead}, store={extraStore}, hits={result.Hits.GetValueOrDefault(Template.MetadataInitGuard)}");
            Check(function.Blocks.SelectMany(b => b.Statements).OfType<Call>().Count(c => c.Target == Expr.C(target, 64)) == 1,
                "复查保留真正的托管调用");
            if (extraRead) Check(function.Blocks.SelectMany(b => b.Statements).OfType<Define>().Any(d => d.Value is Load), "未用快照也不能隐藏读取");
        }
    }

    private static void Check(bool condition, string reason)
    {
        if (!condition) throw new InvalidOperationException(reason);
    }

    private static void AliasChecks(byte[] original, SleighDecoder decoder)
    {
        const ulong basis = 0x180000000;
        var bytes = original.ToArray();
        System.Convert.FromHexString("E92B000000").CopyTo(bytes, 0x2a0); // 独立入口 → 分配实现
        RuntimeHelper[] Identify(byte[] data, bool managed = false)
        {
            var image = ImageDocument.Parse(data);
            var map = CodeMap.BuildPe(image, managed ? [basis + 0x10a0] : []);
            var scan = CodeScan.FromReferences(map, new Dictionary<ulong, CodeRef[]> {
                [basis + 0x1000] = [new(basis + 0x1000, basis + 0x10a0, RefKind.Call, 0)] });
            return X64RuntimeHelpers.Identify(map, scan, new PcodeMachine(image, decoder));
        }
        Check(Identify(bytes).Any(h => h.Address == basis + 0x10a0 && h.Kind == HelperKind.ObjectNew && h.CallSites == 1), "调用入口跳板关联导出实现");
        Check(Identify(bytes, true).All(h => h.Address != basis + 0x10a0), "不覆盖托管入口身份");
        var modified = bytes.ToArray();
        System.Convert.FromHexString("B901000000E926000000").CopyTo(modified, 0x2a0);
        Check(Identify(modified).All(h => h.Address != basis + 0x10a0), "修改参数的调用入口不归并");
        var cycle = bytes.ToArray();
        System.Convert.FromHexString("E9FBFFFFFF").CopyTo(cycle, 0x2a0);
        Check(Identify(cycle).All(h => h.Address != basis + 0x10a0), "跳板环不提供语义");
        var conflict = bytes.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(conflict.AsSpan(0x444), 0x10d0);
        Check(Identify(conflict).All(h => h.Address != basis + 0x10a0), "不传播冲突的导出语义");
        // 外层失败分支返回 null；内层分配保持自身的异常语义。
        System.Convert.FromHexString("4883EC28E867000000EB0233C04883C428C3").CopyTo(bytes, 0x2c0);
        bytes[0x330] = 0xc3;
        System.Convert.FromHexString("E98B000000").CopyTo(bytes, 0x2a0);
        var allocator = Identify(bytes);
        Check(allocator.Any(h => h.Address == basis + 0x10a0 && h.Kind == HelperKind.ObjectNew)
            && allocator.All(h => h.Address != basis + 0x10c0), "分配正常目标不继承外层失败返回行为");
    }

    private static void GenericMetadataChecks(BaseFacts basisFacts)
    {
        var owner = new TypeDef { Index = 0, Assembly = "Fixture.dll", Namespace = "", Name = "Container", Token = 0x02000001,
            Attributes = System.Reflection.TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 };
        var argument = new DefinitionRef(new TypeDef { Index = 1, Assembly = "Fixture.dll", Namespace = "", Name = "Element", Token = 0x02000002,
            Attributes = System.Reflection.TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 }, []);
        var method = new MethodDef { Index = 0, Owner = owner, Name = "Read", Token = 0x06000001,
            Attributes = System.Reflection.MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = argument, Parameters = [] };
        var reference = new MethodRef(method, [argument], []);
        {
            const ulong helper = 0x180001080;
            var facts = basisFacts with { Helpers = RuntimeHelpers.FromEvidence(basisFacts.Code, basisFacts.Scan,
                    [new(helper, HelperKind.InitializedTypeInfo, null, "测试契约", 1)]),
                RuntimeOffsets = new(null, 0xb8, "测试布局"),
                Usages = new UsageSlots { Slots = new Dictionary<ulong, UsageSlot>(), UnreferencedDecodable = new Dictionary<ulong, Usage>(), SlotAddressBeforeCall = new Dictionary<ulong, int>() } };
            Check(new FactsCallModel(facts, facts.MachineFactory!().Convention).Signature(helper) is { Reads: [var input], Results: [var output] }
                && input == Storage.Gpr(1) && output == Storage.Gpr(0), "布局初始化使用 RCX→RAX 返回原类指针契约");
            var block = new Block(0x1000) { End = 0x1010 };
            var result = new Variable(Storage.Gpr(0), 1);
            block.Statements.Add(new Call(block.Start, CallKind.Direct, Expr.C(helper, 64)) { Arguments = [new Symbol(SymbolKind.Class, argument)], Results = [Storage.Gpr(0)], Defines = [result] });
            block.Statements.Add(new Return(block.Start + 5) { Value = new Load(new Binary(BinOp.Add, new Use(result, 64), Expr.C(0xb8, 64), 64), 64) });
            var function = new MachineFunction { Entry = block.Start, Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            new IdiomRewriter(facts).Run(function);
            Check(function.Blocks.SelectMany(b => b.Statements).OfType<Call>().Any(c => c.Op?.Kind == OpKind.InitClass)
                && function.Blocks.SelectMany(b => b.Statements).OfType<Return>().Single().Value is Symbol { Kind: SymbolKind.StaticFields, Value: var fields } && Equals(fields, argument),
                "非守卫初始化的返回值也能继续解析字段，初始化操作本身保留");
        }
        foreach (var mode in new[] { "dominated", "partial_path", "wrong_offset" })
        {
            var head = new Block(0x1000) { End = 0x1010 };
            var initialize = new Block(0x1010) { End = 0x1020 };
            var merge = new Block(0x1020) { End = 0x1030 };
            head.Statements.Add(new Branch(head.Start, new Entry(Storage.Gpr(1)), initialize.Start, merge.Start));
            var init = new Call(head.Start, CallKind.Direct, Expr.C(0x2000, 64)) { Op = new RuntimeOp(OpKind.InitClass, argument), Arguments = [new Symbol(SymbolKind.Class, argument)] };
            if (mode == "partial_path") initialize.Statements.Add(init); else head.Statements.Insert(0, init);
            initialize.Statements.Add(new Jump(initialize.Start, merge.Start));
            var flag = new Load(new Binary(BinOp.Add, new Symbol(SymbolKind.Class, argument), Expr.C(mode == "wrong_offset" ? 0x135UL : 0x155UL, 64), 64), 8);
            merge.Statements.Add(new Return(merge.Start) { Value = new Binary(BinOp.And, flag, Expr.C(1, 8), 8) });
            MachineFunction.AddEdge(head, initialize); MachineFunction.AddEdge(head, merge); MachineFunction.AddEdge(initialize, merge);
            var function = new MachineFunction { Entry = head.Start, Range = new(head.Start, merge.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [head, initialize, merge] };
            function.Renumber();
            Check(ClassInitializationFacts.Run(function, constructorFacts: false, classFlagsOffset: 0x155) == (mode == "dominated"),
                "初始化标志折叠要求同类型、正确偏移且所有到达路径均完成初始化");
        }
        var registrations = new Registrations { CodeRegistration = 0, MetadataRegistration = 0, Entries = [], ByAddress = new Dictionary<ulong, CodeEntry[]>(),
            MetadataUsageSlots = [], TypePointers = new Dictionary<ulong, int>(), InvokerOf = new Dictionary<MethodDef, int>(),
            Rgctx = new Dictionary<(string, uint), RgctxEntry[]> { [(owner.Assembly, owner.Token)] = [new(RgctxKind.Class, new GenericParameterRef("T", false, 0))] } };
        foreach (var scenario in new[] { "valid", "no_layout", "wrong_offset", "bad_index", "narrow", "missing_table" })
        {
            var block = new Block(0x1000) { End = 0x1010 };
            Expr Add(Expr value, ulong offset) => new Binary(BinOp.Add, value, Expr.C(offset, 64), 64);
            var declaring = new Load(Add(new Symbol(SymbolKind.Method, reference), 0x30), 64);
            var table = new Load(Add(declaring, scenario == "wrong_offset" ? 0x190UL : 0x188UL), 64);
            block.Statements.Add(new Return(0x1000) { Value = new Load(Add(table, scenario == "bad_index" ? 8UL : 0UL), scenario == "narrow" ? 32 : 64) });
            var function = new MachineFunction { Entry = block.Start, Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            var facts = basisFacts with { Registrations = registrations, RuntimeOffsets = new(null, null, "测试布局") { MethodClass = 0x30, ClassRgctxData = scenario == "no_layout" ? null : 0x188 } };
            if (scenario == "missing_table") ((Dictionary<(string, uint), RgctxEntry[]>)registrations.Rgctx).Clear();
            var state = new IdiomState(new IdiomRewriter(facts), function);
            for (var i = 0; i < 4; i++)
            {
                MetadataLoadsPass.Run(function, new UsageSlots { Slots = new Dictionary<ulong, UsageSlot>(), UnreferencedDecodable = new Dictionary<ulong, Usage>(), SlotAddressBeforeCall = new Dictionary<ulong, int>() }, methodClassOffset: 0x30);
                state.defs = new IdiomRewriter.Defs(function);
                state.GenericMetadataLoads();
            }
            Check((block.Statements[0] is Return { Value: Symbol { Kind: SymbolKind.Class, Value: var result } } && Equals(result, argument)) == (scenario == "valid"),
                "泛型类型实参由所属注册表代入，未知布局、宽度、条目和令牌不猜测");
        }
        ((Dictionary<(string, uint), RgctxEntry[]>)registrations.Rgctx)[(owner.Assembly, owner.Token)] = [new(RgctxKind.Class, new GenericParameterRef("T", false, 0))];
        foreach (var actual in new TypeRef[] { argument, new ArrayRef(argument, 1) })
        {
            var block = new Block(0x1000) { End = 0x1010 };
            Expr Add(Expr value, ulong offset) => new Binary(BinOp.Add, value, Expr.C(offset, 64), 64);
            var incoming = new Use(new Variable(Storage.Gpr(1), 0), 64);
            block.Statements.Add(new Return(0x1000) { Value = new Load(new Load(Add(new Load(Add(incoming, 0x30), 64), 0x188), 64), 64) });
            var function = new MachineFunction { Entry = block.Start, Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            var facts = basisFacts with { Registrations = registrations,
                Usages = new UsageSlots { Slots = new Dictionary<ulong, UsageSlot>(), UnreferencedDecodable = new Dictionary<ulong, Usage>(), SlotAddressBeforeCall = new Dictionary<ulong, int>() },
                RuntimeOffsets = new(null, null, "测试布局") { MethodClass = 0x30, ClassRgctxData = 0x188 } };
            var result = new IdiomRewriter(facts).Run(function, new MethodRef(method, [actual], []));
            Check(result.Errors.Count == 0 && function.Blocks.SelectMany(b => b.Statements).OfType<Return>().Single().Value is Symbol { Value: var resolved }
                && Equals(resolved, actual), "共享入口按本次方法实例解析隐藏 MethodInfo，不串用其他实例");
        }
    }

    private static void GcChecks(byte[] original, SleighDecoder decoder, BaseFacts basisFacts)
    {
        const ulong basis = 0x180000000;
        var bytes = original.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x418), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x440), 0x1100);
        Encoding.ASCII.GetBytes("il2cpp_gc_wbarrier_set_field\0").CopyTo(bytes, 0x480);
        System.Convert.FromHexString("488BCA498BD0E915000000").CopyTo(bytes, 0x300);
        System.Convert.FromHexString("488911E958FFFFFF").CopyTo(bytes, 0x320);
        var body = System.Convert.FromHexString("833D00000000004C8BC1743549C1E80C488D0D000000004181E0FFFF1F00418BC048C1E8064183E03F488D14C10F0D0A488B02488BC84C0FABC1F0480FB10A75EFC3");
        BinaryPrimitives.WriteInt32LittleEndian(body.AsSpan(2), 0x21e0 - 0x1087);
        BinaryPrimitives.WriteInt32LittleEndian(body.AsSpan(19), 0x2180 - 0x1097);
        body.CopyTo(bytes, 0x280);
        System.Convert.FromHexString("E93BFFFFFF").CopyTo(bytes, 0x340);
        RuntimeHelper[] Identify(byte[] data)
        {
            var image = ImageDocument.Parse(data);
            var map = CodeMap.BuildPe(image, []);
            var scan = CodeScan.FromReferences(map, new Dictionary<ulong, CodeRef[]> {
                [basis + 0x1000] = [new(basis + 0x1000, basis + 0x1140, RefKind.Call, 0)] });
            return X64RuntimeHelpers.Identify(map, scan, new PcodeMachine(image, decoder));
        }
        var helpers = Identify(bytes);
        Check(helpers.Any(h => h.Address == basis + 0x1140 && h.Kind == HelperKind.GcNotification), "导出存储后的完整位图通知及其调用别名");
        Check(helpers.All(h => h.Address != basis + 0x1100 && h.Address != basis + 0x1120), "有引用写入的外层不得视作纯通知");
        foreach (var offset in new[] { 10, 13, 25, 34, 40, 45, 52, 58, 63, 65 })
        {
            var changed = bytes.ToArray(); changed[0x280 + offset] ^= 1;
            Check(Identify(changed).All(h => h.Kind != HelperKind.GcNotification), "改变开关、页号、目标地址、原子操作或循环出口时拒绝通知语义");
        }
        foreach (var offset in new[] { 0x301, 0x321 })
        {
            var changed = bytes.ToArray(); changed[offset] ^= 1;
            Check(Identify(changed).All(h => h.Kind != HelperKind.GcNotification), "导出参数转发和字段存储必须匹配");
        }
        var shifted = bytes.ToArray();
        BinaryPrimitives.WriteUInt64LittleEndian(shifted.AsSpan(0xb0), basis + 0x10000000);
        Check(Identify(shifted).Any(h => h.Address == basis + 0x10000000 + 0x1080 && h.Kind == HelperKind.GcNotification), "通知识别不依赖映像基址");
        var facts = basisFacts with { Helpers = RuntimeHelpers.FromEvidence(basisFacts.Code, basisFacts.Scan, helpers) };
        var signature = new FactsCallModel(facts, facts.MachineFactory!().Convention).Signature(basis + 0x1140);
        Check(signature is { Reads: [var location], Results.Length: 0 } && location == Storage.Gpr(1), "通知仅读取 RCX，不伪造值参数或返回值");
        var block = new Block(basis + 0x1000) { End = basis + 0x1010 };
        var address = Expr.C(basis + 0x2010, 64);
        var store = new Store(block.Start, address, Expr.C(42, 64));
        block.Statements.Add(store);
        block.Statements.Add(new Call(block.Start + 4, CallKind.Direct, Expr.C(basis + 0x1140, 64)) { Arguments = [address] });
        var function = new MachineFunction { Entry = block.Start, Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
        new IdiomRewriter(facts).Run(function);
        Check(block.Statements.Contains(store) && block.Statements.OfType<Call>().Single() is { Op.Kind: OpKind.WriteBarrier, Arguments.Length: 1 }, "通知归一保留实际存储和单参数契约");
    }

    private static void ThrowChecks(BaseFacts basisFacts, ulong basis, ulong helper)
    {
        var facts = basisFacts with { Helpers = RuntimeHelpers.FromEvidence(basisFacts.Code, basisFacts.Scan,
            [new(helper, HelperKind.Throw, "System.NullReferenceException", "测试中的独立异常契约", 1)]) };
        Check(new FactsCallModel(facts, facts.MachineFactory!().Convention).Signature(helper) is { Reads.Length: 0, Results.Length: 0 },
            "无参抛出包装不读取残留的参数寄存器");
        foreach (var sideEffect in new[] { false, true })
        {
            var head = new Block(basis + 0x1000) { End = basis + 0x1010 };
            var fail = new Block(basis + 0x1010) { End = basis + 0x1020 };
            var pass = new Block(basis + 0x1020) { End = basis + 0x1021 };
            head.Statements.Add(new Branch(head.Start, new Compare(Cond.Eq, new Entry(Storage.Gpr(1)), Expr.C(0, 64)), fail.Start, pass.Start));
            if (sideEffect) fail.Statements.Add(new Store(fail.Start, Expr.C(basis + 0x2000, 64), Expr.C(1, 32)));
            fail.Statements.Add(new Call(fail.Start + 4, CallKind.Direct, Expr.C(helper, 64)) { DoesNotReturn = true });
            pass.Statements.Add(new Return(pass.Start) { Value = Expr.C(42, 32) });
            MachineFunction.AddEdge(head, fail); MachineFunction.AddEdge(head, pass);
            var function = new MachineFunction { Entry = head.Start, Range = new(head.Start, pass.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate),
                Blocks = [head, fail, pass] };
            function.Renumber();
            var result = new IdiomRewriter(facts).Run(function);
            Check(result.Hits.GetValueOrDefault(Template.NullCheck) == (sideEffect ? 0 : 1), "判空仅归一没有附加副作用的抛出分支");
            Check(function.Blocks.SelectMany(b => b.Statements).OfType<Store>().Any() == sideEffect, "抛出之前的业务写入不得丢失");
        }
    }
}

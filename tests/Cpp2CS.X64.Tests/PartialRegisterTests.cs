using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Ssa;

namespace Cpp2CS.X64.Tests;

internal static class PartialRegisterTests
{
    internal static void Run()
    {
        foreach (var insertedWidth in new[] { 8, 32 })
        foreach (var observedWidth in new[] { 8, 16, 32, 64 })
        foreach (var origin in new[] { "entry", "call", "load", "intrinsic" })
        {
            var source = new Variable(Storage.Gpr(0), 1); var written = source with { Version = 2 };
            var incoming = new Use(new Variable(Storage.Gpr(8), 0), 64);
            var block = new Block(0x1000) { End = 0x1008 };
            if (origin == "call") block.Statements.Add(new Call(0x1000, CallKind.Direct, Expr.C(0x2000, 64)) { Results = [Storage.Gpr(0)], Defines = [source] });
            else if (origin == "load") block.Statements.Add(new Define(0x1000, source, new Load(incoming, 64)));
            else if (origin == "intrinsic") block.Statements.Add(new Define(0x1000, source, new Intrinsic("unmodeled_effect", [], 64)));
            var baseValue = origin == "entry" ? incoming : new Use(source, 64);
            block.Statements.Add(new Store(0x1001, Expr.C(0x3000, 64), Expr.C(7, 32)));
            block.Statements.Add(new Define(0x1002, written, new Insert(baseValue, new Use(new Variable(Storage.Gpr(2), 0), insertedWidth), 0)));
            block.Statements.Add(new Return(0x1003) { Value = new Use(written, observedWidth) });
            var function = new MachineFunction { Entry = block.Start, Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            Propagate.Run(function, Dominators.Compute(function));
            Check(SsaCheck.Verify(function, Dominators.Compute(function)).Count == 0, "部分寄存器传播保持 SSA");
            var forwarded = block.Statements.OfType<Return>().Single().Value is Use { Variable.Storage: var register, Variable.Version: 0, Width: var width }
                && register == Storage.Gpr(2) && width == observedWidth;
            Check(forwarded == (observedWidth <= insertedWidth && origin is "entry" or "call"), "只在观察位全部被覆盖且不会隐藏读取时传播：" + origin);
            Check(block.Statements.OfType<Store>().Count() == 1 && (origin != "call" || block.Statements.OfType<Call>().Count() == 1), "保留原有写入与调用效果");
            if (origin == "load") Check(block.Statements.OfType<Define>().Any(d => d.Value is Load), "不能因寄存器低位重写丢弃潜在异常读取");
        }
        foreach (var fromMemory in new[] { false, true })
        {
            var head = new Block(0x1000); var initialize = new Block(0x1100); var merge = new Block(0x1200);
            var returned = new Variable(Storage.Gpr(0), 1); var joined = returned with { Version = 2 }; var final = returned with { Version = 3 };
            var entry = new Variable(Storage.Gpr(0), 0);
            head.Statements = [new Branch(0x1000, new Compare(Cond.Eq, new Use(new Variable(Storage.Gpr(1), 0), 64), Expr.C(0, 64)), initialize.Start, merge.Start)];
            initialize.Statements = fromMemory ? [new Define(0x1100, returned, new Load(Expr.C(0x4000, 64), 64)), new Jump(0x1101, merge.Start)]
                : [new Call(0x1100, CallKind.Direct, Expr.C(0x2000, 64)) { Results = [Storage.Gpr(0)], Defines = [returned] }, new Jump(0x1101, merge.Start)];
            merge.Statements = [new Phi(0x1200, joined, [entry, returned]), new Define(0x1201, final, new Insert(new Use(joined, 64), Expr.C(0, 8), 0)),
                new Return(0x1202) { Value = new Use(final, 8) }];
            MachineFunction.AddEdge(head, merge); MachineFunction.AddEdge(head, initialize); MachineFunction.AddEdge(initialize, merge);
            // Branch 的两条正常后继按跳转、落空排序；phi 来源仍对应 merge 的前驱顺序。
            head.Successors.Reverse();
            var function = new MachineFunction { Entry = head.Start, Range = new(head.Start, 0x1203, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [head, initialize, merge] };
            function.Renumber();
            Propagate.Run(function, Dominators.Compute(function));
            Check(SsaCheck.Verify(function, Dominators.Compute(function)).Count == 0, "守卫合流的位片传播保持 SSA");
            Check((merge.Statements.OfType<Return>().Single().Value is Const { Value: 0, Width: 8 }) == !fromMemory,
                "返回低字节不依赖守卫两臂的调用返回高位，但不得隐藏另一臂读取");
        }
        PhiReturns();
        SnapshotReturns();
        PhiPredicateTests.Run();
    }

    private static void SnapshotReturns()
    {
        var cases = 0;
        foreach (var insertedWidth in new[] { 8, 16, 32 })
        foreach (var observedWidth in new[] { 8, 16, 32, 64 })
        foreach (var origin in new[] { "entry", "call", "load", "intrinsic" })
        foreach (var lowOrigin in new[] { "load", "derived-load", "call", "intrinsic" })
        foreach (var fullUse in new[] { false, true })
        {
            var input = new Variable(Storage.Gpr(0), 0); var source = input with { Version = 1 }; var written = input with { Version = 2 };
            var snapshot = new Variable(new Storage(Bank.Temp, 100, 64), 1);
            var boolean = new Variable(new Storage(Bank.Temp, 101, 8), 1);
            var block = new Block(0x1000) { End = 0x1020 };
            if (origin == "call") block.Statements.Add(new Call(0x1000, CallKind.Direct, Expr.C(0x2000, 64)) { Results = [source.Storage], Defines = [source] });
            if (origin == "load") block.Statements.Add(new Define(0x1001, source, new Load(Expr.C(0x6000, 64), 64)));
            if (origin == "intrinsic") block.Statements.Add(new Define(0x1001, source, new Intrinsic("unmodeled_effect", [], 64)));
            if (lowOrigin is "load" or "derived-load") block.Statements.Add(new Define(0x1002, snapshot, new Load(Expr.C(0x4000, 64), 64)));
            if (lowOrigin == "call") block.Statements.Add(new Call(0x1002, CallKind.Direct, Expr.C(0x2100, 64)) { Results = [snapshot.Storage], Defines = [snapshot] });
            if (lowOrigin == "intrinsic") block.Statements.Add(new Define(0x1002, snapshot, new Intrinsic("unmodeled_effect", [], 64)));
            Expr low = new Use(snapshot, insertedWidth);
            if (lowOrigin == "derived-load")
            {
                block.Statements.Add(new Define(0x1003, boolean, new Cpp2CS.Ir.Convert(ConvKind.ZeroExtend,
                    new Compare(Cond.Ne, new Use(snapshot, 64), Expr.C(0, 64)), 8)));
                low = insertedWidth == 8 ? new Use(boolean, 8) : new Cpp2CS.Ir.Convert(ConvKind.ZeroExtend, new Use(boolean, 8), insertedWidth);
            }
            // 读取之后改写同一内存，投影必须继续使用原快照。
            block.Statements.Add(new Store(0x1004, Expr.C(0x4000, 64), Expr.C(0xfedcba9876543210, 64)));
            block.Statements.Add(new Define(0x1005, written, new Insert(new Use(origin == "entry" ? input : source, 64), low, 0)));
            if (fullUse) block.Statements.Add(new Store(0x1006, Expr.C(0x5000, 64), new Use(written, 64)));
            block.Statements.Add(new Return(0x1007) { Value = new Use(written, observedWidth) });
            var function = new MachineFunction { Entry = block.Start, Range = new(block.Start, block.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            Propagate.Run(function, Dominators.Compute(function));
            Check(SsaCheck.Verify(function, Dominators.Compute(function)).Count == 0, "保留快照的部分寄存器投影保持 SSA");
            var ret = block.Statements.OfType<Return>().Single().Value!;
            var forwarded = !ExprMap.Walk(ret).OfType<Use>().Any(u => u.Variable == written);
            Check(forwarded == (observedWidth <= insertedWidth && origin is "entry" or "call"), "只拒绝被丢弃来源的读取与未知操作");
            Check(block.Statements.OfType<Define>().Count(d => d.Value is Load) == (origin == "load" ? 1 : 0) + (lowOrigin is "load" or "derived-load" ? 1 : 0),
                "投影保留全部读取，不重复求值或隐藏被丢弃高位的读取");
            if (origin == "intrinsic" || lowOrigin == "intrinsic")
            {
                Check(block.Statements.OfType<Define>().Any(d => d.Value is Intrinsic), "保留未知操作");
                continue;
            }
            foreach (var bits in new[] { 0UL, 1UL, 0x12345678UL, 0x8000000000000000UL, ulong.MaxValue })
            {
                const ulong initial = 0x9876543210abcdef;
                const ulong returned = 0x89abcdef01234567;
                var values = new Dictionary<Variable, ulong> { [input] = initial };
                var evaluator = new Evaluator();
                for (var i = 0; i < 8; i++)
                {
                    evaluator.Written[0x4000UL + (ulong)i] = (byte)(bits >> (8 * i));
                    evaluator.Written[0x6000UL + (ulong)i] = (byte)(returned >> (8 * i));
                }
                ulong Eval(Expr expression) => (ulong)evaluator.Eval(ExprMap.Map(expression, node => node is Use use ? Expr.C(values[use.Variable], use.Width) : null));
                ulong actual = 0; ulong? stored = null; var calls = 0;
                foreach (var statement in block.Statements)
                    switch (statement)
                    {
                        case Define d: values[d.Target] = Eval(d.Value); break;
                        case Call c: values[c.Defines.Single()] = c.Address == 0x1000 ? returned : bits; calls++; break;
                        case Store s:
                            var address = Eval(s.Target); var value = Eval(s.Value);
                            if (address == 0x5000) stored = value;
                            for (var i = 0; i < s.Value.Width / 8; i++) evaluator.Written[address + (ulong)i] = (byte)(value >> (8 * i));
                            break;
                        case Return r: actual = Eval(r.Value!); break;
                    }
                var rawLow = lowOrigin == "derived-load" ? bits == 0 ? 0UL : 1UL : bits;
                var expected = ((origin == "entry" ? initial : returned) & ~Expr.Mask(insertedWidth)) | (rawLow & Expr.Mask(insertedWidth));
                Check(actual == (expected & Expr.Mask(observedWidth)) && (!fullUse || stored == expected), "读取快照与原生低位插入、完整高位观察一致");
                Check(calls == (origin == "call" ? 1 : 0) + (lowOrigin == "call" ? 1 : 0) && evaluator.Failure is null, "执行对照保持调用次数");
                cases++;
            }
        }
        Console.WriteLine($"部分寄存器读取快照执行对照通过：{cases} 组输入，保留读取时机与完整位型");
    }

    private static void PhiReturns()
    {
        var cases = 0;
        foreach (var insertedWidth in new[] { 8, 32 })
        foreach (var observedWidth in new[] { 8, 16, 32, 64 })
        foreach (var origin in new[] { "entry", "call", "load", "intrinsic", "inserted-load" })
        foreach (var fullUse in new[] { false, true })
        {
            var head = new Block(0x1000); var left = new Block(0x1100); var right = new Block(0x1200); var merge = new Block(0x1300);
            var input = new Variable(Storage.Gpr(0), 0); var result = input with { Version = 1 };
            var first = input with { Version = 2 }; var second = input with { Version = 3 }; var joined = input with { Version = 4 };
            var parameter = new Use(new Variable(Storage.Gpr(1), 0), 64);
            head.Statements = [new Branch(head.Start, new Compare(Cond.Ne, parameter, Expr.C(0, 64)), left.Start, right.Start)];
            Expr Base() => origin is "entry" or "inserted-load" ? new Use(input, 64) : new Use(result, 64);
            left.Statements = [new Define(left.Start, first, new Insert(Base(), origin == "inserted-load" ? new Use(result, insertedWidth) : Expr.C(0x97531, insertedWidth), 0)), new Jump(left.Start + 1, merge.Start)];
            if (origin == "call") left.Statements.Insert(0, new Call(left.Start, CallKind.Direct, Expr.C(0x2000, 64)) { Results = [Storage.Gpr(0)], Defines = [result] });
            if (origin is "load" or "inserted-load") left.Statements.Insert(0, new Define(left.Start, result, new Load(Expr.C(0x4000, 64), 64)));
            if (origin == "intrinsic") left.Statements.Insert(0, new Define(left.Start, result, new Intrinsic("unmodeled_effect", [], 64)));
            right.Statements = [new Define(right.Start, second, new Insert(new Use(input, 64), Expr.C(0xabcde, insertedWidth), 0)), new Jump(right.Start + 1, merge.Start)];
            merge.Statements = [new Phi(merge.Start, joined, [first, second]), new Return(merge.Start + 2) { Value = new Use(joined, observedWidth) }];
            if (fullUse) merge.Statements.Insert(1, new Store(merge.Start + 1, Expr.C(0x5000, 64), new Use(joined, 64)));
            MachineFunction.AddEdge(head, left); MachineFunction.AddEdge(head, right); MachineFunction.AddEdge(left, merge); MachineFunction.AddEdge(right, merge);
            var function = new MachineFunction { Entry = head.Start, Range = new(head.Start, merge.Start + 3, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [head, left, right, merge] };
            function.Renumber();
            Propagate.Run(function, Dominators.Compute(function));
            Check(SsaCheck.Verify(function, Dominators.Compute(function)).Count == 0, "窄 φ 保持前驱对应和定义支配关系");
            if (observedWidth <= insertedWidth && origin is "entry" or "call" or "inserted-load")
                Check(merge.Statements.OfType<Phi>().Any(p => p.Target.Width == observedWidth), "为低位观察建立独立合流");
            if (origin is "load" or "intrinsic" or "inserted-load")
                Check(left.Statements.OfType<Define>().Any(d => d.Value is Load or Intrinsic), "合流投影不能隐藏读取或未知操作");
            if (origin == "call") Check(left.Statements.OfType<Call>().Count() == 1, "合流投影保留调用");
            if (origin == "intrinsic") continue;
            var random = new Random(82117);
            foreach (var side in new[] { false, true })
            for (var iteration = 0; iteration < 16; iteration++)
            {
                var initial = (ulong)random.NextInt64() | (1UL << 63); var returned = (ulong)random.NextInt64();
                var values = new Dictionary<Variable, ulong> { [input] = initial, [parameter.Variable] = side ? 1UL : 0UL };
                var evaluator = new Evaluator();
                for (var i = 0; i < 8; i++) evaluator.Written[0x4000UL + (ulong)i] = (byte)(returned >> (i * 8));
                ulong Eval(Expr expression) => (ulong)evaluator.Eval(ExprMap.Map(expression, node => node is Use use ? Expr.C(values[use.Variable], use.Width) : null));
                var block = head; Block? previous = null; ulong actual = 0; ulong? stored = null; var calls = 0;
                for (var step = 0; step < 8 && block is not null; step++)
                {
                    Block? next = null;
                    foreach (var statement in block.Statements)
                        switch (statement)
                        {
                            case Phi phi: values[phi.Target] = values[phi.Sources[block.Predecessors.IndexOf(previous!)]]; break;
                            case Define d: values[d.Target] = Eval(d.Value); break;
                            case Call call: values[call.Defines.Single()] = returned; calls++; break;
                            case Store store: stored = Eval(store.Value); break;
                            case Branch branch: next = function.Blocks.Single(b => b.Start == (Eval(branch.Condition) != 0 ? branch.Target : branch.Fallthrough)); break;
                            case Jump jump: next = function.Blocks.Single(b => b.Start == jump.Target); break;
                            case Return ret: actual = Eval(ret.Value!); break;
                        }
                    previous = block; block = next;
                }
                var high = side && origin is "call" or "load" ? returned : initial;
                var low = side ? origin == "inserted-load" ? returned : 0x97531UL : 0xabcdeUL;
                var expected = (high & ~Expr.Mask(insertedWidth)) | (low & Expr.Mask(insertedWidth));
                Check(actual == (expected & Expr.Mask(observedWidth)) && (!fullUse || stored == expected), "窄与完整观察分别保持原生位型");
                Check(calls == (side && origin == "call" ? 1 : 0), "执行路径保持调用次数");
                Check(evaluator.Failure is null, "窄 φ 执行对照完成");
                cases++;
            }
        }
        Console.WriteLine($"部分寄存器合流执行对照通过：{cases} 组输入");
    }

    private static void Check(bool condition, string reason) { if (!condition) throw new InvalidOperationException(reason); }
}

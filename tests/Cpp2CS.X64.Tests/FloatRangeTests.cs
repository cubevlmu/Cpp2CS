using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Ssa;
using Cpp2CS.Recovery.Shape;
using Cpp2CS.Recovery.Values;

namespace Cpp2CS.X64.Tests;

internal static class FloatRangeTests
{
    internal static void Run()
    {
        var syms = new SymTable();
        foreach (var width in new[] { 32, 64 })
        {
            var x = syms.Arg(0, width); var y = syms.Arg(1, width); var zero = syms.Const(0, width);
            var squared = syms.Binary(BinOp.FMul, x, x, width);
            var sum = syms.Binary(BinOp.FAdd, squared, syms.Binary(BinOp.FMul, y, y, width), width);
            var absolute = syms.Unary(UnOp.FAbs, x, width);
            var root = syms.Unary(UnOp.FSqrt, x, width);
            var unsigned = syms.Convert(ConvKind.UIntToFloat, syms.Arg(2, 64), width);
            var converted = syms.Convert(ConvKind.FloatToFloat, syms.Binary(BinOp.FMul, syms.Arg(3, 32), syms.Arg(3, 32), 32), width);
            foreach (var value in new[] { squared, sum, absolute, root, unsigned, converted })
            {
                Check(FloatRangeBranches.Constant(syms.Compare(Cond.FLt, value, zero)) == false, "非负或 NaN 不满足有序小于零");
                Check(FloatRangeBranches.Constant(syms.Compare(Cond.FGt, zero, value)) == false, "交换操作数保持证明");
                Check(FloatRangeBranches.Constant(syms.Compare(Cond.FUge, value, zero)) == true, "无序或大于等于零恒真");
                Check(FloatRangeBranches.Constant(syms.Compare(Cond.FGe, value, zero)) is null, "NaN 仍可能使有序大于等于零为假");
                var unordered = syms.Logical(false, syms.Compare(Cond.FUnordered, zero, zero), syms.Compare(Cond.FUnordered, value, value));
                var carry = syms.Binary(BinOp.Or, syms.ZeroExtend(unordered, 8), syms.ZeroExtend(syms.Compare(Cond.FLt, zero, value), 8), 8);
                var equal = syms.Binary(BinOp.Or, syms.ZeroExtend(unordered, 8), syms.ZeroExtend(syms.Compare(Cond.FEq, zero, value), 8), 8);
                var above = syms.Not(syms.Logical(false, syms.Compare(Cond.Ne, carry, syms.Const(0, 8)), syms.Compare(Cond.Ne, equal, syms.Const(0, 8))));
                Check(FloatRangeBranches.Constant(above) == false, "P-code CF/ZF/PF 链须保留无序关系并核对完整条件：" + above);
            }
            foreach (var value in new[] { syms.Binary(BinOp.FMul, x, y, width), syms.Binary(BinOp.FSub, squared, sum, width),
                syms.Unary(UnOp.FNeg, squared, width), syms.Convert(ConvKind.Bitcast, syms.Arg(4, width), width) })
                Check(FloatRangeBranches.Constant(syms.Compare(Cond.FLt, value, zero)) is null, "未知乘积、减法、变号和位型不提供非负证明");
            var first = syms.Read(new Nop(1, ""), 0, syms.Arg(7, 64), width);
            var later = syms.Read(new Nop(2, ""), 0, syms.Arg(7, 64), width);
            Check(FloatRangeBranches.Constant(syms.Compare(Cond.FLt, syms.Binary(BinOp.FMul, first, later, width), zero)) is null,
                "同址不同快照不能冒充平方");
            Cfg(width);
        }
        if (Sse.IsSupported && Sse2.IsSupported)
        {
            uint[] edges = [0, 0x80000000, 1, 0x80000001, 0x00800000, 0x80800000, 0x3f800000, 0xbf800000,
                0x7f7fffff, 0xff7fffff, 0x7f800000, 0xff800000, 0x7fc01234, 0xffc01234, 0x7f801234, 0xff801234];
            var random = new Random(49781); var count = 0;
            for (var i = 0; i < 4096; i++)
            {
                var x = BitConverter.UInt32BitsToSingle(i < edges.Length ? edges[i] : (uint)random.NextInt64(1L << 32));
                var y = BitConverter.UInt32BitsToSingle(i < edges.Length ? edges[edges.Length - i - 1] : (uint)random.NextInt64(1L << 32));
                var vx = Vector128.CreateScalar(x); var vy = Vector128.CreateScalar(y);
                var sum = Sse.AddScalar(Sse.MultiplyScalar(vx, vx), Sse.MultiplyScalar(vy, vy));
                var converted = Sse2.ConvertToVector128Double(sum).GetElement(0);
                Check(!(0.0 > converted) && (double.IsNaN(converted) || converted >= 0.0), "独立 SSE 平方和及扩宽保持可行关系");
                count++;
            }
            Console.WriteLine($"浮点范围与 NaN 条件对照通过：{count} 组 SSE 输入");
        }
    }

    private static void Cfg(int width)
    {
        var start = new Block(0x1000); var bad = new Block(0x1100); var good = new Block(0x1200); var end = new Block(0x1300);
        var input = new Use(new Variable(Storage.Gpr(1), 0), width);
        var square = new Variable(Storage.Temp(2000), 1); var left = new Variable(Storage.Gpr(0), 1);
        var right = left with { Version = 2 }; var merged = left with { Version = 3 };
        start.Statements = [new Store(0x1000, Expr.C(0x4000, 64), Expr.C(7, 32)),
            new Define(0x1001, square, new Binary(BinOp.FMul, input, input, width)),
            new Branch(0x1002, new Compare(Cond.FLt, new Use(square, width), Expr.C(0, width)), bad.Start, good.Start)];
        bad.Statements = [new Call(0x1100, CallKind.Direct, Expr.C(0x9999, 64)), new Define(0x1101, left, Expr.C(11, 64)), new Jump(0x1102, end.Start)];
        good.Statements = [new Define(0x1200, right, Expr.C(22, 64)), new Jump(0x1201, end.Start)];
        end.Statements = [new Phi(0x1300, merged, [left, right]), new Return(0x1301) { Value = new Use(merged, 64) }];
        MachineFunction.AddEdge(start, bad); MachineFunction.AddEdge(start, good); MachineFunction.AddEdge(bad, end); MachineFunction.AddEdge(good, end);
        var function = new MachineFunction { Entry = start.Start, Range = new(start.Start, 0x1302, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate),
            Blocks = [start, bad, good, end] };
        function.Renumber();
        Check(FloatRangeBranches.Run(function, ValueModel.Build(function, new Inputs())) == 1, "独立 SSA 图须删去不可行分支");
        Check(Lowering.Cleanup(function).Count == 0, "删除边后修复 phi 并保持 SSA");
        Check(!function.Blocks.SelectMany(b => b.Statements).OfType<Call>().Any()
            && function.Blocks.SelectMany(b => b.Statements).OfType<Store>().Count() == 1
            && function.Blocks.SelectMany(b => b.Statements).OfType<Return>().Single().Value is Const { Value: 22 },
            "只删除不可达调用，保留分支前写入和正确返回来源");
    }

    private sealed class Inputs : IValueEnvironment
    {
        public Sym? Entry(SymTable syms, Storage storage) => syms.Arg(storage.Index, storage.Width);
        public Sym? CallResult(SymTable syms, Call call, int index, IReadOnlyList<Sym> arguments) => null;
        public Sym? MetadataRead(SymTable syms, Sym address, int width) => null;
    }

    private static void Check(bool condition, string reason) { if (!condition) throw new InvalidOperationException(reason); }
}

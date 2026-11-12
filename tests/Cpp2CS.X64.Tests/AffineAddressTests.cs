using Cpp2CS.Ir;
using Cpp2CS.Recovery.Memory;
using Cpp2CS.Recovery.Typing;
using Cpp2CS.Recovery.Values;

namespace Cpp2CS.X64.Tests;

internal static class AffineAddressTests
{
    internal static void Run()
    {
        var s = new SymTable();
        var root = s.Local(LocalSpace.Copy(0), 0);
        var other = s.Local(LocalSpace.Copy(1), 0);
        var i = s.Arg(0, 64); var j = s.Arg(1, 64);
        Sym Add(Sym a, Sym b) => s.Binary(BinOp.Add, a, b, 64);
        Sym Mul(Sym a, ulong k) => s.Binary(BinOp.Mul, a, s.Const(k, 64), 64);
        var cases = new[]
        {
            Add(root, Mul(Add(i, Mul(i, 2)), 4)),
            Add(Add(Add(root, Mul(i, 8)), Mul(i, 4)), s.Const(32, 64)),
            Add(root, Mul(Add(Add(i, j), Mul(Add(i, j), 2)), 4)),
        };
        var inputs = new ulong[] { 0, 1, 2, 0x40000000, 0xffffffff, 0x8000000000000000, ulong.MaxValue };
        foreach (var expression in cases)
        {
            var form = AffineAddress.Normalize(expression)!;
            Check(form.Decompose(s, x => x is LocalSym, out var normalized) && normalized.Root == root && normalized.Scale == 12,
                "同宽乘加应保留根并归一为十二字节步长");
            foreach (var a in inputs) foreach (var b in inputs)
            {
                ulong Eval(Sym value) => value switch
                {
                    LocalSym => 0x12340000,
                    ArgSym argument => argument.Index == 0 ? a : b,
                    ConstSym constant => constant.Value,
                    OpSym { Op.Kind: OperatorKind.Binary } op when op.Op.Binary == BinOp.Add => unchecked(Eval(op.Args[0]) + Eval(op.Args[1])),
                    OpSym { Op.Kind: OperatorKind.Binary } op when op.Op.Binary == BinOp.Mul => unchecked(Eval(op.Args[0]) * Eval(op.Args[1])),
                    _ => throw new InvalidOperationException("夹具包含未定义运算"),
                };
                var expected = Eval(expression);
                var actual = unchecked(Eval(root) + (ulong)normalized.Offset + Eval(normalized.Index!) * (ulong)normalized.Scale);
                Check(actual == expected, "归一必须保留64位模算术，包括溢出输入");
            }
        }
        var truncated = s.Convert(ConvKind.ZeroExtend, s.Binary(BinOp.Mul, s.Arg(2, 32), s.Const(0x40000000, 32), 32), 64);
        var barrier = AffineAddress.Normalize(Add(root, truncated))!;
        Check(barrier.Terms.ContainsKey(truncated), "32位截断后扩展必须保留为原子，不跨扩展提取系数");
        Check(!AffineAddress.Normalize(Add(root, other))!.Decompose(s, x => x is LocalSym, out _), "不同存储根不能合并成单一根");
        var product = s.Binary(BinOp.Mul, i, j, 64);
        Check(AffineAddress.Normalize(Add(root, product))!.Terms.ContainsKey(product), "变量乘变量必须保留原子");
        Console.WriteLine("仿射地址归一通过：147组模算术对照，扩展屏障、不同存储根和非线性原子保留");
    }

    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}

using Cpp2CS.Ir;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class NativeTests
{
    public static void Run(string sla)
    {
        using var decoder = new SleighDecoder(sla);
        FrameModelTests.Run();
        FloatRangeTests.Run();
        PartialRegisterTests.Run();
        ReferenceTests.Run(decoder);
        FenceTests.Run(decoder);
        List<Stmt> Lift(string bytes)
        {
            var code = System.Convert.FromHexString(bytes);
            var instruction = decoder.Decode(0x1000, code);
            Check(instruction.Length == code.Length, "指令长度");
            var result = new List<Stmt>();
            PcodeLowerer.Lower(instruction, result);
            Check(!result.OfType<Opaque>().Any(), string.Join("; ", result));
            return result;
        }

        // 同一地址替换字节必须使 SLEIGH 缓存失效；省略 pspec 也必须按长模式解码。
        var mov1 = Lift("B801000000");
        var mov2 = Lift("B802000000");
        Check(Execute(mov1, ulong.MaxValue, 0).Get(Storage.Gpr(0)) == 1, "EAX 清零扩展");
        Check(Execute(mov2, 0, 0).Get(Storage.Gpr(0)) == 2, "解码缓存失效");
        var add = Lift("4801D0");
        var sub = Lift("4829D0");
        var cmp = Lift("4839D0");
        var cmov = Lift("480F45C2");
        foreach (var zero in new[] { 0u, 1u })
        {
            var state = new Evaluator();
            state.Registers[Storage.Gpr(0)] = 12;
            state.Registers[Storage.Gpr(2)] = 34;
            state.Registers[new(Bank.Temp, 201, 8)] = zero;
            state.Run(cmov, 0x1000, 0x1004);
            Check(state.Failure is null && state.Get(Storage.Gpr(0)) == (zero == 0 ? 34u : 12u), $"CMOVNE ZF={zero} result={state.Get(Storage.Gpr(0))}: {string.Join("; ", cmov)}");
        }
        Check(Lift("C3") is [Return], "RET 归一");
        Check(Lift("C20000") is [Return], "RET 0 归一");
        var cleanup = new List<Stmt>();
        PcodeLowerer.Lower(decoder.Decode(0x1000, System.Convert.FromHexString("C20800")), cleanup);
        Check(cleanup is [Opaque], "非零清栈量不能被忽略");
        Check(Lift("E801000000") is [Call], "CALL 归一");
        var packedSqrt = Lift("660F51C1");
        if (System.Runtime.Intrinsics.X86.Sse2.IsSupported)
        {
            double[] lanes = [0, -0.0, 2, 9, 0.125, double.PositiveInfinity, -1, double.NaN];
            foreach (var low in lanes)
            foreach (var high in lanes)
            {
                var input = System.Runtime.Intrinsics.Vector128.Create(low, high);
                var hardware = System.Runtime.Intrinsics.X86.Sse2.Sqrt(input);
                var state = new Evaluator();
                state.Registers[Storage.Vec(0)] = UInt128.MaxValue;
                state.Registers[Storage.Vec(1)] = ((UInt128)BitConverter.DoubleToUInt64Bits(high) << 64) | BitConverter.DoubleToUInt64Bits(low);
                state.Run(packedSqrt, 0x1000, 0x1004);
                var actual = state.Get(Storage.Vec(0));
                for (var lane = 0; lane < 2; lane++)
                {
                    var bits = (ulong)(actual >> (lane * 64));
                    var expected = System.Runtime.Intrinsics.Vector128.GetElement(hardware, lane);
                    Check(state.Failure is null && (double.IsNaN(expected) ? double.IsNaN(BitConverter.UInt64BitsToDouble(bits)) : bits == BitConverter.DoubleToUInt64Bits(expected)), "SQRTPD 独立双通道硬件对照");
                }
            }
            Console.WriteLine("SQRTPD 硬件结果对照通过：64 组双通道输入（NaN 比较分类）");
        }
        var values = new ulong[] { 0, 1, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000, ulong.MaxValue, 0x123456789ABCDEF0 };
        foreach (var a in values)
        foreach (var b in values)
        foreach (var subtract in new[] { false, true })
        {
            var state = Execute(subtract ? sub : add, a, b);
            var expected = subtract ? unchecked(a - b) : unchecked(a + b);
            Check(state.Get(Storage.Gpr(0)) == expected, "整数结果");
            Check(state.Get(new(Bank.Temp, 200, 8)) == ((subtract ? a < b : expected < a) ? 1u : 0u), "CF");
            var signed = subtract ? (Int128)(long)a - (long)b : (Int128)(long)a + (long)b;
            Check(state.Get(new(Bank.Temp, 203, 8)) == (signed < long.MinValue || signed > long.MaxValue ? 1u : 0u), "OF");
            Check(state.Get(new(Bank.Temp, 201, 8)) == (expected == 0 ? 1u : 0u), "ZF");
            Check(state.Get(new(Bank.Temp, 202, 8)) == (expected >> 63), "SF");
            Check(state.Get(new(Bank.Temp, 204, 8)) == (System.Numerics.BitOperations.PopCount((uint)(byte)expected) % 2 == 0 ? 1u : 0u), "PF");
            var compared = Execute(cmp, a, b);
            Check(compared.Get(Storage.Gpr(0)) == a, "CMP 保留操作数");
        }
        var scalar = Lift("F30F58C1");
        var fp = new Evaluator();
        fp.Registers[Storage.Vec(0)] = ((UInt128)0xDEADBEEF << 64) | BitConverter.SingleToUInt32Bits(1.5f);
        fp.Registers[Storage.Vec(1)] = BitConverter.SingleToUInt32Bits(2.25f);
        fp.Run(scalar, 0x1000, 0x1004);
        Check(fp.Failure is null && (uint)fp.Get(Storage.Vec(0)) == BitConverter.SingleToUInt32Bits(3.75f), "ADDSS");
        Check((ulong)(fp.Get(Storage.Vec(0)) >> 64) == 0xDEADBEEF, "ADDSS 保留高位");
        var trunc = Lift("F20F2CC0");
        foreach (var input in new[] { -3.75, 0, 3.75, double.NaN, double.PositiveInfinity, double.NegativeInfinity, 2147483648.0 })
        {
            var state = new Evaluator();
            state.Registers[Storage.Vec(0)] = BitConverter.DoubleToUInt64Bits(input);
            state.Run(trunc, 0x1000, 0x1004);
            var expected = double.IsNaN(input) || input < int.MinValue || input >= 2147483648.0 ? 0x80000000u : unchecked((uint)(int)input);
            Check(state.Failure is null && state.Get(Storage.Gpr(0)) == expected, "CVTTSD2SI 越界与 NaN");
        }
        var vector = Lift("660FEFC0");
        var vectorState = new Evaluator();
        vectorState.Registers[Storage.Vec(0)] = UInt128.MaxValue;
        vectorState.Run(vector, 0x1000, 0x1004);
        Check(vectorState.Failure is null && vectorState.Get(Storage.Vec(0)) == 0, "PXOR 清零");
        Console.WriteLine("SLEIGH 原生指令语义测试通过");
    }

    private static Evaluator Execute(List<Stmt> statements, ulong a, ulong b)
    {
        var state = new Evaluator();
        state.Registers[Storage.Gpr(0)] = a;
        state.Registers[Storage.Gpr(2)] = b;
        state.Run(statements, 0x1000, 0x1003);
        Check(state.Failure is null, state.Failure ?? "");
        return state;
    }

    private static void Check(bool condition, string reason)
    {
        if (!condition) throw new InvalidOperationException(reason);
    }
}




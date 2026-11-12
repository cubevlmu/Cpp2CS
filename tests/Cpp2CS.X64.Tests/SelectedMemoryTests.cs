using System.Runtime.InteropServices;
using Cpp2CS.Ir;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Recovery.Shape;

namespace Cpp2CS.X64.Tests;

internal static class SelectedMemoryTests
{
    [UnmanagedFunctionPointer(System.Runtime.InteropServices.CallingConvention.Cdecl)]
    private delegate int Native(nint left, nint right, int flag, int value);

    internal static void NativeCheck(byte[] code, string variant)
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != System.Runtime.InteropServices.Architecture.X64) return;
        var left = Marshal.AllocHGlobal(32); var right = Marshal.AllocHGlobal(32);
        try
        {
            HardwareTests.WithCode(code, pointer =>
            {
                var invoke = Marshal.GetDelegateForFunctionPointer<Native>(pointer);
                foreach (var number in new[] { int.MinValue, -1, 0, 1, 17, int.MaxValue })
                    foreach (var flag in new[] { false, true })
                    {
                        Marshal.WriteInt32(left, 24, number); Marshal.WriteInt32(left, 28, ~number); Marshal.WriteInt32(right, 24, ~number);
                        var expected = flag ? ~number : number;
                        if (variant == "select-null-store") { if (!flag) Check(invoke(left, 0, 41, 0) == 41 && Marshal.ReadInt32(left, 24) == 41); }
                        else if (variant == "select-field") Check(invoke(left, flag ? 1 : 0, 0, 0) == expected);
                        else if (variant == "select-loop")
                        {
                            foreach (var count in new[] { -1, 0, 1, 3, 5 }) Check(invoke(left, flag ? 1 : 0, count, 0) == unchecked(expected * Math.Max(0, count)));
                            Check(invoke(0, flag ? 1 : 0, 0, 0) == 0);
                        }
                        else if (variant == "select-object") Check(invoke(flag ? 0 : left, flag ? right : 0, flag ? 1 : 0, 0) == expected);
                        else
                        {
                            Check(invoke(flag ? 0 : left, flag ? right : 0, flag ? 1 : 0, 41) == 41);
                            Check(Marshal.ReadInt32(flag ? left : right, 24) == (flag ? number : ~number));
                        }
                    }
            });
        }
        finally { Marshal.FreeHGlobal(left); Marshal.FreeHGlobal(right); }
    }

    internal static void Rejections()
    {
        Expr entry = new Entry(Storage.Gpr(1));
        var condition = new Compare(Cond.Ne, entry, Expr.C(0, 64));
        var choice = new Select(condition, Expr.C(24, 64), Expr.C(28, 64), 64);
        Expr address = new Binary(BinOp.Add, entry, choice, 64);
        foreach (var mode in new[] { "condition-effect", "address-effect", "lazy-value", "handler" })
        {
            var block = new Block(0x1000) { End = 0x1010 };
            var selectedAddress = mode switch
            {
                "condition-effect" => choice with { Condition = new Intrinsic("opaque_condition", [entry], 1) },
                "address-effect" => choice with { True = new Load(entry, 64) },
                _ => address,
            };
            Expr read = new Load(selectedAddress, 32);
            if (mode == "lazy-value") read = new Select(condition, new Load(address, 32), Expr.C(0, 32), 32);
            block.Statements.Add(new Define(0x1001, new Variable(Storage.Gpr(0), 1), read));
            block.Statements.Add(new Return(0x1002));
            var function = new MachineFunction { Entry = block.Start, Range = new(0x1000, 0x1010, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate), Blocks = [block] };
            if (mode == "handler")
            {
                var handler = new Block(0x2000) { IsLandingPad = true };
                block.Handler = handler; block.Successors.Add(handler); handler.Predecessors.Add(block); function.Blocks.Add(handler);
            }
            if (SelectedMemoryPaths.Run(function) != 0) throw new InvalidOperationException("条件访存不能跨效果、惰性求值或未处理异常边：" + mode);
        }
    }

    private static void Check(bool valid) { if (!valid) throw new InvalidOperationException("条件访存机器码的独立硬件结果不符"); }
}

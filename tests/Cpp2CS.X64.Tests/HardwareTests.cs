using System.ComponentModel;
using System.Runtime.InteropServices;
using Cpp2CS.Ir;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class HardwareTests
{
    internal static void WithCode(byte[] code, Action<IntPtr> action)
    {
        var memory = VirtualAlloc(IntPtr.Zero, (nuint)code.Length, 0x3000, 0x04);
        if (memory == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            Marshal.Copy(code, 0, memory, code.Length);
            if (!VirtualProtect(memory, (nuint)code.Length, 0x20, out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!FlushInstructionCache(GetCurrentProcess(), memory, (nuint)code.Length)) throw new Win32Exception(Marshal.GetLastWin32Error());
            action(memory);
        }
        finally { if (!VirtualFree(memory, 0, 0x8000)) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    }
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate ulong NativeBinary(ulong left, ulong right);

    public static void Run(string sla)
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != System.Runtime.InteropServices.Architecture.X64)
        {
            Console.WriteLine("跳过硬件对照：要求 Windows x64 进程");
            return;
        }
        using var decoder = new SleighDecoder(sla);
        var random = new Random(7319);
        var cases = 0;
        foreach (var operation in new[] { "4801D0", "4829D0", "4839D0" })
        {
            // RCX/RDX 是宿主 Win64 实参；RFLAGS 作为独立观测结果返回。
            var code = System.Convert.FromHexString("4889C8" + operation + "9C58C3");
            var memory = VirtualAlloc(IntPtr.Zero, (nuint)code.Length, 0x3000, 0x04);
            if (memory == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                Marshal.Copy(code, 0, memory, code.Length);
                if (!VirtualProtect(memory, (nuint)code.Length, 0x20, out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
                if (!FlushInstructionCache(GetCurrentProcess(), memory, (nuint)code.Length)) throw new Win32Exception(Marshal.GetLastWin32Error());
                var native = Marshal.GetDelegateForFunctionPointer<NativeBinary>(memory);
                var instruction = decoder.Decode(0x1000, System.Convert.FromHexString(operation));
                var statements = new List<Stmt>();
                PcodeLowerer.Lower(instruction, statements);
                for (var i = 0; i < 128; i++)
                {
                    var left = BitConverter.ToUInt64(RandomBytes());
                    var right = BitConverter.ToUInt64(RandomBytes());
                    var flags = native(left, right);
                    var evaluator = new Evaluator();
                    evaluator.Registers[Storage.Gpr(0)] = left;
                    evaluator.Registers[Storage.Gpr(2)] = right;
                    evaluator.Run(statements, 0x1000, 0x1003);
                    if (evaluator.Failure is not null) throw new InvalidOperationException(evaluator.Failure);
                    foreach (var (index, bit) in new[] { (200, 0), (201, 6), (202, 7), (203, 11), (204, 2) })
                        if (evaluator.Get(new(Bank.Temp, index, 8)) != ((flags >> bit) & 1))
                            throw new InvalidOperationException($"硬件标志位对照失败：{operation} {left:x} {right:x} bit{bit}");
                    cases++;
                }
            }
            finally
            {
                if (!VirtualFree(memory, 0, 0x8000)) throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        Console.WriteLine($"x64 硬件标志位对照通过：{cases} 组输入，每组 5 个标志位");
        byte[] RandomBytes() { var bytes = new byte[8]; random.NextBytes(bytes); return bytes; }
    }

    [DllImport("kernel32", SetLastError = true)] private static extern IntPtr VirtualAlloc(IntPtr address, nuint size, uint allocation, uint protection);
    [DllImport("kernel32", SetLastError = true)] private static extern bool VirtualProtect(IntPtr address, nuint size, uint protection, out uint old);
    [DllImport("kernel32", SetLastError = true)] private static extern bool VirtualFree(IntPtr address, nuint size, uint operation);
    [DllImport("kernel32", SetLastError = true)] private static extern bool FlushInstructionCache(IntPtr process, IntPtr address, nuint size);
    [DllImport("kernel32")] private static extern IntPtr GetCurrentProcess();
}

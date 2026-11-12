using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Cpp2CS.Facts;
using Cpp2CS.Image;

namespace Cpp2CS.X64.Tests;

internal static class FieldHelperTests
{
    [UnmanagedFunctionPointer(System.Runtime.InteropServices.CallingConvention.Cdecl)]
    private delegate nint Address(nint receiver, nint field);

    internal static void Run(byte[] original, SleighDecoder decoder)
    {
        const ulong basis = 0x180000000;
        var checks = 0;
        foreach (var (parent, offset, bits, condition) in new[] { (16, 24, 40, 0x49), (16, 24, 40, 0x4d), (24, 32, 44, 0x49), (24, 32, 44, 0x4d) })
        {
            var bytes = original.ToArray(); var sections = bytes.AsSpan(0x128, 120).ToArray();
            Array.Clear(bytes, 0x128, 80); sections.CopyTo(bytes, 0x178);
            void U32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x94), 224); U32(0x104, 14); U32(0x108, 0x2000); U32(0x10c, 0x100);
            U32(0x414, 3); U32(0x418, 3); U32(0x41c, 0x2040); U32(0x420, 0x2050); U32(0x424, 0x2060);
            var names = new[] { "il2cpp_field_get_parent", "il2cpp_field_get_offset", "il2cpp_class_is_valuetype" };
            for (var i = 0; i < 3; i++)
            {
                U32(0x440 + i * 4, (uint)(0x10c0 + i * 16)); U32(0x450 + i * 4, (uint)(0x2080 + i * 32));
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x460 + i * 2), (ushort)i);
                System.Text.Encoding.ASCII.GetBytes(names[i] + "\0").CopyTo(bytes, 0x480 + i * 32);
            }
            System.Convert.FromHexString("E87B000000C3").CopyTo(bytes, 0x200); U32(0x704, 0x1006);
            var body = System.Convert.FromHexString("488B42004C6342004C03C183780000498D48F0490F49C8488BC1C3");
            body[3] = (byte)parent; body[7] = (byte)offset; body[13] = (byte)bits; body[21] = (byte)condition; body.CopyTo(bytes, 0x280);
            new byte[] { 0x48, 0x8b, 0x41, (byte)parent, 0xc3 }.CopyTo(bytes, 0x2c0);
            new byte[] { 0x48, 0x63, 0x41, (byte)offset, 0xc3 }.CopyTo(bytes, 0x2d0);
            new byte[] { 0x8b, 0x41, (byte)bits, 0xc1, 0xe8, 0x1f, 0xc3 }.CopyTo(bytes, 0x2e0);
            RuntimeHelper[] Identify(byte[] data)
            {
                var image = ImageDocument.Parse(data); var map = CodeMap.BuildPe(image, [basis + 0x1000]); var machine = new PcodeMachine(image, decoder);
                return X64FieldHelpers.Identify(map, X64References.Scan(map, machine, [basis + 0x1000]), machine).ToArray();
            }
            Check(Identify(bytes) is [{ Kind: HelperKind.FieldAddress, Address: basis + 0x1080 }], "完整字段地址体和三个导出访问器必须一致");
            for (var i = 0; i < body.Length; i++)
            {
                var changed = bytes.ToArray(); changed[0x280 + i] ^= 1;
                Check(Identify(changed).Length == 0, "地址体逐字节翻转低位的变异须拒绝"); checks++;
            }
            foreach (var at in new[] { 0x2c3, 0x2d3, 0x2e2, 0x2e5, 0x480 })
            {
                var changed = bytes.ToArray(); changed[at] ^= 1;
                Check(Identify(changed).Length == 0, "布局或类型位访问器冲突须拒绝"); checks++;
            }
            if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != System.Runtime.InteropServices.Architecture.X64) continue;
            HardwareTests.WithCode(body, pointer =>
            {
                var invoke = Marshal.GetDelegateForFunctionPointer<Address>(pointer);
                var storage = Marshal.AllocHGlobal(384);
                try
                {
                    var field = storage + 128; var klass = storage + 256; Marshal.WriteIntPtr(field + parent, klass);
                    foreach (var signedOffset in new[] { -16, -1, 0, 16, 24, 40, int.MaxValue })
                    foreach (var isValueType in new[] { false, true })
                    {
                        Marshal.WriteInt32(field + offset, signedOffset); Marshal.WriteInt32(klass + bits, isValueType ? int.MinValue : 0x7fffffff);
                        Check(invoke(storage, field) == storage + (nint)signedOffset - (isValueType ? 16 : 0), "引用和值类型的字段地址算术须与真实硬件一致");
                        Check(invoke(0, field) == (nint)signedOffset - (isValueType ? 16 : 0), "原生字段地址计算本身不检查空接收者");
                    }
                }
                finally { Marshal.FreeHGlobal(storage); }
            });
        }
        Console.WriteLine($"Win64 字段地址证明：两种导出布局、两种等价条件移动、112 组硬件地址对照及 {checks} 项代码／布局变异拒绝通过");
    }

    private static void Check(bool valid, string reason) { if (!valid) throw new InvalidOperationException(reason); }
}

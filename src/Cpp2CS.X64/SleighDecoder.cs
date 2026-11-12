using System.Runtime.InteropServices;
using System.Buffers.Binary;
using System.Text;

namespace Cpp2CS.X64;

/// <summary>空间、字节偏移、大小与寄存器别名；访存空间标识另存为稳定名称。</summary>
public sealed record PcodeVarnode(string Space, int SpaceType, ulong Offset, int Size, string? Register, string? ReferencedSpace = null);

/// <summary>保持原顺序的 P-code 运算。</summary>
public sealed record PcodeOperation(int Index, int Opcode, string Name,
    PcodeVarnode? Output, PcodeVarnode[] Inputs, string? UserOp = null);

public sealed record LiftedInstruction(ulong Address, int Length, PcodeOperation[] Operations, string? Mnemonic = null);

/// <summary>独立 SLEIGH 解码器；同一实例的解码、缓存与释放互斥。</summary>
public sealed class SleighDecoder : IDisposable
{
    private IntPtr handle;
    private readonly object gate = new();
    private const int DecodeCapacity = 16384;
    private readonly Dictionary<(ulong Address, ulong Low, ulong High, int Count), LiftedInstruction> decoded = [];
    private readonly Queue<(ulong Address, ulong Low, ulong High, int Count)> decodeOrder = [];

    public SleighDecoder(string sla, string? pspec = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sla);
        if (!File.Exists(sla)) throw new FileNotFoundException("SLEIGH .sla file missing", sla);
        if (pspec is not null && !File.Exists(pspec)) throw new FileNotFoundException("SLEIGH .pspec file missing", pspec);
        if (Native.AbiVersion() != 3) throw new NotSupportedException("SLEIGH bridge ABI mismatch; rebuild native bridge");
        var error = new byte[4096];
        handle = Native.Open(Path.GetFullPath(sla), pspec is null ? null : Path.GetFullPath(pspec), error, error.Length);
        if (handle == IntPtr.Zero)
            throw new InvalidOperationException($"SLEIGH initialization failed: {Error(error)}");
    }

    public LiftedInstruction Decode(ulong address, ReadOnlySpan<byte> bytes)
    {
        lock (gate) return DecodeCore(address, bytes);
    }

    private LiftedInstruction DecodeCore(ulong address, ReadOnlySpan<byte> bytes)
    {
        ObjectDisposedException.ThrowIf(handle == IntPtr.Zero, this);
        if (bytes.IsEmpty) throw new ArgumentException("No instruction bytes available", nameof(bytes));
        if (bytes.Length > 15) bytes = bytes[..15];
        var operations = new List<PcodeOperation>();
        Exception? callbackFailure = null;
        Native.Receiver callback = (_, opcode, namePtr, outPtr, inputsPtr, count, userOpPtr) =>
        {
            try
            {
                if (count < 0 || count > 64) throw new InvalidDataException($"Unexpected input count {count}");
                var inputs = new PcodeVarnode[count];
                for (var index = 0; index < count; index++)
                    inputs[index] = ReadVarnode(IntPtr.Add(inputsPtr, index * Marshal.SizeOf<Native.Varnode>()));
                operations.Add(new(operations.Count, opcode, Marshal.PtrToStringUTF8(namePtr) ?? $"op_{opcode}",
                    outPtr == IntPtr.Zero ? null : ReadVarnode(outPtr), inputs, Marshal.PtrToStringUTF8(userOpPtr)));
            }
            // 托管异常不能穿过原生回调边界，返回后保留原异常并终止解码。
            catch (Exception ex) { callbackFailure ??= ex; }
        };
        var buffer = bytes.ToArray();
        var error = new byte[4096];
        var mnemonic = new byte[128];
        var length = Native.Instruction(handle, address, buffer, buffer.Length, callback,
            IntPtr.Zero, mnemonic, mnemonic.Length, error, error.Length);
        GC.KeepAlive(callback);
        if (callbackFailure is not null) throw new InvalidDataException("P-code callback failed", callbackFailure);
        if (length <= 0 || length > buffer.Length)
            throw new InvalidDataException($"0x{address:X}: SLEIGH decode failed: {Error(error)}");
        return new(address, length, operations.ToArray(), Error(mnemonic));
    }

    /// <summary>机器分析只读 P-code；缓存限定于当前规格和上下文，地址与全部输入字节共同参与键。</summary>
    internal LiftedInstruction DecodeCached(ulong address, ReadOnlySpan<byte> bytes)
    {
        lock (gate) return CachedCore(address, bytes);
    }

    private LiftedInstruction CachedCore(ulong address, ReadOnlySpan<byte> bytes)
    {
        ObjectDisposedException.ThrowIf(handle == IntPtr.Zero, this);
        if (bytes.IsEmpty) throw new ArgumentException("No instruction bytes available", nameof(bytes));
        if (bytes.Length > 15) bytes = bytes[..15];
        Span<byte> keyBytes = stackalloc byte[16];
        keyBytes.Clear();
        bytes.CopyTo(keyBytes);
        var key = (address, BinaryPrimitives.ReadUInt64LittleEndian(keyBytes),
            BinaryPrimitives.ReadUInt64LittleEndian(keyBytes[8..]), bytes.Length);
        if (decoded.TryGetValue(key, out var known)) return known;
        var instruction = DecodeCore(address, bytes);
        if (decoded.Count == DecodeCapacity) decoded.Remove(decodeOrder.Dequeue());
        decoded.Add(key, instruction);
        decodeOrder.Enqueue(key);
        return instruction;
    }

    private static PcodeVarnode ReadVarnode(IntPtr pointer)
    {
        var raw = Marshal.PtrToStructure<Native.Varnode>(pointer);
        return new(Marshal.PtrToStringUTF8(raw.SpaceName) ?? "?", raw.SpaceType,
            raw.Offset, checked((int)raw.Size), Marshal.PtrToStringUTF8(raw.RegisterName) is { Length: > 0 } r ? r : null,
            Marshal.PtrToStringUTF8(raw.ReferencedSpace));
    }

    private static string Error(byte[] buffer)
    {
        var end = Array.IndexOf(buffer, (byte)0);
        return Encoding.UTF8.GetString(buffer, 0, end < 0 ? buffer.Length : end);
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (handle == IntPtr.Zero) return;
            Native.Close(handle);
            handle = IntPtr.Zero;
            decoded.Clear();
            decodeOrder.Clear();
        }
        GC.SuppressFinalize(this);
    }

    ~SleighDecoder() { Dispose(); }

    private static class Native
    {
        private const string Library = "cpp2cs_sleigh_bridge";

        // 允许从工作区指定桥 DLL 的绝对路径。
        static Native()
        {
            NativeLibrary.SetDllImportResolver(typeof(Native).Assembly, (name, assembly, path) =>
            {
                if (name != Library) return IntPtr.Zero;
                var custom = Environment.GetEnvironmentVariable("CPP2CS_SLEIGH_BRIDGE");
                return !string.IsNullOrWhiteSpace(custom) && File.Exists(custom)
                    ? NativeLibrary.Load(Path.GetFullPath(custom)) : IntPtr.Zero;
            });
        }

        [StructLayout(LayoutKind.Sequential)]
        internal readonly struct Varnode
        {
            public readonly int SpaceType;
            public readonly uint Size;
            public readonly ulong Offset;
            public readonly IntPtr SpaceName;
            public readonly IntPtr RegisterName;
            public readonly IntPtr ReferencedSpace;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void Receiver(IntPtr user, int opcode, IntPtr opcodeName,
            IntPtr output, IntPtr inputs, int inputCount, IntPtr userOpName);

        [DllImport(Library, EntryPoint = "cpp2cs_sleigh_open", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr Open([MarshalAs(UnmanagedType.LPUTF8Str)] string sla,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string? pspec, [Out] byte[] error, int capacity);

        [DllImport(Library, EntryPoint = "cpp2cs_sleigh_abi_version", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int AbiVersion();

        [DllImport(Library, EntryPoint = "cpp2cs_sleigh_instruction", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int Instruction(IntPtr handle, ulong address, byte[] bytes,
            int count, Receiver receiver, IntPtr user, [Out] byte[] mnemonic, int mnemonicCapacity, [Out] byte[] error, int capacity);

        [DllImport(Library, EntryPoint = "cpp2cs_sleigh_close", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void Close(IntPtr handle);
    }
}

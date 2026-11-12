using System.Buffers.Binary;

namespace Cpp2CS.Image;

public enum WindowsHandlerKind { Unknown, Seh, Cxx3, Cxx4 }
public sealed record WindowsScope(ulong Start, ulong End, ulong Handler, ulong? Continuation, string Kind);
public sealed record WindowsEhAnalysis(WindowsHandlerKind HandlerKind, string? HandlerIdentity, string MetadataStatus,
    IReadOnlyList<WindowsScope> Scopes, string ManagedProjection, string BlockingProof)
{
    public IReadOnlyList<WindowsUnwindAction> UnwindActions { get; init; } = [];
    public IReadOnlyList<WindowsIpState> IpStates { get; init; } = [];
    public IReadOnlyList<WindowsCatchRegion> CatchRegions { get; init; } = [];
    public byte? CxxHeader { get; init; }
    public uint? BbtFlags { get; init; }
    public uint? CatchFrameOffset { get; init; }
    public uint? CxxMagic { get; init; }
    public uint? EhFlags { get; init; }
    public int? UnwindHelpOffset { get; init; }
    public ulong? ExceptionSpecification { get; init; }
    public string? DecoderEvidence { get; init; }
    public string? RuntimeContract { get; init; }
}
public sealed record WindowsUnwindAction(int State, int NextState, byte Kind, ulong? Action, uint? ObjectOffset);
public sealed record WindowsIpState(ulong Address, int State);
public sealed record WindowsCatchHandler(uint Adjectives, ulong? TypeDescriptor, long? ObjectOffset, ulong Entry, IReadOnlyList<ulong> Continuations)
{
    public int? FrameOffset { get; init; }
    public string? NativeTypeName { get; init; }
}
public sealed record WindowsCatchRegion(uint Low, uint High, uint CatchHigh, IReadOnlyList<WindowsCatchHandler> Handlers);

/// <summary>PE 语言处理器身份和异常元数据独立于托管投影；未知处理器不按表头形状猜测。</summary>
public static class WindowsEhReader
{
    public static WindowsEhAnalysis Read(ImageDocument image, FunctionRange range)
    {
        if (range.Handler is not { } handler)
            return new(WindowsHandlerKind.Unknown, null, "no-handler", [], "not-proven",
                range.HasSeparatedFragments ? "separated-entry-state-not-proven" : "no-language-handler");
        var identity = Identity(image, handler);
        var kind = identity switch
        {
            "__C_specific_handler" => WindowsHandlerKind.Seh,
            "__CxxFrameHandler3" => WindowsHandlerKind.Cxx3,
            "__CxxFrameHandler4" => WindowsHandlerKind.Cxx4,
            _ => WindowsHandlerKind.Unknown,
        };
        WindowsEhAnalysis Unknown(string status, string reason) => new(kind, identity, status, [], "not-proven", reason);
        if (kind == WindowsHandlerKind.Unknown && WindowsFh4LayoutProof.Matches(image, handler))
        {
            var decoded = WindowsCxx4Reader.Read(image, range);
            var runtime = WindowsFh4RuntimeProof.Matches(image, handler, out var contract);
            return decoded with { HandlerIdentity = runtime ? "__CxxFrameHandler4" : null,
                DecoderEvidence = runtime ? "independent-coff-fh4-dispatch-data-and-crt-contract" : "complete-msvc-fh4-layout-code/decoder-data-validated/callee-effects-unproven",
                RuntimeContract = contract,
                BlockingProof = (runtime ? "" : contract + ";") + decoded.BlockingProof };
        }
        if (kind == WindowsHandlerKind.Unknown) return Unknown("unknown-handler", "handler-identity-not-proven");
        if (kind == WindowsHandlerKind.Cxx4) return WindowsCxx4Reader.Read(image, range);
        if (kind == WindowsHandlerKind.Cxx3) return WindowsCxx3Reader.Read(image, range);
        if (kind != WindowsHandlerKind.Seh) return Unknown("unsupported-schema", "versioned-cxx-unwind-and-catch-decoder-required");
        if (range.HasSeparatedFragments) return Unknown("unsupported-layout", "separated-entry-state-not-proven");
        if (range.HandlerData is not { } data || !Readable(image, data, 4)) return Unknown("malformed", "scope-count-not-readable");
        var count = image.ReadU32(data);
        if (count > 4096 || !Readable(image, data, checked(4 + (int)count * 16))) return Unknown("malformed", "scope-table-out-of-range");
        var scopes = new List<WindowsScope>();
        for (var i = 0U; i < count; i++)
        {
            var entry = data + 4 + i * 16;
            var start = image.PreferredBase + image.ReadU32(entry);
            var end = image.PreferredBase + image.ReadU32(entry + 4);
            var action = image.ReadU32(entry + 8);
            var target = image.ReadU32(entry + 12);
            if (start >= end || !range.Contains(start) || end > range.ContiguousEnd)
                return Unknown("malformed", "protected-range-outside-function");
            if (target == 0 && (action <= 1 || !image.IsExecutable(image.PreferredBase + action))
                || target != 0 && (action > 1 && !image.IsExecutable(image.PreferredBase + action)
                    || !range.Contains(image.PreferredBase + target))) return Unknown("malformed", "scope-action-or-continuation-not-proven");
            scopes.Add(new(start, end, action <= 1 ? action : image.PreferredBase + action,
                target == 0 ? null : image.PreferredBase + target, target == 0 ? "cleanup" : "filter"));
        }
        foreach (var a in scopes)
            foreach (var b in scopes)
                if (a.Start < b.Start && b.Start < a.End && a.End < b.End) return Unknown("malformed", "crossing-protected-ranges");
        return new(kind, identity, "parsed", scopes, "not-proven", "filter-behavior-cleanup-effects-and-managed-exception-binding-required");
    }

    internal static bool Readable(ImageDocument image, ulong address, int size) => image.SectionAt(address) is { } section
        && (section.Flags & 1) == 0 && MappedData(image, address, size);

    internal static string? TypeDescriptorName(ImageDocument image, ulong address)
    {
        if (!MappedData(image, address, 17)) return null;
        var bytes = image.ReadUpTo(address + 16, 1024);
        var length = bytes.IndexOf((byte)0);
        if (length <= 0 || bytes[..length].ToArray().Any(b => b is < 32 or > 126)) return null;
        return System.Text.Encoding.ASCII.GetString(bytes[..length]);
    }

    // MSVC type_info 含运行时名称缓存，可位于可写 .data；这里只证明原生类型记录的映射，不推断托管类型。
    internal static bool MappedData(ImageDocument image, ulong address, int size) => size >= 0
        && image.SectionAt(address) is { Executable: false } section
        && address - section.Address <= section.Size && (ulong)size <= section.Size - (address - section.Address)
        && image.ReadUpTo(address, size).Length == size;

    private static string? Identity(ImageDocument image, ulong entry)
    {
        var seen = new HashSet<ulong>();
        for (var depth = 0; depth < 8 && image.IsExecutable(entry) && seen.Add(entry); depth++)
        {
            var bytes = image.ReadUpTo(entry, 6);
            if (bytes.Length < 6) return null;
            if (bytes[0] == 0xe9)
            {
                entry = unchecked(entry + 5 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(bytes[1..]));
                continue;
            }
            if (bytes[0] != 0xff || bytes[1] != 0x25) return null;
            var slot = unchecked(entry + 6 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(bytes[2..]));
            if (!image.Imports.TryGetValue(slot, out var symbol)) return null;
            var module = image.ImportModules.GetValueOrDefault(slot)?.ToLowerInvariant();
            return (symbol, module) switch
            {
                ("__C_specific_handler", "ntdll.dll" or "vcruntime140.dll" or "msvcrt.dll") => symbol,
                ("__CxxFrameHandler3", "vcruntime140.dll" or "msvcrt.dll") => symbol,
                ("__CxxFrameHandler4", "vcruntime140_1.dll") => symbol,
                _ => null,
            };
        }
        return null;
    }
}

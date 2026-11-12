using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace Cpp2CS.Image;

/// <summary>匹配独立 COFF 的 FH4 分派闭包、引用数据及 CRT 叶函数；系统边界按 IAT 和加载配置核对。</summary>
internal static class WindowsFh4RuntimeProof
{
    private sealed record Relocation(int Offset, int Kind, long Addend, int Value, string? Target, string Symbol);
    private sealed record Node(bool Executable, int Length, string Hash, Relocation[] Relocations, Node[]? Alternatives);
    private sealed record LeafRelocation(int Offset, int Kind);
    private sealed record Leaf(bool Executable, int Length, string Hash, LeafRelocation[] Relocations);
    private sealed record Profile(string Contract, string Root, Dictionary<string, string> Roots, Dictionary<string, Node> Nodes, Dictionary<string, Leaf[]> Boundaries);
    private static readonly Lazy<Profile> Data = new(() =>
    {
        using var stream = typeof(WindowsFh4RuntimeProof).Assembly.GetManifestResourceStream("Cpp2CS.Image.msvc-fh4-x64.json")!;
        return JsonSerializer.Deserialize<Profile>(stream)!;
    });
    private static readonly ConditionalWeakTable<ImageDocument, ConcurrentDictionary<ulong, string>> Cache = new();
    internal static bool Matches(ImageDocument image, ulong handler, out string reason)
    {
        reason = Cache.GetOrCreateValue(image).GetOrAdd(handler, entry => Match(image, entry));
        return reason == "msvc-fh4-runtime-contract";
    }
    internal static bool MatchesThrow(ImageDocument image, ulong entry) => Data.Value.Roots.TryGetValue("_CxxThrowException", out var root)
        && Match(image, entry, root) == "msvc-fh4-runtime-contract";
    internal static bool MatchesLibrary(ImageDocument image, ulong entry, string symbol) => Data.Value.Roots.TryGetValue(symbol, out var root)
        && Match(image, entry, root) == "msvc-fh4-runtime-contract";

    /// <summary>清理路径可依赖的独立 CRT 控制契约；不据此删除访存或其他副作用。</summary>
    internal static bool CleanupBoundary(ImageDocument image, ulong entry, out bool returns)
    {
        // 单条 JMP 的重定位归零后没有身份信息，只沿跳转链匹配真正实现。
        foreach (var name in new[] { "_free_base", "_invoke_watson", "__std_terminate" })
            if (Data.Value.Boundaries.TryGetValue(name, out var variants)
                && variants.Where(v => v.Length > 8).Any(v => LeafMatches(image, entry, v))
                && (name != "__std_terminate" || TerminateTarget(image, entry)))
            { returns = name == "_free_base"; return true; }
        returns = false;
        return false;
    }

    private static bool TerminateTarget(ImageDocument image, ulong entry)
    {
        var bytes = image.ReadUpTo(entry, 10);
        if (bytes.Length != 10 || !bytes[..5].SequenceEqual(System.Convert.FromHexString("4883EC28E8")) || bytes[9] != 0xcc) return false;
        var target = unchecked(entry + 9 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(bytes[5..9]));
        return Data.Value.Boundaries.TryGetValue("terminate", out var variants)
            && variants.Where(v => v.Length > 8).Any(v => LeafMatches(image, target, v));
    }

    private static string Match(ImageDocument image, ulong handler, string? root = null)
    {
        var profile = Data.Value;
        var bound = new Dictionary<string, ulong>();
        var external = new Dictionary<string, ulong>();
        var ready = new Stack<(string Key, ulong Address)>(); ready.Push((root ?? profile.Root, handler));
        while (ready.TryPop(out var item))
        {
            if (bound.TryGetValue(item.Key, out var old))
            { if (old != item.Address) return "fh4-runtime-reference-conflict:" + item.Key; continue; }
            bound[item.Key] = item.Address;
            var originalNode = profile.Nodes[item.Key];
            var node = new[] { originalNode }.Concat(originalNode.Alternatives ?? []).FirstOrDefault(n => NodeMatches(image, item.Address, n));
            if (node is null) return "fh4-runtime-body-mismatch:" + item.Key;
            if (node.Executable && !image.IsExecutable(item.Address)) return "fh4-runtime-code-not-mapped:" + item.Key;
            var bytes = Bytes(image, item.Address, node.Length);
            if (bytes is null) return "fh4-runtime-data-not-mapped:" + item.Key;
            foreach (var relocation in node.Relocations)
            {
                var offset = relocation.Offset; var kind = relocation.Kind; var width = kind == 1 ? 8 : 4;
                if (offset < 0 || offset + width > bytes.Length) return "fh4-runtime-profile-relocation-invalid";
                var value = kind >= 4 ? unchecked((ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(offset)))
                    : kind == 1 ? BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(offset)) : BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset));
                var target = unchecked((kind >= 4 ? item.Address + (ulong)offset + 4 + (ulong)(kind - 4) + value
                    : kind == 3 ? image.PreferredBase + value : value) - (ulong)relocation.Addend - (ulong)relocation.Value);
                bytes.AsSpan(offset, width).Clear();
                if (relocation.Target is { } key) ready.Push((key, target));
                else
                {
                    if (external.TryGetValue(relocation.Symbol, out var previous) && previous != target)
                        return "fh4-runtime-external-reference-conflict:" + relocation.Symbol;
                    external[relocation.Symbol] = target;
                }
            }
            if (System.Convert.ToHexString(SHA256.HashData(bytes)) != node.Hash)
                return "fh4-runtime-body-mismatch:" + item.Key;
        }
        foreach (var (name, address) in external)
        {
            if (name == "__ImageBase" && address == image.PreferredBase) continue;
            if (name.StartsWith("__imp_", StringComparison.Ordinal)
                && image.Imports.GetValueOrDefault(address) == name[6..]) continue;
            if (name is "__security_cookie" or "__guard_check_icall_fptr" or "__guard_dispatch_icall_fptr")
            { if (LoadConfigPointer(image, name) == address) continue; return "fh4-runtime-load-config-binding:" + name; }
            if (name is "__isa_available" or "__isa_enabled" or "__favor" or "__use_fma3_lib"
                && image.SectionAt(address) is { Executable: false } section && (section.Flags & 1) != 0) continue;
            if (profile.Boundaries.TryGetValue(name, out var variants) && variants.Any(v => LeafMatches(image, address, v))) continue;
            return "fh4-runtime-boundary-not-proven:" + name;
        }
        return "msvc-fh4-runtime-contract";
    }

    private static bool NodeMatches(ImageDocument image, ulong address, Node node)
    {
        var bytes = Bytes(image, address, node.Length); if (bytes is null) return false;
        foreach (var relocation in node.Relocations)
        {
            var width = relocation.Kind == 1 ? 8 : 4;
            if (relocation.Offset < 0 || relocation.Offset + width > bytes.Length) return false;
            bytes.AsSpan(relocation.Offset, width).Clear();
        }
        return System.Convert.ToHexString(SHA256.HashData(bytes)) == node.Hash;
    }

    private static bool LeafMatches(ImageDocument image, ulong address, Leaf leaf)
    {
        var seen = new HashSet<ulong>();
        for (var depth = 0; depth < 8 && (!leaf.Executable || image.IsExecutable(address)) && seen.Add(address); depth++)
        {
            var bytes = Bytes(image, address, leaf.Length); if (bytes is null) return false;
            var original = image.ReadUpTo(address, 5).ToArray();
            foreach (var relocation in leaf.Relocations)
            {
                var width = relocation.Kind == 1 ? 8 : 4;
                if (relocation.Offset + width > bytes.Length) return false;
                bytes.AsSpan(relocation.Offset, width).Clear();
            }
            if (System.Convert.ToHexString(SHA256.HashData(bytes)) == leaf.Hash) return true;
            if (leaf.Executable && CallPaddingMatches(image, address, leaf)) return true;
            if (!leaf.Executable || original.Length != 5 || original[0] != 0xe9) return false;
            address = unchecked(address + 5 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(original.AsSpan(1)));
        }
        return false;
    }

    private static bool CallPaddingMatches(ImageDocument image, ulong address, Leaf leaf)
    {
        // 链接器可在直接调用后插入单字节 NOP；只在 COFF 已标出的 CALL 边界删除填充。
        var extra = leaf.Relocations.Count(r => r.Kind == 4);
        var source = image.ReadUpTo(address, leaf.Length + extra);
        if (source.Length < leaf.Length) return false;
        var bytes = source.ToArray().ToList(); var removed = 0;
        foreach (var relocation in leaf.Relocations.OrderBy(r => r.Offset))
        {
            var after = relocation.Offset + 4;
            if (relocation.Kind != 4 || relocation.Offset <= 0 || after >= bytes.Count || bytes[relocation.Offset - 1] != 0xe8) continue;
            if (bytes[after] == 0x90) { bytes.RemoveAt(after); removed++; }
        }
        if (removed == 0 || bytes.Count < leaf.Length) return false;
        var normalized = bytes.Take(leaf.Length).ToArray();
        foreach (var relocation in leaf.Relocations)
            normalized.AsSpan(relocation.Offset, relocation.Kind == 1 ? 8 : 4).Clear();
        return System.Convert.ToHexString(SHA256.HashData(normalized)) == leaf.Hash;
    }

    private static byte[]? Bytes(ImageDocument image, ulong address, int length)
    {
        if (length == 0) return [];
        var resolution = image.Resolve(address);
        if (resolution.Kind == AddressKind.Unmapped || resolution.AvailableBytes < (ulong)length) return null;
        return resolution.Kind == AddressKind.ZeroFill ? new byte[length] : image.ReadUpTo(address, length).ToArray();
    }

    private static ulong? LoadConfigPointer(ImageDocument image, string name)
    {
        var bytes = image.Bytes.Span;
        if (bytes.Length < 64) return null;
        var nt = BinaryPrimitives.ReadInt32LittleEndian(bytes[60..]);
        if (nt < 0 || nt + 24 + 112 + 11 * 8 > bytes.Length) return null;
        var entry = nt + 24 + 112 + 10 * 8;
        var rva = BinaryPrimitives.ReadUInt32LittleEndian(bytes[entry..]);
        var size = BinaryPrimitives.ReadUInt32LittleEndian(bytes[(entry + 4)..]);
        var offset = name switch { "__security_cookie" => 88, "__guard_check_icall_fptr" => 112, _ => 120 };
        if (rva == 0 || size < offset + 8) return null;
        var data = image.ReadUpTo(image.PreferredBase + rva + (ulong)offset, 8);
        return data.Length == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(data) : null;
    }
}

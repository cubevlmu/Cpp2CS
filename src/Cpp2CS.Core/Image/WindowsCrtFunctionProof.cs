using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace Cpp2CS.Image;

/// <summary>完整 CRT 代码、常量节及重定位关系提供库入口身份，不从调用点形状猜测。</summary>
public static class WindowsCrtFunctionProof
{
    private static readonly ConditionalWeakTable<ImageDocument, ConcurrentDictionary<ulong, string>> Cache = new();
    public static string? Symbol(ImageDocument image, ulong entry)
    {
        var symbol = Cache.GetOrCreateValue(image).GetOrAdd(entry, address =>
            new[] { "modf", "powf", "acosf", "cosf", "sinf", "sqrtf", "memset" }.FirstOrDefault(name => WindowsFh4RuntimeProof.MatchesLibrary(image, address, name)) ?? "");
        return symbol.Length == 0 ? null : symbol;
    }
}

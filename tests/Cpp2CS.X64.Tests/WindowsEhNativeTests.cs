using Cpp2CS.Image;

namespace Cpp2CS.X64.Tests;

internal static class WindowsEhNativeTests
{
    internal static void Run(string path, string schema)
    {
        var expected = schema switch { "fh3" => WindowsHandlerKind.Cxx3, "fh4" => WindowsHandlerKind.Cxx4,
            _ => throw new ArgumentException("schema 必须为 fh3 或 fh4") };
        var image = ImageDocument.Load(path); var table = FunctionTable.Build(image);
        foreach (var name in new[] { "FixtureCleanup", "FixtureCatch" })
        {
            var entry = image.Exports[name]; var range = table.Ranges.Single(r => r.Start == entry);
            var analysis = WindowsEhReader.Read(image, range);
            if (analysis.HandlerKind != expected || analysis.MetadataStatus != "parsed" || analysis.UnwindActions.Count == 0
                || name == "FixtureCatch" && analysis.CatchRegions.Count == 0 || analysis.ManagedProjection != "not-proven")
                throw new InvalidOperationException(name + ": " + System.Text.Json.JsonSerializer.Serialize(analysis));
            Console.WriteLine($"{name}: {analysis.HandlerIdentity}, {analysis.UnwindActions.Count} unwind actions, {analysis.IpStates.Count} IP states, {analysis.CatchRegions.Count} catch regions; managed projection remains unproven");
            if (analysis.DecoderEvidence is not null && name == "FixtureCatch")
            {
                var handler = range.Handler!.Value;
                ulong Relative(ulong field) => unchecked(field + 4 + (ulong)(long)System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(image.ReadUpTo(field, 4)));
                var decoder = Relative(handler + 123); var wrapper = Relative(handler + 174);
                if (analysis.HandlerIdentity is not null || !analysis.BlockingProof.Contains("callee-effects-not-proven", StringComparison.Ordinal))
                    throw new InvalidOperationException("布局证明不能冒充完整静态处理器身份或效果证明");
                var checks = 0;
                foreach (var (codeEntry, size, relocations) in new[] { (handler, 200, new[] { 65, 78, 87, 123, 174 }),
                    (decoder, 300, new[] { 33, 63, 70, 160, 167, 249, 256 }), (wrapper, 75, new[] { 49, 56 }) })
                    for (var offset = 0; offset < size; offset++)
                    {
                        if (relocations.Any(r => offset >= r && offset < r + 4)) continue;
                        var changed = image.Bytes.ToArray(); changed[checked((int)image.Resolve(codeEntry + (ulong)offset).FileOffset!.Value)] ^= 1;
                        if (WindowsFh4LayoutProof.Matches(ImageDocument.Parse(changed), handler)) throw new InvalidOperationException("完整原生布局见证必须拒绝指令变异");
                        checks++;
                    }
                foreach (var address in new[] { handler + 65, handler + 123, decoder + 33, decoder + 63,
                    image.PreferredBase + image.ReadU32(decoder + 63), image.PreferredBase + image.ReadU32(decoder + 70) })
                {
                    var changed = image.Bytes.ToArray(); changed[checked((int)image.Resolve(address).FileOffset!.Value)] ^= 1;
                    if (WindowsFh4LayoutProof.Matches(ImageDocument.Parse(changed), handler)) throw new InvalidOperationException("布局见证必须核对重定位绑定及压缩整数表");
                    checks++;
                }
                Console.WriteLine($"静态 FH4 布局见证变异拒绝通过：{checks} 项；外部处理效果仍未证明");
            }
        }
    }
}

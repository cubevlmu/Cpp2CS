using System.Globalization;
using System.Text;
using System.Text.Json;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Input;
using Cpp2CS.Model;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Cli;

internal static class Program
{
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private static int Main(string[] args)
    {
        switch (args)
        {
            case ["facts", var binary, var metadata, var sla, var output, var assembly]:
                RecoveryCommand.WriteFacts(binary, metadata, sla, output, assembly);
                return 0;
            case ["recover", var binary, var metadata, var sla, var output, var assembly]:
                RecoveryCommand.Run(binary, metadata, sla, output, assembly, int.MaxValue);
                return 0;
            case ["recover", var binary, var metadata, var sla, var output, var assembly, var limit, .. var options]:
                RecoveryCommand.Run(binary, metadata, sla, output, assembly, limit == "all" ? int.MaxValue : int.Parse(limit, CultureInfo.InvariantCulture), options);
                return 0;
            case ["methods", var binary, var metadata, var output]:
                Methods(binary, metadata, output);
                return 0;
            case ["pcode", var binary, var sla, var address, var count, var output, .. var options]:
                Dump(binary, sla, Address(address), int.Parse(count, CultureInfo.InvariantCulture), output, ProcessorSpec(options));
                return 0;
            case ["ir", var binary, var sla, var address, var count, var output, .. var options]:
                DumpIr(binary, sla, Address(address), int.Parse(count, CultureInfo.InvariantCulture), output, ProcessorSpec(options));
                return 0;
            case ["cfg", var binary, var sla, var address, var output]:
                DumpCfg(binary, sla, Address(address), output);
                return 0;
            case ["scan", var binary, var sla, var limit, var output, .. var options]:
                Scan(binary, sla, int.Parse(limit, CultureInfo.InvariantCulture), output, ProcessorSpec(options));
                return 0;
            default:
                Console.Error.WriteLine("""
                    cpp2cs-x64 methods <GameAssembly.dll> <global-metadata.dat> <methods.tsv>
                    cpp2cs-x64 facts   <binary> <metadata> <x86-64.sla> <output> <assembly.dll>
                    cpp2cs-x64 pcode   <GameAssembly.dll> <x86-64.sla> <hex-VA> <instructions> <pcode.jsonl> [--pspec file]
                    cpp2cs-x64 ir      <GameAssembly.dll> <x86-64.sla> <hex-VA> <instructions> <ir.txt> [--pspec file]
                    cpp2cs-x64 cfg     <GameAssembly.dll> <x86-64.sla> <hex-VA> <cfg.txt>
                    cpp2cs-x64 scan    <GameAssembly.dll> <x86-64.sla> <function-count> <report.json> [--pspec file]
                    cpp2cs-x64 recover <binary> <metadata> <x86-64.sla> <output> <assembly.dll> [all|method-count]
                    CPP2CS_SLEIGH_BRIDGE 指向本机原生桥 DLL。recover 输出 CIL、C# 和逐方法诊断。
                    """);
                return 2;
        }
    }

    private static ulong Address(string text) => ulong.Parse(text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? text[2..] : text,
        NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    private static void DumpCfg(string path, string sla, ulong entry, string output)
    {
        var image = LoadPe(path);
        using var decoder = new SleighDecoder(sla);
        var map = Cpp2CS.Facts.CodeMap.BuildPe(image, [entry]);
        var cfg = new Cpp2CS.Machine.Flow.CfgBuilder(new PcodeMachine(image, decoder), map);
        var function = cfg.Build(entry);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
        using var writer = new StreamWriter(output, false, new UTF8Encoding(false));
        writer.Write(function);
        foreach (var problem in function.Problems) writer.WriteLine($"问题：{problem}");
        foreach (var call in function.Blocks.SelectMany(b => b.Statements).OfType<Call>().Where(c => c.DoesNotReturn))
            writer.WriteLine($"不返回调用 0x{call.Address:x}: {call.Target}");
        writer.WriteLine($"异常边未建模：{function.Range.HasUnmodeledExceptions}");
        if (cfg.WindowsExceptionProblem(entry) is { } exceptionProblem) writer.WriteLine(exceptionProblem);
        Console.WriteLine($"CFG：{function.Blocks.Count} 块，{function.Problems.Count} 个边界问题。输出：{output}");
    }

    private static string? ProcessorSpec(string[] options) => options switch
    {
        [] => null,
        ["--pspec", var path] => path,
        _ => throw new ArgumentException("Expected optional --pspec <file>"),
    };

    private static ImageDocument LoadPe(string path)
    {
        var image = ImageDocument.Load(path);
        if (image.Architecture != Architecture.X64) throw new NotSupportedException("Only PE32+ AMD64 images are supported");
        return image;
    }

    private static void Methods(string dll, string metadata, string output)
    {
        _ = LoadPe(dll);
        var (model, _) = ModelBuilder.Load(dll, metadata);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
        using var writer = new StreamWriter(output, false, new UTF8Encoding(false));
        foreach (var method in model.Methods.Where(m => m.Address != 0).OrderBy(m => m.Address))
            writer.WriteLine($"{method.Address:x}\t{method.Owner.Assembly}\t{method.Owner.FullName}.{method.Name}");
        Console.WriteLine($"Wrote {model.Methods.Count(m => m.Address != 0)} method entries to {output}");
    }

    private static void Dump(string path, string sla, ulong address, int max, string output, string? pspec)
    {
        if (max <= 0 || max > 100_000) throw new ArgumentOutOfRangeException(nameof(max));
        var image = LoadPe(path);
        if (!image.IsExecutable(address)) throw new InvalidDataException($"0x{address:x} is not executable");
        using var decoder = new SleighDecoder(sla, pspec);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
        using var writer = new StreamWriter(output, false, new UTF8Encoding(false));
        for (int i = 0; i < max; i++)
        {
            if (!image.IsExecutable(address)) break;
            var bytes = image.ReadUpTo(address, 15);
            if (bytes.IsEmpty) break;
            var insn = decoder.Decode(address, bytes);
            writer.WriteLine(JsonSerializer.Serialize(insn, Json));
            address += (ulong)insn.Length;
        }
        Console.WriteLine($"Wrote raw P-code to {output}");
    }

    private static void DumpIr(string path, string sla, ulong address, int max, string output, string? pspec)
    {
        if (max <= 0 || max > 100_000) throw new ArgumentOutOfRangeException(nameof(max));
        var image = LoadPe(path);
        using var decoder = new SleighDecoder(sla, pspec);
        var machine = new PcodeMachine(image, decoder);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
        using var writer = new StreamWriter(output, false, new UTF8Encoding(false));
        for (var i = 0; i < max && image.IsExecutable(address); i++)
        {
            var statements = new List<Stmt>();
            var size = machine.Lift(address, statements);
            if (size == 0)
            {
                writer.WriteLine($"{address:x}: (cannot decode)");
                break;
            }
            writer.WriteLine($"{address:x}: +{size}");
            foreach (var statement in statements) writer.WriteLine($"    {statement}");
            address += (ulong)size;
        }
        Console.WriteLine($"Wrote preliminary Machine IR to {output}");
    }

    private static void Scan(string path, string sla, int count, string output, string? pspec)
    {
        if (count <= 0) throw new ArgumentOutOfRangeException(nameof(count));
        var image = LoadPe(path);
        var table = FunctionTable.Build(image);
        using var decoder = new SleighDecoder(sla, pspec);
        var opcodes = new Dictionary<string, long>(StringComparer.Ordinal);
        var failures = new List<object>();
        long instructions = 0;
        long lowered = 0;
        var loweringFailures = new Dictionary<string, long>();
        var loweringSamples = new List<object>();
        var functions = 0;
        foreach (var range in table.Ranges.Take(count))
        {
            functions++;
            ulong pc = range.Start;
            var budget = 100_000;
            while (pc < range.End && --budget > 0)
            {
                try
                {
                    var available = image.ReadUpTo(pc, (int)Math.Min(15UL, range.End - pc));
                    if (available.IsEmpty) throw new InvalidDataException("Unmapped bytes");
                    var insn = decoder.Decode(pc, available);
                    instructions++;
                    var statements = new List<Stmt>();
                    PcodeLowerer.Lower(insn, statements);
                    if (statements.OfType<Opaque>().FirstOrDefault() is { } opaque)
                    {
                        loweringFailures[opaque.Text] = loweringFailures.GetValueOrDefault(opaque.Text) + 1;
                        if (loweringSamples.Count < 20) loweringSamples.Add(new { bytes = System.Convert.ToHexString(available[..insn.Length]), instruction = insn, reason = opaque.Text });
                    }
                    else lowered++;
                    foreach (var op in insn.Operations)
                        opcodes[op.Name] = opcodes.GetValueOrDefault(op.Name) + 1;
                    pc += (ulong)insn.Length;
                }
                catch (InvalidDataException e)
                {
                    failures.Add(new { function = $"0x{range.Start:x}", at = $"0x{pc:x}", reason = e.Message });
                    break;
                }
            }
            if (budget == 0) failures.Add(new { function = $"0x{range.Start:x}", at = $"0x{pc:x}", reason = "Instruction budget exhausted" });
        }
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
        File.WriteAllText(output, JsonSerializer.Serialize(new
        {
            source = Path.GetFullPath(path), sha256 = image.Sha256,
            functionTableSource = table.Source, functions, instructions,
            lowered, loweringFailures, loweringSamples,
            pcodeOperations = opcodes.OrderByDescending(p => p.Value).ToDictionary(p => p.Key, p => p.Value),
            failures,
            warning = "This is a raw P-code decoding audit, not a C# recovery success metric."
        }, new JsonSerializerOptions(Json) { WriteIndented = true }));
        Console.WriteLine($"Decoded {instructions} instructions in {functions} .pdata functions. Errors: {failures.Count}. Report: {output}");
    }
}

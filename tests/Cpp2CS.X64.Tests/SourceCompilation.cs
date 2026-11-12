using System.Diagnostics;

namespace Cpp2CS.X64.Tests;

/// <summary>使用显式提供的 Roslyn 与框架引用验证生成源码；不改写生成的方法体。</summary>
internal static class SourceCompilation
{
    internal static string? Check(string output, string assemblyName)
    {
        var compiler = Environment.GetEnvironmentVariable("CPP2CS_TEST_CSC");
        var references = Environment.GetEnvironmentVariable("CPP2CS_TEST_FRAMEWORK_REFS");
        if (compiler is null || references is null)
        {
            Console.WriteLine("公共管线源码编译未运行：未提供 CPP2CS_TEST_CSC 和 CPP2CS_TEST_FRAMEWORK_REFS");
            return null;
        }
        if (!File.Exists(compiler) || !Directory.Exists(references)) throw new InvalidOperationException("显式源码编译工具或框架引用不存在");
        var response = Path.Combine(output, "source-check.rsp");
        var assembly = Path.Combine(output, "source-check.dll");
        var sources = Directory.GetFiles(Path.Combine(output, "src", assemblyName + ".dll"), "*.cs", SearchOption.AllDirectories)
            // 此检查使用完整框架契约；StrippedAttributes 仅用于缺少这些框架声明的裁剪核心库。
            .Where(p => Path.GetFileName(p) != "StrippedAttributes.cs").ToArray();
        if (sources.Length == 0) throw new InvalidOperationException("没有可供编译的目标源码");
        var framework = Directory.GetFiles(references, "*.dll");
        var frameworkNames = framework.Select(Path.GetFileName).ToHashSet(StringComparer.OrdinalIgnoreCase);
        File.WriteAllLines(response, new[] { "-nostdlib+", "-target:library", "-unsafe+", "-langversion:latest", "-warn:0", $"-out:\"{assembly}\"" }
            .Concat(framework.Select(p => $"-r:\"{p}\""))
            .Concat(Directory.GetFiles(Path.Combine(output, "assemblies"), "*.dll")
                .Where(p => !frameworkNames.Contains(Path.GetFileName(p)) && Path.GetFileName(p) != assemblyName + ".dll")
                .Select(p => $"-r:\"{p}\""))
            .Concat(sources.Select(p => $"\"{p}\"")));
        var start = new ProcessStartInfo("dotnet") { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add(compiler); start.ArgumentList.Add("@" + response);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("无法启动 Roslyn 编译器");
        var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(30_000)) { process.Kill(entireProcessTree: true); throw new InvalidOperationException("源码编译超过 30 秒"); }
        var text = stdout.GetAwaiter().GetResult() + stderr.GetAwaiter().GetResult();
        File.WriteAllText(Path.Combine(output, "source-check.log"), text);
        if (process.ExitCode != 0 || !File.Exists(assembly)) throw new InvalidOperationException("公共管线生成源码编译失败：\n" + text);
        Console.WriteLine($"公共管线目标源码 Roslyn 编译通过：{sources.Length} 个文件，使用显式框架契约");
        return assembly;
    }
}

using System.Reflection;
using System.Text.Json;
using Cpp2CS.Facts;
using Cpp2CS.Pipeline;

namespace Cpp2CS.X64.Tests;

internal static class PipelineTests
{
    internal static void Run(ProgramFacts facts, byte[] binary, string assemblyName)
    {
        var directory = Path.Combine(Path.GetTempPath(), "Cpp2CS-pipeline-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var image = Path.Combine(directory, "fixture.bin");
            var metadata = Path.Combine(directory, "fixture.metadata");
            var output = Path.Combine(directory, "output");
            File.WriteAllBytes(image, binary);
            File.WriteAllBytes(metadata, [1]);
            var request = new RecoveryRequest(image, metadata, output)
            {
                Assemblies = [assemblyName + ".dll"], SourceLayout = "project",
                RecoverDependencies = false, MethodTimeoutSeconds = 0, MaxMemoryMB = 0,
            };
            var builds = 0;
            var result = RecoverySession.Run(request, _ => { builds++; return facts; });
            // 普通别名的定义没有原生地址；只有共享注册构造、处理方法及工厂有定义见证。
            Check(builds == 1 && result.SelectedMethods == 3 && result.EmittedMethods == 2,
                $"公共管线须选择完整目标定义，并将运行时声明与完整方法体分开计数：{result.SelectedMethods}/{result.EmittedMethods}\n"
                + File.ReadAllText(Path.Combine(output, "recovery.jsonl")));
            using var manifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(output, "run.json")));
            Check(manifest.RootElement.GetProperty("status").GetString() == "complete", "完整管线须发布完成清单");
            var stages = manifest.RootElement.GetProperty("stages").EnumerateArray().Select(s => s.GetProperty("Name").GetString()).ToArray();
            Check(stages.SequenceEqual(new[] { "facts", "selection", "recovery", "dependencies", "publication", "decompile" }),
                "后端不能绕过公共校验、发布和反编译阶段");
            var rows = File.ReadLines(Path.Combine(output, "recovery.jsonl")).Select(s => JsonDocument.Parse(s)).ToArray();
            try
            {
                Check(rows.Select(r => r.RootElement.GetProperty("methodIndex").GetInt32()).Order().SequenceEqual(new[] { 2, 4, 5 })
                    && rows.All(r => !r.RootElement.GetProperty("dependency").GetBoolean()
                    && r.RootElement.GetProperty("assembly").GetString() == assemblyName + ".dll"), "依赖库不作为恢复目标");
                Check(rows.Count(r => r.RootElement.GetProperty("status").GetString() == "runtime-declaration") == 1,
                    "共享委托构造须发布为运行时声明");
            }
            finally { foreach (var row in rows) row.Dispose(); }
            var checks = File.ReadLines(Path.Combine(output, "managed-checks.jsonl")).Select(s => JsonDocument.Parse(s)).ToArray();
            try
            {
                Check(checks.Length == 2 && checks.All(c => c.RootElement.GetProperty("status").GetString() == "passed"
                    && c.RootElement.GetProperty("published").GetBoolean()
                    && !c.RootElement.GetProperty("dependency").GetBoolean()
                    && c.RootElement.GetProperty("imageSha256").GetString() == facts.Model.Image.Sha256),
                    "静态检查须逐方法保存真实身份、发布状态与映像证据，不含运行时声明");
                Check(!File.ReadLines(Path.Combine(output, "managed-check-diagnostics.jsonl")).Any(), "通过的夹具不能产生静态失败诊断");
            }
            finally { foreach (var check in checks) check.Dispose(); }
            var assembly = Assembly.Load(File.ReadAllBytes(Path.Combine(output, "assemblies", assemblyName + ".dll")));
            void Execute(Assembly loaded)
            {
                var handler = loaded.GetType("Fixture.Handler", true)!;
                var factory = loaded.GetType("Fixture.Factory", true)!.GetMethod("Make")!;
                foreach (var expected in new[] { int.MinValue, 0, int.MaxValue })
                {
                    var target = System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(handler);
                    handler.GetField("Bias")!.SetValue(target, expected);
                    var callback = (Delegate)factory.Invoke(null, [target])!;
                    Check((int)callback.DynamicInvoke([null])! == expected, "公共管线 CIL 和重新编译的 C# 必须保留委托绑定及执行结果");
                }
            }
            Execute(assembly);
            Check(Directory.GetFiles(Path.Combine(output, "src"), "*.cs", SearchOption.AllDirectories).Length > 0,
                "公共管线须输出目标程序集源码");
            if (SourceCompilation.Check(output, assemblyName) is { } compiled) Execute(Assembly.Load(File.ReadAllBytes(compiled)));
        }
        finally
        {
            // 反编译器的映射可能仍持有程序集，不能用清理失败遮蔽测试结论。
            try { Directory.Delete(directory, recursive: true); }
            catch (IOException) { Console.WriteLine($"临时程序集仍被映射：{directory}"); }
        }
        Console.WriteLine("公共管线 x64 对照通过：全定义选择、运行时声明、依赖范围、阶段清单、C# 输出及 CLR 执行");
    }

    private static void Check(bool condition, string reason)
    {
        if (!condition) throw new InvalidOperationException(reason);
    }
}

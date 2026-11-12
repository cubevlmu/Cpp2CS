using System.Reflection;
using Cpp2CS.Output;

namespace Cpp2CS.X64.Tests;

internal static class SourceIteratorTests
{
    internal static void Run()
    {
        if (Environment.GetEnvironmentVariable("CPP2CS_TEST_CSC") is null) return;
        var directory = Path.Combine(Path.GetTempPath(), "Cpp2CS-iterator-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(directory, "assemblies"));
        var sources = Path.Combine(directory, "src", "IteratorFixture.dll");
        Directory.CreateDirectory(sources);
        var source = Decompilation.Decompile(typeof(IteratorSourceFixture).Assembly.Location,
            Path.GetDirectoryName(typeof(IteratorSourceFixture).Assembly.Location)!,
            t => t.FullName == typeof(IteratorSourceFixture).FullName, false, recoveringBodies: true).Single().Source;
        if (source.Contains("yield return", StringComparison.Ordinal)) throw new InvalidOperationException("恢复源码须保留显式协程状态机");
        File.WriteAllText(Path.Combine(sources, "IteratorFixture.cs"), source);
        var compiled = SourceCompilation.Check(directory, "IteratorFixture")!;
        var run = Assembly.Load(File.ReadAllBytes(compiled)).GetType(typeof(IteratorSourceFixture).FullName!, true)!.GetMethod("Values")!;
        foreach (var seed in new[] { int.MinValue, -1, 0, 1, int.MaxValue })
        {
            var actual = ((IEnumerable<int>)run.Invoke(null, [seed])!).ToArray();
            if (!actual.SequenceEqual(IteratorSourceFixture.Values(seed))) throw new InvalidOperationException("显式状态机的编译与执行必须保持协程结果");
        }
        Console.WriteLine("恢复源码显式状态机重新编译及 CLR 对照通过：5 组输入");
    }
}

public static class IteratorSourceFixture
{
    public static IEnumerable<int> Values(int seed)
    {
        yield return seed;
        yield return unchecked(seed + 1);
    }
}

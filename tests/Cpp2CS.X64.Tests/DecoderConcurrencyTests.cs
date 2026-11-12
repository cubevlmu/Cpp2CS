using System.Text.Json;
using Cpp2CS.X64;

namespace Cpp2CS.X64.Tests;

internal static class DecoderConcurrencyTests
{
    internal static void Run(string sla)
    {
        byte[][] bytes = [Convert.FromHexString("B801000000"), Convert.FromHexString("4883C002"),
            Convert.FromHexString("0F57C0"), Convert.FromHexString("488B4110")];
        string[] expected;
        using (var sequential = new SleighDecoder(sla))
        {
            expected = bytes.Select(b => JsonSerializer.Serialize(sequential.Decode(0x1000, b))).ToArray();
            for (var i = 0; i < bytes.Length; i++)
            {
                var cached = sequential.DecodeCached(0x1000, bytes[i]);
                if (JsonSerializer.Serialize(cached) != expected[i]
                    || !ReferenceEquals(cached, sequential.DecodeCached(0x1000, bytes[i])))
                    throw new InvalidOperationException("同址换码的缓存须按全部字节区分，并复用只读 P-code");
            }
            var branch = Convert.FromHexString("E901000000");
            if (sequential.DecodeCached(0x1000, branch).Operations.SequenceEqual(sequential.DecodeCached(0x2000, branch).Operations))
                throw new InvalidOperationException("相对跳转不能跨地址复用解码结果");
            // 单个上下文的容量有界；被逐出的指令须重新得到相同结果。
            for (var i = 0; i < 16385; i++) sequential.DecodeCached((ulong)(0x3000 + i), [0x90]);
            if (JsonSerializer.Serialize(sequential.DecodeCached(0x1000, bytes[0])) != expected[0])
                throw new InvalidOperationException("缓存逐出不能改变解码结果");
        }
        using var barrier = new Barrier(4);
        var workers = Enumerable.Range(0, 4).Select(worker => Task.Factory.StartNew(() =>
        {
            for (var round = 0; round < 4; round++)
            {
                if (!barrier.SignalAndWait(TimeSpan.FromSeconds(30)))
                    throw new InvalidOperationException("并发解码线程未能到达初始化屏障");
                using var decoder = new SleighDecoder(sla);
                for (var i = 0; i < 32; i++)
                {
                    var index = (i + worker) % bytes.Length;
                    var actual = JsonSerializer.Serialize(decoder.Decode(0x1000, bytes[index]));
                    if (actual != expected[index]) throw new InvalidOperationException("独立解码上下文并发时不得相互污染");
                }
            }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default)).ToArray();
        Task.WaitAll(workers);
        using (var shared = new SleighDecoder(sla))
            Parallel.For(0, 512, i =>
            {
                var index = i % bytes.Length;
                if (JsonSerializer.Serialize(shared.DecodeCached(0x1000, bytes[index])) != expected[index])
                    throw new InvalidOperationException("共享事实证明器使用同一上下文时，缓存与解码必须互斥");
            });
        Console.WriteLine("SLEIGH 并发对照通过：四线程同步创建/释放上下文，512 次同址换码与顺序 P-code 完全一致");
        Console.WriteLine("SLEIGH 共享上下文对照通过：512 次并发缓存读取，覆盖共同事实证明器的调用方式");
    }
}

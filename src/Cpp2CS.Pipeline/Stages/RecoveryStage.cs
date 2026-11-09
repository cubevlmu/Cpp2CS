using System.Diagnostics;
using Cpp2CS.Facts;
using Cpp2CS.Recovery;

namespace Cpp2CS.Pipeline;

internal static class RecoveryStage
{
    internal sealed record RecoveryBatch(MethodDecompiler Recovery, MethodRecoveryResult[] Targets);

    internal static RecoveryBatch RecoverMethods(RecoveryTarget[] selected, ProgramFacts facts, ManagedTypes types, int jobs, Action<string> Log, MethodGuard? guard = null, long maxMemoryMB = 0)
    {
        var methods = selected;
        var watch = Stopwatch.StartNew();
        var recovery = new MethodDecompiler(facts, types);
        var targets = new MethodRecoveryResult[methods.Length];
        var completed = 0;
        var active = new System.Collections.Concurrent.ConcurrentDictionary<int, long>();

        static long GetMemMB()
        {
            var proc = Process.GetCurrentProcess();
            return Math.Max(proc.WorkingSet64, proc.PrivateMemorySize64) / (1024 * 1024);
        }

        using var timer = new Timer(_ =>
        {
            foreach (var (index, started) in active.ToArray().OrderBy(p => p.Key))
            {
                var elapsed = Stopwatch.GetElapsedTime(started).TotalSeconds;
                if (elapsed >= 3.0)
                {
                    var target = selected[index];
                    Log($"[Recovery][处理中... 已耗时 {elapsed:F1}s] 0x{target.Entry:x} {target.Instance} (当前内存: {GetMemMB()}MB)");
                }
            }
        }, null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));

        void Recover(int i, ref MethodDecompiler worker)
        {
            var target = selected[i];
            var itemStart = Stopwatch.GetTimestamp();
            active[i] = itemStart;

            if (maxMemoryMB > 0)
            {
                var curMem = GetMemMB();
                if (curMem > maxMemoryMB * 0.85)
                {
                    GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);
                    GC.WaitForPendingFinalizers();
                    var afterMem = GetMemMB();
                    Log($"[Recovery][GC主动回收] 内存达 {curMem}MB / 设定上限 {maxMemoryMB}MB，GC后: {afterMem}MB");
                }
            }

            var methodDesc = $"0x{target.Entry:x} {target.Instance}";
            Log($"[Recovery] [{i + 1}/{methods.Length}] 开始恢复: {methodDesc} (内存: {GetMemMB()}MB)");

            targets[i] = guard is null ? target.Recover(worker) : guard.Run(target.Method, target.Entry, ref worker, target.Recover);
            active.TryRemove(i, out _);
            var count = Interlocked.Increment(ref completed);
            var itemElapsedMs = Stopwatch.GetElapsedTime(itemStart).TotalMilliseconds;
            var statusDesc = targets[i].Body is not null
                ? "成功"
                : (targets[i].Partial is not null ? "部分" : (targets[i].Holes.Count > 0 ? $"未恢复: {targets[i].Holes[0].Reason}" : "无方法体"));

            Log($"[Recovery] [{count}/{methods.Length}] 完成: {methodDesc} ({itemElapsedMs:F0}ms, 状态: {statusDesc}, 内存: {GetMemMB()}MB)");

            if (count % 50 == 0 || count == methods.Length)
                Log($"[Recovery] 总体进度: {count}/{methods.Length} ({count * 100.0 / methods.Length:F1}%)，累计耗时 {watch.Elapsed.TotalSeconds:F1}s");
        }
        Log($"方法恢复并行度：{jobs}");
        if (jobs == 1)
            for (var i = 0; i < methods.Length; i++) Recover(i, ref recovery);
        else
        {
            // 工作线程独享恢复器和分析缓存；结果按原清单索引汇总。
            using var workers = new ThreadLocal<MethodDecompiler>(() => new(facts, types), trackAllValues: true);
            Parallel.For(0, methods.Length, new ParallelOptions { MaxDegreeOfParallelism = jobs }, i =>
            {
                var worker = workers.Value!;
                Recover(i, ref worker);
                workers.Value = worker;
            });
            recovery = workers.Values.FirstOrDefault() ?? recovery;
        }
        return new(recovery, targets);
    }
}

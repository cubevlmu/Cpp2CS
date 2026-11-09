using System.Diagnostics;
using Cpp2CS.Recovery;

namespace Cpp2CS.Pipeline;

/// <summary>
/// 逐方法防护机制：
/// 1. 在独立后台线程中执行方法恢复，设置栈大小防止常规爆栈。
/// 2. 周期监控单方法执行时限，超时立即跳过，避免长时间卡死在某个复杂控制流或模式匹配循环中。
/// 3. 动态监控进程内存占用，接近阈值主动触发 GC；若超过 maxMemoryMB 立即熔断跳过，防止 OOM 崩溃。
/// 4. 出现超时、超限或异常时记录详细日志与 RecoveryHole，并刷新 worker 避免污染后续方法。
/// </summary>
internal sealed class MethodGuard(Func<MethodDecompiler> create, TimeSpan limit, Action<string> log, long maxMemoryMB = 0)
{
    private const int StackBytes = 64 * 1024 * 1024;
    private int crashes, timeouts, memSkips;

    public int Crashes => crashes;
    public int Timeouts => timeouts;
    public int MemSkips => memSkips;

    private static long GetMemoryMB()
    {
        var proc = Process.GetCurrentProcess();
        return Math.Max(proc.WorkingSet64, proc.PrivateMemorySize64) / (1024 * 1024);
    }

    /// <summary>worker 在失败后换成新的。</summary>
    public MethodRecoveryResult Run(MethodRef method, ulong entry, ref MethodDecompiler worker, Func<MethodDecompiler, MethodRecoveryResult> recover)
    {
        // 1. 运行前检查内存
        if (maxMemoryMB > 0)
        {
            var curMB = GetMemoryMB();
            if (curMB >= maxMemoryMB * 0.9)
            {
                GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);
                GC.WaitForPendingFinalizers();
                curMB = GetMemoryMB();
                if (curMB >= maxMemoryMB)
                {
                    Interlocked.Increment(ref memSkips);
                    var memReason = $"启动前内存超限 (当前 {curMB}MB >= 上限 {maxMemoryMB}MB)";
                    log($"[内存跳过] 0x{entry:x} {method}：{memReason}，已跳过！");
                    return new MethodRecoveryResult(method, entry, null, [new RecoveryHole(entry, memReason)]);
                }
            }
        }

        MethodRecoveryResult? result = null;
        Exception? failure = null;
        var current = worker;
        var thread = new Thread(() =>
        {
            try { result = recover(current); }
            catch (Exception e) { failure = e; }
        }, StackBytes) { IsBackground = true, Name = $"Decompile_0x{entry:x}" };

        thread.Start();

        var sw = Stopwatch.StartNew();
        var lastHeartbeat = sw.ElapsedMilliseconds;
        var timedOut = false;
        var memExceeded = false;
        string? memExceededMsg = null;

        // 2. 动态轮询等待（每 200ms 检查一次耗时与内存），防止阻塞期间内存暴涨或长时间挂起
        while (thread.IsAlive)
        {
            if (thread.Join(200))
            {
                break;
            }

            if (sw.ElapsedMilliseconds - lastHeartbeat >= 2000)
            {
                lastHeartbeat = sw.ElapsedMilliseconds;
                log($"[MethodGuard][处理中... 已耗时 {sw.Elapsed.TotalSeconds:F1}s] 0x{entry:x} {method} (当前内存: {GetMemoryMB()} MB)");
            }

            if (limit > TimeSpan.Zero && sw.Elapsed >= limit)
            {
                timedOut = true;
                break;
            }

            if (maxMemoryMB > 0)
            {
                var curMB = GetMemoryMB();
                if (curMB >= maxMemoryMB)
                {
                    GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);
                    curMB = GetMemoryMB();
                    if (curMB >= maxMemoryMB)
                    {
                        memExceeded = true;
                        memExceededMsg = $"运行中内存超限 (当前 {curMB}MB >= 上限 {maxMemoryMB}MB)";
                        break;
                    }
                }
            }
        }

        string reason;
        if (timedOut)
        {
            Interlocked.Increment(ref timeouts);
            try { thread.Priority = ThreadPriority.Lowest; } catch { }
            reason = $"单方法恢复超时 (已耗时 {sw.Elapsed.TotalSeconds:F1}s，超过时限 {limit.TotalSeconds:F0}s)";
            log($"[超时跳过] 0x{entry:x} {method}：{reason}，已强制跳过该方法继续执行！");
        }
        else if (memExceeded)
        {
            Interlocked.Increment(ref memSkips);
            try { thread.Priority = ThreadPriority.Lowest; } catch { }
            reason = memExceededMsg ?? $"单方法恢复内存超限 (超过上限 {maxMemoryMB}MB)";
            log($"[内存跳过] 0x{entry:x} {method}：{reason}，已强制跳过该方法继续执行！");
        }
        else if (failure is not null)
        {
            Interlocked.Increment(ref crashes);
            if (failure is OutOfMemoryException)
            {
                GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);
            }
            var at = failure.StackTrace?.Split('\n').FirstOrDefault()?.Trim();
            reason = $"恢复异常 {failure.GetType().Name}：{failure.Message}（{at}）";
            log($"[异常跳过] 0x{entry:x} {method}：{reason}，已记录并继续");
        }
        else
        {
            return result!;
        }

        // 出现超时、超限或异常时，废弃被污染的 worker，重新创建干净的新实例
        worker = create();
        return new MethodRecoveryResult(method, entry, null, [new RecoveryHole(entry, reason)]);
    }
}


namespace Cpp2CS.Pipeline;

/// <summary>运行核心恢复流程。</summary>
public static class RecoverySession
{
    public static RecoveryRunResult Run(RecoveryRequest request, Action<string>? progress = null)
    {
        request.Validate();
        return CoreProfile.Run(request, progress);
    }

    /// <summary>后端提供基础事实；选择、恢复、校验及发布仍由公共管线执行。</summary>
    public static RecoveryRunResult Run(RecoveryRequest request,
        Func<Action<string>, Cpp2CS.Facts.ProgramFacts> buildFacts, Action<string>? progress = null)
    {
        request.Validate();
        ArgumentNullException.ThrowIfNull(buildFacts);
        return CoreProfile.Run(request, progress, buildFacts);
    }
}

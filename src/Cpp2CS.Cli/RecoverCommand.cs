using Cpp2CS.Pipeline;

namespace Cpp2CS.Cli;

internal static class RecoverCommand
{
    public static int Run(string binary, string metadata, string output, string[] options)
    {
        var request = RecoveryRequest.Parse(binary, metadata, output, options);
        if (!request.HasScope)
        {
            Console.Error.WriteLine("必须且只能指定一种恢复范围：--all、--assemblies、--namespaces、--methods 或 --types。");
            return 2;
        }
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        var result = RecoverySession.Run(request, msg =>
        {
            Console.WriteLine(msg);
            Console.Out.Flush();
        });
        Console.Write(result.Report);
        Console.Out.Flush();
        return 0;
    }
}

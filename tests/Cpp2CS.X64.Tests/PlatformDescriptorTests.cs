using System.Text;
using Cpp2CS.Facts;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Machine.Storage;
using Cpp2CS.Recovery.Calls;

namespace Cpp2CS.X64.Tests;

internal static class PlatformDescriptorTests
{
    internal static void Run(byte[] original)
    {
        var bytes = original.ToArray();
        Encoding.ASCII.GetBytes("fixture.native\0").CopyTo(bytes, 0x600);
        Encoding.ASCII.GetBytes("NativeEntry\0").CopyTo(bytes, 0x610);
        var image = ImageDocument.Parse(bytes);
        const long descriptor = -96;
        foreach (var variant in new[] { "whole", "bytes", "missing", "invalid-bool", "branches", "writable-string", "wrong-resolver", "wrong-result", "extra-call", "observable-store", "cache-phi" })
        {
            var start = new Block(0x1000) { End = 0x1100 };
            var fields = new (int Offset, ulong Value, int Width)[]
            {
                (0, 0x180003000, 64), (8, 14, 64), (16, 0x180003010, 64), (24, 11, 64),
                (32, 1, 32), (36, 1, 32), (44, variant == "invalid-bool" ? 2UL : 1UL, 8),
            };
            foreach (var field in fields)
                if (variant == "whole") start.Statements.Add(new Store(0x1000, new FrameAddress(descriptor + field.Offset), Expr.C(field.Value, field.Width)));
                else for (var index = 0; index < field.Width / 8; index++)
                {
                    if (variant == "missing" && field.Offset == 0 && index == 7) continue;
                    start.Statements.Add(new Store(0x1000, new FrameAddress(descriptor + field.Offset + index), Expr.C(field.Value >> (index * 8), 8)));
                }
            var pointer = new Variable(Storage.Gpr(0), 1);
            Call Resolve(ulong site) => new(site, CallKind.Direct, Expr.C(0x9000, 64))
                { Sources = [Storage.Gpr(1)], Arguments = [new FrameAddress(descriptor)], Results = [Storage.Gpr(0)], Defines = [pointer] };
            Call Forward(ulong site) => new(site, CallKind.Indirect, variant == "wrong-result"
                ? new Use(new Variable(Storage.Gpr(0), 0), 64) : new Use(pointer, 64));
            var function = new MachineFunction { Entry = start.Start, Range = new(start.Start, start.End, CodeRegion.Managed, BoundaryEvidence.Pdata), Blocks = [start] };
            if (variant == "branches")
            {
                var left = new Block(0x1100) { End = 0x1110 }; var right = new Block(0x1120) { End = 0x1130 };
                var join = new Block(0x1140) { End = 0x1150 };
                start.Statements.Add(new Branch(0x1002, new Read(Storage.Gpr(2), 64), left.Start, right.Start));
                left.Statements.Add(new Store(left.Start, new FrameAddress(descriptor + 36), Expr.C(0, 32)));
                right.Statements.Add(new Store(right.Start, new FrameAddress(descriptor + 36), Expr.C(1, 32)));
                left.Statements.Add(new Jump(0x1101, join.Start)); right.Statements.Add(new Jump(0x1121, join.Start));
                join.Statements.Add(Resolve(join.Start));
                join.Statements.Add(Forward(join.Start + 1));
                MachineFunction.AddEdge(start, left); MachineFunction.AddEdge(start, right);
                MachineFunction.AddEdge(left, join); MachineFunction.AddEdge(right, join);
                function = new() { Entry = start.Start, Range = function.Range with { End = join.End }, Blocks = [start, left, right, join] };
            }
            else if (variant == "cache-phi")
            {
                var cached = new Variable(Storage.Temp(5000), 1); var merged = new Variable(Storage.Temp(5001), 1);
                var initialize = new Block(0x1100) { End = 0x1110 }; var join = new Block(0x1120) { End = 0x1130 };
                start.Statements.Add(new Define(0x1002, cached, new Load(Expr.C(0x180002080, 64), 64)));
                start.Statements.Add(new Branch(0x1003, new Compare(Cond.Eq, new Use(cached, 64), Expr.C(0, 64)), initialize.Start, join.Start));
                initialize.Statements.Add(Resolve(initialize.Start));
                initialize.Statements.Add(new Store(initialize.Start + 1, Expr.C(0x180002080, 64), new Use(pointer, 64)));
                initialize.Statements.Add(new Jump(initialize.Start + 2, join.Start));
                join.Statements.Add(new Phi(join.Start, merged, [cached, pointer]));
                join.Statements.Add(Forward(join.Start + 1) with { Target = new Use(merged, 64) });
                MachineFunction.AddEdge(start, initialize); MachineFunction.AddEdge(start, join); MachineFunction.AddEdge(initialize, join);
                function = new() { Entry = start.Start, Range = function.Range with { End = join.End }, Blocks = [start, initialize, join] };
            }
            else
            {
                start.Statements.Add(Resolve(0x1002));
                if (variant != "wrong-resolver") start.Statements.Add(Forward(0x1003));
                if (variant == "extra-call") start.Statements.Add(new Call(0x1004, CallKind.Direct, Expr.C(0x9100, 64)));
                if (variant == "observable-store") start.Statements.Add(new Store(0x1004, Expr.C(0x180002088, 64), Expr.C(1, 32)));
            }
            var currentImage = image;
            if (variant == "writable-string")
            {
                var mutable = bytes.ToArray();
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(mutable.AsSpan(0x19c), 0xc0000040);
                currentImage = ImageDocument.Parse(mutable);
            }
            var import = PlatformInvokeStub.Read(function, currentImage, new UnknownCalls(), out var failure);
            if (variant is "whole" or "bytes" or "cache-phi")
                Check(import is { Library: "fixture.native", EntryPoint: "NativeEntry", ExactSpelling: true,
                    CallingConvention: System.Runtime.InteropServices.CallingConvention.Cdecl, CharSet: System.Runtime.InteropServices.CharSet.Unicode },
                    "完整描述符的宽写和逐字节写必须产生相同导入契约：" + variant + ": " + import);
            else Check(import is null, "缺字节、路径不同、可写字符串或无效布尔必须拒绝：" + variant);
            if (import is null) Check(!string.IsNullOrWhiteSpace(failure), "拒绝时必须保存具体证明缺口");
            if (variant == "missing") Check(failure!.Contains("moduleName", StringComparison.Ordinal), "缺失字节诊断必须指出具体字段");
            if (variant == "invalid-bool") Check(failure!.Contains("isNoMangle", StringComparison.Ordinal), "非法布尔诊断必须指出具体字段");
        }
        Console.WriteLine("P/Invoke 描述符检查通过：整写、字节重组、缺失位、分支冲突和布尔边界");
    }

    private sealed class UnknownCalls : IFrameCallEffects
    {
        public ArgumentUse Argument(Call call, int index) => ArgumentUse.Unknown;
        public bool WritesEscaped(Call call) => true;
        public int? StackRead(Call call) => null;
    }
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}

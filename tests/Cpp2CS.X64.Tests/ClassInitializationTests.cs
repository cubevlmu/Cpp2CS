using System.Reflection;
using Cpp2CS.Facts;
using Cpp2CS.Idioms;
using Cpp2CS.Image;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;
using Cpp2CS.Model;

namespace Cpp2CS.X64.Tests;

internal static class ClassInitializationTests
{
    internal static void Run(BaseFacts basis)
    {
        var owner = new TypeDef { Index = 0, Assembly = "Fixture.dll", Namespace = "", Name = "Owner", Token = 0x02000001,
            Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 };
        var other = new TypeDef { Index = 1, Assembly = "Fixture.dll", Namespace = "", Name = "Other", Token = 0x02000002,
            Attributes = TypeAttributes.Public, IsValueType = false, IsEnum = false, Size = 16 };
        var type = new DefinitionRef(owner, []);
        foreach (var mode in new[] { "", "cctor", "unknown-owner", "wrong-offset", "unknown-layout", "wrong-type", "narrow", "partial-path", "earlier-read" })
        {
            var caller = MethodRef.Open(new MethodDef { Index = 0, Owner = owner, Name = mode == "cctor" ? ".cctor" : "Run", Token = 0x06000001,
                Attributes = MethodAttributes.Static, ImplAttributes = 0, Slot = -1 });
            var head = new Block(0x1000) { End = 0x1010 };
            var slow = new Block(0x1010) { End = 0x1020 };
            var merge = new Block(0x1020) { End = 0x1030 };
            var initialized = mode == "wrong-type" ? new DefinitionRef(other, []) : type;
            var init = new Call(0x1001, CallKind.Direct, Expr.C(0x2000, 64)) { Op = new(OpKind.RunClassConstructor, initialized),
                Arguments = [new Symbol(SymbolKind.Class, initialized)] };
            var flag = new Load(new Binary(BinOp.Add, new Symbol(SymbolKind.Class, type),
                Expr.C(mode == "wrong-offset" ? 0xe0UL : 0x124UL, 64), 64), mode == "narrow" ? 8 : 32);
            var read = new Variable(Storage.Gpr(0), 1);
            if (mode == "partial-path")
            {
                head.Statements.Add(new Branch(0x1000, new Entry(Storage.Gpr(1)), slow.Start, merge.Start));
                slow.Statements.AddRange([init, new Jump(0x1011, merge.Start)]);
                merge.Statements.Add(new Return(0x1020) { Value = flag });
                MachineFunction.AddEdge(head, slow); MachineFunction.AddEdge(head, merge); MachineFunction.AddEdge(slow, merge);
            }
            else if (mode == "earlier-read") head.Statements.AddRange([new Define(0x1000, read, flag), init,
                new Return(0x1002) { Value = new Use(read, 32) }]);
            else head.Statements.AddRange([init, new Return(0x1002) { Value = flag }]);
            var function = new MachineFunction { Entry = head.Start, Range = new(head.Start, merge.End, CodeRegion.Managed, BoundaryEvidence.SymbolCandidate),
                Blocks = mode == "partial-path" ? [head, slow, merge] : [head] };
            function.Renumber();
            var facts = basis with { RuntimeOffsets = new(mode == "unknown-layout" ? null : 0x124, null, "独立布局见证") };
            var result = new IdiomRewriter(facts).Run(function, mode == "unknown-owner" ? null : caller);
            Check(result.Errors.Count == 0, "类初始化事实改写须保持 SSA");
            var returned = function.Blocks.SelectMany(b => b.Statements).OfType<Return>().Single().Value;
            Check((returned is Const { Value: 1, Width: 32 }) == (mode == ""),
                "只折叠已完成初始化之后的同类型标志；未知布局、静态构造、错误位置、位宽、缺少支配和旧快照均保留");
            Check(function.Blocks.SelectMany(b => b.Statements).OfType<Call>().Any(c => c.Op?.Kind == OpKind.RunClassConstructor),
                "只消除重复标志读取，初始化调用及其异常效果须保留");
        }
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

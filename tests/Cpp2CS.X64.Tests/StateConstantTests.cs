using Cpp2CS.Ir;
using Cpp2CS.Managed;
using Cpp2CS.Model;
using Cpp2CS.Recovery.Control;

namespace Cpp2CS.X64.Tests;

internal static class StateConstantTests
{
    internal static void Run(TypeDef[] core)
    {
        var integer = new DefinitionRef(core.Single(t => t.Name == "Int32"), []);
        var boolean = new DefinitionRef(core.Single(t => t.Name == "Boolean"), []);
        var state = new LocalValue(new Variable(Storage.Gpr(0), 1), integer, 32);
        var other = new LocalValue(new Variable(Storage.Gpr(1), 1), integer, 32);
        ConstantValue Constant(int n) => new(unchecked((uint)n), integer, 32);
        ManagedEdge Edge(ulong at, params ManagedCopy[] copies) => new(at, copies);
        ManagedBranch Branch(ulong at, int n, ulong yes, ulong no) => new(at, new ComparisonValue(Cond.Eq, state, Constant(n), boolean), Edge(yes), Edge(no));
        ManagedReturn Return(ulong at) => new(at, state);
        foreach (var invalidation in new[] { "", "assignment", "call", "copy", "escape", "edge-escape" })
        {
            var code = new Dictionary<ulong, List<ManagedStatement>> {
                [0] = [Branch(0, 0, 1, 2)],
                [1] = [Return(1)],
                [2] = [Branch(2, 1, 3, 4)],
                [3] = [Return(3)],
                [4] = [Return(4)],
            };
            if (invalidation == "assignment") code[1].Insert(0, new ManagedAssignment(1, state, new ArgumentValue(0, integer, 32)));
            if (invalidation == "call")
            {
                var method = MethodRef.Open(new MethodDef { Index = 0, Owner = core[0], Name = "Read", Token = 0x06000001,
                    Attributes = System.Reflection.MethodAttributes.Static, ImplAttributes = 0, Slot = -1, ReturnType = integer });
                code[1].Insert(0, new ManagedCall(1, new(method, null, [], false), state));
            }
            if (invalidation == "copy") { code[1] = [new ManagedJump(1, Edge(5, new ManagedCopy(state, Constant(7))))]; code[5] = [Return(5)]; }
            if (invalidation == "escape") code[4].Insert(0, new ManagedAssignment(4, other, new AddressValue(state)));
            if (invalidation == "edge-escape") { code[4] = [new ManagedJump(4, Edge(5, new ManagedCopy(other, new AddressValue(state))))]; code[5] = [Return(5)]; }
            StateConstants.Rewrite(code, 0, state);
            var result = (ManagedReturn)code[invalidation == "copy" ? 5UL : 1UL][^1];
            Check(invalidation is "assignment" or "call" or "escape" or "edge-escape" ? result.Value is LocalValue
                : result.Value is ConstantValue c && c.Bits == (invalidation == "copy" ? 7UL : 0UL), "分派边可证明常量；赋值、调用结果、并行复制和地址逃逸必须正确转移或撤销事实");
            Check(((ManagedReturn)code[3][^1]).Value is ConstantValue { Bits: 1 } == (invalidation is not ("escape" or "edge-escape")),
                "另一条恢复路径应独立推导状态一，地址逃逸时保持原样");
            Check(invalidation == "edge-escape" || ((ManagedReturn)code[4][^1]).Value is LocalValue, "非等值边不提供任意常量");
        }
        foreach (var backEdge in new[] { false, true })
        {
            var code = new Dictionary<ulong, List<ManagedStatement>> {
                [0] = [Branch(0, 0, 1, 2)],
                [1] = [new ManagedJump(1, Edge(3))],
                [2] = [Branch(2, 1, 3, 4)],
                [3] = backEdge ? [new ManagedBranch(3, new ArgumentValue(0, boolean, 8), Edge(1, new ManagedCopy(state, Constant(1))), Edge(4))] : [Return(3)],
                [4] = [Return(4)],
            };
            StateConstants.Rewrite(code, 0, state);
            Check(((ManagedReturn)code[backEdge ? 4UL : 3UL][^1]).Value is LocalValue, "不同状态的合流和循环必须取未知，不能用先访问的路径覆盖另一条路径");
        }
        var narrow = new ConversionValue(ConvKind.Truncate, state, integer, 8);
        var narrowed = new Dictionary<ulong, List<ManagedStatement>> {
            [0] = [new ManagedBranch(0, new ComparisonValue(Cond.Eq, narrow, new ConstantValue(0, integer, 8), boolean), Edge(1), Edge(2))],
            [1] = [Return(1)], [2] = [Return(2)],
        };
        StateConstants.Rewrite(narrowed, 0, state);
        Check(((ManagedReturn)narrowed[1][0]).Value is LocalValue, "窄化比较只约束低位，不能推断完整状态值");
    }

    private static void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
}

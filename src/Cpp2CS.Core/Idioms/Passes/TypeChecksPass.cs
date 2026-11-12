using Cpp2CS.Facts;
using Cpp2CS.Ir;
using Cpp2CS.Machine.Flow;

namespace Cpp2CS.Idioms;

internal static class TypeChecksPass
{
    internal static bool TypeChecks(this IdiomState state)
    {
        var changed = false;
        var reuseChecks = new List<Action>();
        foreach (var head in state.function.Blocks.ToArray())
        {
            if (state.removed.Contains(head) || head.Statements.LastOrDefault() is not Branch branch)
                continue;
            var normal = head.NormalSuccessors.ToArray();
            if (normal.Length != 2 || normal[0] == normal[1])
                continue;
            // 深度比较：Ult(objDepth, typeDepth) 跳到失败一侧（或 Uge 跳到继续一侧）
            if (StripConversionsPass.StripConversions(state.defs.Expand(branch.Condition)) is not Compare { Cond: Cond.Ult or Cond.Uge } depth)
                continue;
            if (StripConversionsPass.StripConversions(state.RawDefinition(StripConversionsPass.StripConversions(depth.Left)) ?? depth.Left) is not Load { Width: 8, Address: Binary { Op: BinOp.Add, Right: Const { Value: RuntimeLayout.ClassTypeHierarchyDepth } } objectDepth })
                continue;
            var expandedTypeDepth = StripConversionsPass.StripConversions(state.defs.Expand(depth.Right));
            if (expandedTypeDepth is not Load { Width: 8, Address: Binary { Op: BinOp.Add, Left: Symbol { Kind: SymbolKind.Class } type, Right: Const { Value: RuntimeLayout.ClassTypeHierarchyDepth } } })
                continue;
            if (type.Value is not DefinitionRef { Definition.IsInterface: false }
                and not GenericParameterRef { ReferenceBase: not null }) continue;
            var klass = objectDepth.Left;
            var (fail, next) = depth.Cond == Cond.Ult ? (normal[0], normal[1]) : (normal[1], normal[0]);
            if (next.Predecessors.Count != 1 || next.IsLandingPad)
                continue;
            // 继承链比较：*(klass->typeHierarchy + depth*8 - 8) == T
            var hierarchy = Fold.Simplify(new Load(Fold.Simplify(new Binary(BinOp.Add, state.defs.Expand(klass), Expr.C(RuntimeLayout.ClassTypeHierarchy, 64), 64)), 64));
            var hierarchyReads = ExprMap.Walk(hierarchy).Concat(ExprMap.Walk(expandedTypeDepth)).OfType<Load>().ToHashSet();
            bool IsHierarchyTest(Expr e, out bool equal)
            {
                equal = false;
                if (state.defs.Expand(e, 16) is not Compare { Cond: Cond.Eq or Cond.Ne } c)
                    return false;
                var (entry, symbol) = c.Right is Symbol ? (c.Left, c.Right) : (c.Right, c.Left);
                equal = c.Cond == Cond.Eq;
                if (symbol != type || entry is not Load { Width: 64 } entryLoad
                    || !HierarchyAddress(entryLoad.Address, hierarchy, expandedTypeDepth)) return false;
                hierarchyReads.Add(entryLoad);
                return true;
            }

            var result = state.Fresh();
            var op = new Call(branch.Address, CallKind.Direct, Expr.C(0, 64))
            {
                Op = new RuntimeOp(OpKind.TypeCheck, type.Value),
                Arguments = [klass],
                Results = [result.Storage],
                Defines = [result],
            };
            var isType = new Compare(Cond.Ne, new Use(result, 64), Expr.C(0, 64));
            var replaced = false;
            Expr? Substitute(Expr e)
            {
                if (e is not Compare || !IsHierarchyTest(e, out var equal))
                    return null;
                replaced = true;
                return equal ? isType : new Not(isType);
            }
            // 形态一：next 以继承链比较分支到成功/失败 → 两块合成一个分支
            if (next.Statements.LastOrDefault() is Branch compare && IsHierarchyTest(compare.Condition, out var equalTaken) && next.Statements.Take(next.Statements.Count - 1).All(s => s is Define or Nop) && next.NormalSuccessors.ToArray() is [var a0, var a1] && a0 != a1 && (a0 == fail || a1 == fail) && (a0 == fail ? a1 : a0).Predecessors.Count == 1)
            {
                if (!HierarchyEffects(next) || !FailureCompatible()) { state.Reject("typecheck", branch.Address, "继承链检查的效果或失败值不一致"); continue; }
                var success = a0 == fail ? a1 : a0;
                if ((compare.Target == success.Start) != equalTaken || success.Predecessors.Count != 1)
                    continue;
                // 定义随成功边迁移，同一继承链条件也改用已恢复的类型检查结果。
                var moved = next.Statements.OfType<Define>().Select(s => ExprMap.MapOperands(s, e => ExprMap.Map(e, Substitute))).ToList();
                var at = state.recording ? state.Start(head) : default;
                if (state.recording && state.Location(state.defs.Expand(klass), head, at) is { } klassAt && state.Location(type, head, at) is { } typeAt)
                    state.Record(Template.InlineTypeCheck, head, at, new() { ["fail"] = fail.Start, ["success"] = success.Start }, new() { ["klass"] = klassAt, ["type"] = typeAt });
                if (!state.Rewire(head, [op], new Branch(branch.Address, new Compare(Cond.Eq, new Use(result, 64), Expr.C(0, 64)), fail.Start, success.Start), [(fail, head), (success, next)], [next]))
                { state.Reject("typecheck", branch.Address, "继承链检查的控制流重接未获证明"); continue; }
                success.Statements.InsertRange(success.Statements.TakeWhile(s => s is Phi).Count(), moved);
                state.Remove([next]);
            }
            // 形态二：next 中以继承链比较作条件（如 as 的 Select）→ 原位替换为 TypeCheck 的结果（next 中深度检查已通过，两者等价）
            // 形态三：clang 可把无副作用的判断排到两次比较之间；这些判断的另一侧都是失败一侧时，失败提前到深度检查处不改变行为。
            else
            {
                var testing = next.Statements.Any(s => ExprMap.Operands(s).Any(e => ExprMap.Walk(e).Any(x => x is Compare && IsHierarchyTest(x, out _))))
                    ? next : HierarchyBlockAfterPureTests(state, next, fail, head, e => IsHierarchyTest(e, out _));
                if (testing is null)
                {
                    state.Reject("typecheck", branch.Address, "继承表槽或后继路径不匹配");
                    continue;
                }
                if (!HierarchyEffects(testing) || !FailureCompatible()) { state.Reject("typecheck", branch.Address, "继承链检查的效果或失败值不一致"); continue; }
                for (var i = 0; i < testing.Statements.Count; i++)
                    testing.Statements[i] = ExprMap.MapOperands(testing.Statements[i], e => ExprMap.Map(e, Substitute));
                if (!replaced)
                    continue;
                head.Statements.Insert(head.Statements.Count - 1, op);
                head.Statements[^1] = branch with
                {
                    Condition = depth.Cond == Cond.Ult ? new Not(isType) : isType
                };
            }

            // 同一类继承表不会因字段写入改变；支配区域中的重复比较复用此次检查。
            // 先识别其余完整检查，避免提前改掉它们的继承链条件而留下孤立深度检查。
            reuseChecks.Add(() =>
            {
                var bypassed = new HashSet<Block>();
                var pending = new Stack<Block>();
                pending.Push(state.function.EntryBlock);
                while (pending.TryPop(out var reachable))
                {
                    if (reachable == head || !bypassed.Add(reachable)) continue;
                    foreach (var successor in reachable.Successors) pending.Push(successor);
                }
                foreach (var block in state.function.Blocks.Where(b => b != head && !state.removed.Contains(b) && !bypassed.Contains(b)))
                    for (var i = 0; i < block.Statements.Count; i++)
                        block.Statements[i] = ExprMap.MapOperands(block.Statements[i], e => ExprMap.Map(e, Substitute));
            });

            state.Result.Hit(Template.InlineTypeCheck);
            changed = true;

            bool HierarchyEffects(Block block) => block.Statements.All(s => s is Define or Nop or Branch or Jump or Return
                && ExprMap.Operands(s).SelectMany(e => ExprMap.Walk(state.defs.Expand(e, 16)))
                    .All(e => e is not Intrinsic && (e is not Load load || hierarchyReads.Contains(load))));

            // 深度不足与槽位不符都将提前到 head 的失败边，必须保留两种失败的可见值。
            bool FailureCompatible()
            {
                Expr Failed(Expr expression) => Fold.Simplify(ExprMap.Map(state.defs.Expand(expression, 16), part =>
                    part is Compare && IsHierarchyTest(part, out var equal) ? Expr.C(equal ? 0UL : 1UL, 1) : null));
                var pending = new Stack<(Block From, Block At)>(); pending.Push((head, next));
                var seen = new HashSet<Block>();
                while (pending.TryPop(out var path))
                {
                    var (from, block) = path;
                    if (block == fail)
                    {
                        var expected = fail.Predecessors.IndexOf(head); var actual = fail.Predecessors.IndexOf(from);
                        if (expected < 0 || actual < 0 || fail.Statements.OfType<Phi>().Any(p =>
                            Failed(new Use(p.Sources[expected], p.Target.Width)) != Failed(new Use(p.Sources[actual], p.Target.Width)))) return false;
                        continue;
                    }
                    if (!seen.Add(block) || seen.Count > 16 || block.IsLandingPad || block.Statements.Any(s => s is Phi) || !HierarchyEffects(block)) return false;
                    if (block.Statements.LastOrDefault() is Return returned)
                    {
                        if (fail.Statements.LastOrDefault() is not Return failure
                            || fail.Statements.Any(s => s is not (Define or Nop or Return))
                            || fail.Statements.SelectMany(ExprMap.Operands).SelectMany(e => ExprMap.Walk(state.defs.Expand(e, 16))).Any(e => e is Load or Intrinsic)
                            || !ExprMap.Operands(returned).Select(Failed).SequenceEqual(ExprMap.Operands(failure).Select(Failed))) return false;
                        continue;
                    }
                    if (block.Statements.LastOrDefault() is Branch conditional)
                    {
                        var condition = Failed(conditional.Condition);
                        foreach (var successor in block.NormalSuccessors)
                            if (condition is not Const known || successor.Start == (known.Value != 0 ? conditional.Target : conditional.Fallthrough))
                                pending.Push((block, successor));
                    }
                    else if (block.NormalSuccessors.ToArray() is [var successor]) pending.Push((block, successor));
                    else return false;
                }
                return true;
            }
        }

        foreach (var reuse in reuseChecks) reuse();
        return changed;
    }

    /// <summary>只接受 hierarchy[targetDepth - 1]，不能用任意继承表元素冒充目标类型检查。</summary>
    private static bool HierarchyAddress(Expr address, Expr hierarchy, Expr depth)
    {
        var terms = TermsPass.Terms(Fold.Simplify(address));
        if (terms.Count != 3 || terms.Count(t => t == hierarchy) != 1
            || terms.Count(t => t is Const { Value: 0xfffffffffffffff8, Width: 64 }) != 1) return false;
        var index = Fold.Convert(ConvKind.ZeroExtend, depth, 64);
        return terms.Count(t => t is Binary { Width: 64, Op: BinOp.Mul, Right: Const { Value: 8 }, Left: var value } && value == index
            || t is Binary { Width: 64, Op: BinOp.Shl, Right: Const { Value: 3 }, Left: var shifted } && shifted == index) == 1;
    }

    /// <summary>
    /// 从 start 起沿单前驱的后继找到以继承链比较分支的块。途中的块只有不读内存的定义和不读内存的条件，另一侧都进入 fail；
    /// fail 的 φ 在这些边与深度检查的边上取相同的值，否则提前失败会改变合流值。
    /// </summary>
    private static Block? HierarchyBlockAfterPureTests(IdiomState state, Block start, Block fail, Block head, Func<Expr, bool> isHierarchyTest)
    {
        const int MaxTests = 4;
        static bool Pure(Expr e) => !ExprMap.Walk(e).Any(x => x is Load);
        var edges = new List<Block>();
        var current = start;
        for (var step = 0; step <= MaxTests; step++)
        {
            if (current.Statements.LastOrDefault() is not Branch test || current.NormalSuccessors.ToArray() is not [var a, var b] || a == b || a != fail && b != fail)
                return null;
            edges.Add(current);
            if (isHierarchyTest(test.Condition)) return SameFailureValues(state, fail, head, edges) ? current : null;
            if (!Pure(test.Condition) || !current.Statements.SkipLast(1).All(s => s is Nop || s is Define define && Pure(define.Value))) return null;
            current = a == fail ? b : a;
            if (current.Predecessors.Count != 1 || current.IsLandingPad || current.Handler != start.Handler) return null;
        }
        return null;
    }

    private static bool SameFailureValues(IdiomState state, Block fail, Block head, IReadOnlyList<Block> edges)
    {
        // 相等判断成立的一侧，clang 会把值换成比较的常量（GVN）；沿这条边两者相同，换回被比较的值。
        Expr Value(Phi phi, Block edge)
        {
            var value = state.defs.Expand(new Use(phi.Sources[fail.Predecessors.IndexOf(edge)], phi.Target.Width));
            return edge.Statements.LastOrDefault() is Branch { Condition: var condition } test
                && Fold.Simplify(condition) is Compare { Cond: Cond.Eq or Cond.Ne, Left: Use compared, Right: Const constant } comparison
                && (comparison.Cond == Cond.Eq ? test.Target : test.Fallthrough) == fail.Start && value == constant
                ? state.defs.Expand(compared) : value;
        }
        foreach (var phi in fail.Statements.TakeWhile(s => s is Phi).Cast<Phi>())
            if (edges.Any(edge => Value(phi, edge) != Value(phi, head))) return false;
        return true;
    }
}

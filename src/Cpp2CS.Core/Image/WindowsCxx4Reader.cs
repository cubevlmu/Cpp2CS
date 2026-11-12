using System.Buffers.Binary;

namespace Cpp2CS.Image;

/// <summary>已确认 FH4 处理器的版本化元数据解码；依据 MSVC ehdata4_export.h，不自动生成托管异常区域。</summary>
internal static class WindowsCxx4Reader
{
    private sealed class Cursor(ImageDocument image, ulong position)
    {
        internal ulong Position { get; private set; } = position;
        internal bool Byte(out byte value)
        {
            value = 0;
            if (!WindowsEhReader.Readable(image, Position, 1)) return false;
            value = image.ReadUpTo(Position, 1)[0]; Position++; return true;
        }
        internal bool Int(out uint value)
        {
            value = 0;
            if (!WindowsEhReader.Readable(image, Position, 4)) return false;
            value = BinaryPrimitives.ReadUInt32LittleEndian(image.ReadUpTo(Position, 4)); Position += 4; return true;
        }
        internal bool Unsigned(out uint value)
        {
            value = 0;
            if (!Byte(out var first)) return false;
            var length = 1;
            while (length <= 4 && (first & (1 << (length - 1))) != 0) length++;
            if (length == 5) return first == 15 && Int(out value);
            uint encoded = first;
            for (var i = 1; i < length; i++)
            {
                if (!Byte(out var next)) return false;
                encoded |= (uint)next << (i * 8);
            }
            value = encoded >> length;
            return true;
        }
        internal bool Count(out uint count) => Unsigned(out count) && count <= 1024;
    }

    internal static WindowsEhAnalysis Read(ImageDocument image, FunctionRange range)
    {
        WindowsEhAnalysis Fail(string reason) => new(WindowsHandlerKind.Cxx4, "__CxxFrameHandler4", "malformed", [], "not-proven", reason);
        ulong Address(uint rva) => image.PreferredBase + rva;
        bool Contains(ulong pc) => range.Contains(pc) || range.Fragments.Any(f => f.Contains(pc));
        var remaining = 8192;
        if (range.HandlerData is not { } data || !WindowsEhReader.Readable(image, data, 4)) return Fail("fh4-function-info-pointer-not-readable");
        var info = new Cursor(image, Address(image.ReadU32(data)));
        if (!info.Byte(out var header) || (header & 0x80) != 0) return Fail("fh4-header-reserved-or-not-readable");
        uint bbt = 0; uint? catchFrame = null;
        if ((header & 4) != 0 && !info.Unsigned(out bbt)) return Fail("fh4-bbt-flags-not-readable");
        uint unwind = 0, tries = 0;
        if ((header & 8) != 0 && (!info.Int(out unwind) || unwind == 0)) return Fail("fh4-unwind-map-not-readable");
        if ((header & 16) != 0 && (!info.Int(out tries) || tries == 0)) return Fail("fh4-try-map-not-readable");
        if (!info.Int(out var ipMap)) return Fail("fh4-ip-map-not-readable");
        if ((header & 1) != 0)
        {
            if (!info.Unsigned(out var frame)) return Fail("fh4-catch-frame-not-readable");
            catchFrame = frame;
        }

        var actions = new List<WindowsUnwindAction>();
        if (unwind != 0)
        {
            var map = new Cursor(image, Address(unwind));
            if (!map.Count(out var count)) return Fail("fh4-unwind-count-out-of-range");
            var states = new Dictionary<ulong, int> { [map.Position - 1] = -1 };
            for (var state = 0; state < count; state++)
            {
                if (--remaining < 0) return Fail("fh4-metadata-budget-exhausted");
                var entry = map.Position;
                if (!map.Unsigned(out var encoded)) return Fail("fh4-unwind-entry-not-readable");
                var backward = encoded >> 2; var kind = (byte)(encoded & 3);
                if (backward == 0 || backward > entry || !states.TryGetValue(entry - backward, out var next)) return Fail("fh4-unwind-state-backlink-invalid");
                uint action = 0; uint? objectOffset = null;
                if (kind != 0 && (!map.Int(out action) || !image.IsExecutable(Address(action)))) return Fail("fh4-unwind-action-not-executable");
                if (kind is 1 or 2)
                {
                    if (!map.Unsigned(out var offset)) return Fail("fh4-unwind-object-offset-invalid");
                    objectOffset = offset;
                }
                actions.Add(new(state, next, kind, kind == 0 ? null : Address(action), objectOffset)); states[entry] = state;
            }
        }

        var ipStates = new List<WindowsIpState>();
        bool ReadIp(uint rva, ulong segment)
        {
            if (rva == 0) return true;
            var map = new Cursor(image, Address(rva));
            if (!map.Count(out var count)) return false;
            var pc = segment;
            for (var index = 0; index < count; index++)
            {
                if (--remaining < 0) return false;
                if (!map.Unsigned(out var delta) || !map.Unsigned(out var encodedState) || encodedState > int.MaxValue || pc > ulong.MaxValue - delta) return false;
                pc += delta;
                if (!Contains(pc) && pc != range.End && !range.Fragments.Any(f => pc == f.End)) return false;
                var state = (int)encodedState - 1;
                if (actions.Count > 0 && state >= actions.Count) return false;
                ipStates.Add(new(pc, state));
            }
            return true;
        }
        if ((header & 2) == 0)
        {
            if (!ReadIp(ipMap, range.Start)) return Fail("fh4-ip-state-map-invalid");
        }
        else
        {
            if (ipMap == 0) return Fail("fh4-separated-map-null");
            var separated = new Cursor(image, Address(ipMap));
            if (!separated.Count(out var count)) return Fail("fh4-separated-count-invalid");
            var seen = new HashSet<ulong>();
            for (var index = 0; index < count; index++)
            {
                if (!separated.Int(out var segment) || !separated.Int(out var table) || !seen.Add(Address(segment))
                    || Address(segment) != range.Start && !range.Fragments.Any(f => f.Start == Address(segment))
                    || !ReadIp(table, Address(segment))) return Fail("fh4-separated-segment-ownership-not-proven");
            }
        }

        var regions = new List<WindowsCatchRegion>();
        if (tries != 0)
        {
            var map = new Cursor(image, Address(tries));
            if (!map.Count(out var count)) return Fail("fh4-try-count-invalid");
            for (var index = 0; index < count; index++)
            {
                if (!map.Unsigned(out var low) || !map.Unsigned(out var high) || !map.Unsigned(out var catchHigh)
                    || low > high || high >= catchHigh || !map.Int(out var handlersRva) || handlersRva == 0) return Fail("fh4-try-states-invalid");
                var handlers = new Cursor(image, Address(handlersRva));
                if (!handlers.Count(out var handlerCount) || handlerCount == 0) return Fail("fh4-handler-count-invalid");
                var entries = new List<WindowsCatchHandler>();
                for (var h = 0; h < handlerCount; h++)
                {
                    if (--remaining < 0) return Fail("fh4-metadata-budget-exhausted");
                    if (!handlers.Byte(out var flags) || (flags & 0xc0) != 0 || ((flags >> 4) & 3) == 3) return Fail("fh4-handler-header-invalid");
                    uint adjectives = 0, type = 0; uint? objectOffset = null;
                    if ((flags & 1) != 0 && !handlers.Unsigned(out adjectives)) return Fail("fh4-handler-adjectives-invalid");
                    if ((flags & 2) != 0 && (!handlers.Int(out type) || type == 0 || !WindowsEhReader.MappedData(image, Address(type), 17))) return Fail("fh4-type-descriptor-invalid");
                    if ((flags & 4) != 0)
                    {
                        if (!handlers.Unsigned(out var offset)) return Fail("fh4-catch-object-offset-invalid");
                        objectOffset = offset;
                    }
                    if (!handlers.Int(out var entry) || !image.IsExecutable(Address(entry))) return Fail("fh4-catch-entry-invalid");
                    var continuations = new List<ulong>();
                    for (var c = 0; c < ((flags >> 4) & 3); c++)
                    {
                        uint target;
                        if ((flags & 8) != 0 ? !handlers.Int(out target) : !handlers.Unsigned(out target)) return Fail("fh4-continuation-invalid");
                        var pc = (flags & 8) != 0 ? Address(target) : range.Start + target;
                        if (!Contains(pc)) return Fail("fh4-continuation-outside-owner");
                        continuations.Add(pc);
                    }
                    entries.Add(new(adjectives, type == 0 ? null : Address(type), objectOffset, Address(entry), continuations)
                        { NativeTypeName = type == 0 ? null : WindowsEhReader.TypeDescriptorName(image, Address(type)) });
                }
                regions.Add(new(low, high, catchHigh, entries));
            }
        }
        return new(WindowsHandlerKind.Cxx4, "__CxxFrameHandler4", "parsed", [], "not-proven",
            "cleanup-effects-exception-wrapper-binding-and-funclet-entry-state-required")
            { UnwindActions = actions, IpStates = ipStates, CatchRegions = regions, CxxHeader = header,
                BbtFlags = (header & 4) == 0 ? null : bbt, CatchFrameOffset = catchFrame };
    }
}

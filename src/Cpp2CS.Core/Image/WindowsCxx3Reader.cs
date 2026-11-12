namespace Cpp2CS.Image;

/// <summary>由处理器身份锚定的 FH3 x64 相对地址表；布局依据 MSVC ehdata.h。</summary>
internal static class WindowsCxx3Reader
{
    internal static WindowsEhAnalysis Read(ImageDocument image, FunctionRange range)
    {
        WindowsEhAnalysis Fail(string status, string reason) => new(WindowsHandlerKind.Cxx3, "__CxxFrameHandler3", status, [], "not-proven", reason);
        ulong Address(uint rva) => image.PreferredBase + rva;
        bool Readable(uint rva, int size) => rva != 0 && WindowsEhReader.Readable(image, Address(rva), size);
        if (range.HandlerData is not { } data || !WindowsEhReader.Readable(image, data, 4)) return Fail("malformed", "fh3-function-info-pointer-not-readable");
        var infoRva = image.ReadU32(data);
        if (!Readable(infoRva, 40)) return Fail("malformed", "fh3-function-info-not-readable");
        var info = Address(infoRva); var header = image.ReadU32(info);
        if ((header & 0x1fffffff) != 0x19930522) return Fail("unsupported-schema", "fh3-magic-not-supported");
        var states = image.ReadU32(info + 4); var unwind = image.ReadU32(info + 8);
        var tryCount = image.ReadU32(info + 12); var tries = image.ReadU32(info + 16);
        var ipCount = image.ReadU32(info + 20); var ips = image.ReadU32(info + 24);
        var specification = image.ReadU32(info + 32);
        if (states > 1024 || tryCount > 1024 || ipCount > 8192) return Fail("malformed", "fh3-count-out-of-range");
        if (states != 0 && !Readable(unwind, (int)states * 8) || tryCount != 0 && !Readable(tries, (int)tryCount * 20)
            || ipCount != 0 && !Readable(ips, (int)ipCount * 8)) return Fail("malformed", "fh3-table-not-readable");
        var actions = new List<WindowsUnwindAction>();
        for (var state = 0; state < states; state++)
        {
            var entry = Address(unwind) + (uint)state * 8;
            var next = unchecked((int)image.ReadU32(entry)); var action = image.ReadU32(entry + 4);
            if (next < -1 || next >= state || action != 0 && !image.IsExecutable(Address(action))) return Fail("malformed", "fh3-unwind-state-or-action-invalid");
            actions.Add(new(state, next, action == 0 ? (byte)0 : (byte)3, action == 0 ? null : Address(action), null));
        }
        var ipStates = new List<WindowsIpState>();
        ulong? previous = null;
        for (var index = 0U; index < ipCount; index++)
        {
            var entry = Address(ips) + index * 8; var pc = Address(image.ReadU32(entry)); var state = unchecked((int)image.ReadU32(entry + 4));
            if (state < -1 || state >= states || previous is { } last && pc <= last) return Fail("malformed", "fh3-ip-state-order-or-index-invalid");
            if (!range.Contains(pc) && pc != range.End && !range.Fragments.Any(f => pc == f.End))
                return Fail("unsupported-layout", "fh3-ip-state-owner-not-proven");
            ipStates.Add(new(pc, state)); previous = pc;
        }
        var regions = new List<WindowsCatchRegion>(); var remaining = 8192;
        for (var index = 0U; index < tryCount; index++)
        {
            var entry = Address(tries) + index * 20;
            var low = image.ReadU32(entry); var high = image.ReadU32(entry + 4); var catchHigh = image.ReadU32(entry + 8);
            var count = image.ReadU32(entry + 12); var handlers = image.ReadU32(entry + 16);
            if (low > high || high >= catchHigh || catchHigh >= states || count == 0 || count > 1024
                || !Readable(handlers, (int)count * 20) || (remaining -= (int)count) < 0) return Fail("malformed", "fh3-try-states-or-handlers-invalid");
            var entries = new List<WindowsCatchHandler>();
            for (var handler = 0U; handler < count; handler++)
            {
                var at = Address(handlers) + handler * 20; var type = image.ReadU32(at + 4); var body = image.ReadU32(at + 12);
                if (type != 0 && !WindowsEhReader.MappedData(image, Address(type), 17) || !image.IsExecutable(Address(body))) return Fail("malformed", "fh3-catch-type-or-entry-invalid");
                entries.Add(new(image.ReadU32(at), type == 0 ? null : Address(type), unchecked((int)image.ReadU32(at + 8)), Address(body), [])
                    { FrameOffset = unchecked((int)image.ReadU32(at + 16)), NativeTypeName = type == 0 ? null : WindowsEhReader.TypeDescriptorName(image, Address(type)) });
            }
            regions.Add(new(low, high, catchHigh, entries));
        }
        if (specification != 0 && !Readable(specification, 8)) return Fail("malformed", "fh3-exception-specification-not-readable");
        return new(WindowsHandlerKind.Cxx3, "__CxxFrameHandler3", "parsed", [], "not-proven",
            "cleanup-effects-exception-wrapper-binding-and-funclet-entry-state-required")
        {
            CxxMagic = header & 0x1fffffff, BbtFlags = header >> 29, UnwindActions = actions, IpStates = ipStates, CatchRegions = regions,
            UnwindHelpOffset = unchecked((int)image.ReadU32(info + 28)), EhFlags = image.ReadU32(info + 36),
            ExceptionSpecification = specification == 0 ? null : Address(specification),
        };
    }
}

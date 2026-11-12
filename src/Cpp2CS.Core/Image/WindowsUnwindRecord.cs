namespace Cpp2CS.Image;

/// <summary>PE 单条展开记录的原始证据；分离片段保留自身头部，不用主范围覆盖其入口状态。</summary>
public sealed record WindowsUnwindRecord(ulong Address, byte Version, byte Flags, byte PrologLength,
    byte FrameRegister, int FrameOffset, byte[] Codes, ulong? ChainedParent);

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <ehdata4_export.h>

// 使用工具链公开编码器生成边界值，作为托管读取器的独立输入。
int main()
{
    const uint32_t values[] = { 0, 1, 127, 128, 16383, 16384, 2097151,
        2097152, 268435455, 268435456, UINT32_MAX };
    for (uint32_t value : values)
    {
        uint8_t bytes[5] = {};
        const auto size = FH4::Compress::getNETencoded(bytes, value);
        std::printf("%u ", value);
        for (unsigned i = 0; i < size; ++i) std::printf("%02X", bytes[i]);
        std::puts("");
    }
}

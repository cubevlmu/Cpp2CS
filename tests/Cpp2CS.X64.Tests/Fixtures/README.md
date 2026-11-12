# Windows 异常处理夹具

`UnwindHandlers.c` 使用 MSVC 的 `__try` / `__finally`，独立于游戏二进制和元数据。它检查不可继续异常向外传播、清理次数、条件返回，以及清理块中的 `return`。

在仓库根目录的 **x64 Native Tools Command Prompt** 中执行：

```bat
if not exist artifacts mkdir artifacts
cl /nologo /O2 /W4 /TC /utf-8 tests\Cpp2CS.X64.Tests\Fixtures\UnwindHandlers.c /Foartifacts\unwind-handlers.local.obj /Feartifacts\unwind-handlers.local.exe /link /INCREMENTAL:NO /IMPLIB:artifacts\unwind-handlers.local.lib
artifacts\unwind-handlers.local.exe
```

成功时退出码为 0，并报告 80 组检查、三个清理方法的展开标志均为 2，以及 64 次清理。夹具用 `RtlLookupFunctionEntry` 读取自身的展开信息，不固定函数地址；编译器未生成预期标志时直接失败。

`ReturnFromFinally` 在 `EXCEPTION_NONCONTINUABLE` 异常后仍返回 37。因此，`UNW_FLAG_UHANDLER` 只能说明处理器参与展开，不能独立证明方法不返回；需要继续核对清理代码的控制转移。参见 [Microsoft 终止处理器语义](https://learn.microsoft.com/en-us/windows/win32/debug/termination-handler-syntax)。

这是 Windows 原生执行依据，不代表恢复器完成了清理语义恢复，也不计入游戏恢复率。C# 测试程序不会自动编译或执行这个夹具。

`CppEh.cpp` 检查 64 组正常／异常返回、清理顺序以及析构异常替代正常返回。使用 `/EHs`，因为夹具通过 C 链接名称导出可能抛出的函数；`/EHsc` 会附带 `/EHc`，把这些函数假定为不抛出，不能用于此对照。`/GS-` 将语言处理器直接关联到导入身份，避免把安全 cookie 包装识别与表解码混为同一验证。

```bat
cl /nologo /std:c++17 /EHs /GS- /MD /O2 tests\Cpp2CS.X64.Tests\Fixtures\CppEh.cpp /Foartifacts\cpp-eh-fh4.local.obj /Feartifacts\cpp-eh-fh4.local.exe /link /INCREMENTAL:NO /IMPLIB:artifacts\cpp-eh-fh4.local.lib
artifacts\cpp-eh-fh4.local.exe
dotnet tests\Cpp2CS.X64.Tests\bin\Release\net10.0\Cpp2CS.X64.Tests.dll windows-eh-image artifacts\cpp-eh-fh4.local.exe fh4
cl /nologo /std:c++17 /EHs /GS- /MD /O2 /d2FH4- tests\Cpp2CS.X64.Tests\Fixtures\CppEh.cpp /Foartifacts\cpp-eh-fh3.local.obj /Feartifacts\cpp-eh-fh3.local.exe /link /INCREMENTAL:NO /IMPLIB:artifacts\cpp-eh-fh3.local.lib
artifacts\cpp-eh-fh3.local.exe
dotnet tests\Cpp2CS.X64.Tests\bin\Release\net10.0\Cpp2CS.X64.Tests.dll windows-eh-image artifacts\cpp-eh-fh3.local.exe fh3
```

`windows-eh-image` 对照具名导出函数的版本、展开动作、IP 状态与 catch 区域，仍要求托管投影为未证明。cookie 包装和分离 funclet 的身份未由这个夹具覆盖。

将 FH4 命令的 `/MD` 替换为 `/MT` 可检查静态处理器。已知 MSVC 14.44 布局使用完整 COMDAT 指令哈希、重定位关系、无调用解码器和只读压缩整数表核对；外部处理效果及完整处理器身份保持未证明。这个版本匹配失败时继续报告未知，不尝试按数据表外观猜测。测试另外修改 525 个指令／重定位／常量表字节，逐个要求拒绝。

`Fh4Encoding.cpp` 调用当前工具链 `ehdata4_export.h` 的官方编码器，生成 1 至 5 字节压缩整数的边界输入。托管测试采用其固定输出，不以自编编码器自证解码正确。

```bat
cl /nologo /std:c++17 /EHsc tests\Cpp2CS.X64.Tests\Fixtures\Fh4Encoding.cpp /Foartifacts\fh4-encoding.local.obj /Feartifacts\fh4-encoding.local.exe
artifacts\fh4-encoding.local.exe
```

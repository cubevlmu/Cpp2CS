#include <windows.h>
#include <stdio.h>

#if !defined(_MSC_VER) || !defined(_M_X64)
#error This fixture requires MSVC and Windows x64.
#endif

#define TEST_EXCEPTION ((DWORD)0xe1234567)
#define EXPORTED __declspec(dllexport) __declspec(noinline)

static volatile LONG cleanups;

EXPORTED void ThrowWithoutCleanup(void)
{
    RaiseException(TEST_EXCEPTION, EXCEPTION_NONCONTINUABLE, 0, NULL);
}

EXPORTED void ThrowWithCleanup(void)
{
    __try {
        RaiseException(TEST_EXCEPTION, EXCEPTION_NONCONTINUABLE, 0, NULL);
    }
    __finally {
        InterlockedIncrement(&cleanups);
    }
}

EXPORTED int ReturnWithCleanup(int value)
{
    __try {
        if (value)
            RaiseException(TEST_EXCEPTION, EXCEPTION_NONCONTINUABLE, 0, NULL);
    }
    __finally {
        InterlockedIncrement(&cleanups);
    }
    return 37;
}

EXPORTED int ReturnFromFinally(void)
{
    __try {
        RaiseException(TEST_EXCEPTION, EXCEPTION_NONCONTINUABLE, 0, NULL);
    }
    __finally {
        InterlockedIncrement(&cleanups);
        // 故意从清理块返回，证明 UHANDLER 标志不能排除主体返回。
        return 37;
    }
}

static int TestFilter(DWORD code)
{
    return code == TEST_EXCEPTION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

static int UnwindFlags(DWORD64 address)
{
    DWORD64 imageBase = 0;
    PRUNTIME_FUNCTION function = RtlLookupFunctionEntry(address, &imageBase, NULL);
    const BYTE* info;
    if (!function)
        return -1;
    info = (const BYTE*)(ULONG_PTR)(imageBase + function->UnwindData);
    if ((info[0] & 7) != 1 && (info[0] & 7) != 2)
        return -1;
    return info[0] >> 3;
}

int main(void)
{
    int i;
    int throwing = UnwindFlags((DWORD64)(ULONG_PTR)&ThrowWithCleanup);
    int returning = UnwindFlags((DWORD64)(ULONG_PTR)&ReturnWithCleanup);
    int finallyReturning = UnwindFlags((DWORD64)(ULONG_PTR)&ReturnFromFinally);
    if (throwing != 2 || returning != 2 || finallyReturning != 2) {
        fprintf(stderr, "Unexpected UNWIND_INFO flags: %d, %d, %d\n", throwing, returning, finallyReturning);
        return 10;
    }

    for (i = 0; i < 16; ++i) {
        LONG before = cleanups;
        int caught = 0;
        int result = 0;
        __try {
            ThrowWithoutCleanup();
            return 11;
        }
        __except (TestFilter(GetExceptionCode())) {
            caught = 1;
        }
        if (!caught || cleanups != before)
            return 12;

        caught = 0;
        __try {
            ThrowWithCleanup();
            return 13;
        }
        __except (TestFilter(GetExceptionCode())) {
            caught = 1;
        }
        if (!caught || cleanups != before + 1)
            return 14;

        before = cleanups;
        if (ReturnWithCleanup(0) != 37 || cleanups != before + 1)
            return 15;

        before = cleanups;
        caught = 0;
        __try {
            (void)ReturnWithCleanup(1);
            return 16;
        }
        __except (TestFilter(GetExceptionCode())) {
            caught = 1;
        }
        if (!caught || cleanups != before + 1)
            return 17;

        before = cleanups;
        __try {
            result = ReturnFromFinally();
        }
        __except (TestFilter(GetExceptionCode())) {
            return 18;
        }
        if (result != 37 || cleanups != before + 1)
            return 19;
    }

    printf("80 native Windows cases passed; cleanup flags=%d/%d/%d; cleanups=%ld\n",
        throwing, returning, finallyReturning, cleanups);
    return 0;
}

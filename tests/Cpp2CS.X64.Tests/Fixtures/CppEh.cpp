#include <cstdio>

#define EXPORTED extern "C" __declspec(dllexport) __declspec(noinline)
static int trace;

struct Guard
{
    int tag;
    ~Guard() noexcept { trace = trace * 10 + tag; }
};

EXPORTED int FixtureCleanup(int n)
{
    Guard guard{1};
    if (n < 0) throw n;
    return n * 3;
}

EXPORTED int FixtureCatch(int n)
{
    try {
        Guard guard{2};
        return FixtureCleanup(n) + 1;
    }
    catch (int error) {
        Guard guard{3};
        return -error;
    }
}

struct ThrowingGuard
{
    ~ThrowingGuard() noexcept(false) { trace = trace * 10 + 4; throw 41; }
};

EXPORTED int FixtureCleanupThrows()
{
    ThrowingGuard guard;
    return 9;
}

int main()
{
    for (int n = -32; n < 32; ++n) {
        trace = 0;
        const int result = FixtureCatch(n);
        if (result != (n < 0 ? -n : n * 3 + 1) || trace != (n < 0 ? 123 : 12)) return 10;
    }
    trace = 0;
    try { FixtureCleanupThrows(); return 11; }
    catch (int error) { if (error != 41 || trace != 4) return 12; }
    std::puts("C++ EH native checks passed: 64 returns/throws with ordered cleanups; cleanup exception replaces normal return");
}

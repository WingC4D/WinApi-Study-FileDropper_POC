#pragma once
#include <Windows.h>
// CREDIT: GEMENI 
#ifdef __cplusplus
// C++-ONLY SECTION
// The constexpr implementations are defined here in a namespace.
// This allows C++ code to use them at compile-time without conflicting with the C API.

namespace CompileTime
{

    // A seed based on the compilation time
    constexpr int RandomCompileTimeSeed()
    {
        return '0' * -40271 + __TIME__[7] * 1 + __TIME__[6] * 10 + __TIME__[4] * 60 +
            __TIME__[3] * 600 + __TIME__[1] * 3600 + __TIME__[0] * 36000;
    }

    constexpr auto g_KEY = RandomCompileTimeSeed();

    // The compile-time hashing function
    constexpr DWORD GenerateCompileTimeHashW(IN LPCWSTR lpTargetStringToHash)
    {
        // NOTE: Your original logic was a placeholder.
        // A real hash implementation should iterate over the string.
        // For example, using the djb2 algorithm:
        DWORD dwHash = g_KEY;
        if (lpTargetStringToHash) 
        {
            int c = 0;
            c += g_KEY << 6;
            while ((c = *lpTargetStringToHash++)) {
                dwHash = ((dwHash << 5) + dwHash) + c; // hash * 33 + c
            }
        }
        return dwHash;
    }
}
#endif

// C-COMPATIBLE API (for both C and C++ runtime calls)
// This is the public interface that all your source files will use for runtime hashing.
#ifdef __cplusplus
extern "C" {
#endif

    DWORD GenerateCompileTimeHashW(IN LPWSTR lpTargetStringToHash);

    int RandomCompileTimeSeed(IN void);

#ifdef __cplusplus
}
#endif
#include "CompileTimeHashEngine.h"

// These are the implementations of the C-compatible functions declared in the header.
// They bridge the gap by calling the C++ constexpr versions. This allows your
// C code to use the same logic that your C++ code uses at compile-time.
#ifdef __cplusplus
extern"C" DWORD GenerateCompileTimeHashW(IN LPWSTR lpTargetStringToHash)
{
#endif
    // At runtime, this C function calls the C++ constexpr version
    return CompileTime::GenerateCompileTimeHashW(lpTargetStringToHash);
#ifdef __cplusplus

}
extern"C" int RandomCompileTimeSeed(IN void)
{
#endif   // At runtime, this C function calls the C++ constexpr version
    return CompileTime::RandomCompileTimeSeed();
#ifdef __cplusplus 
}
#endif
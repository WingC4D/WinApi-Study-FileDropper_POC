#include <Windows.h>

BOOLEAN HookNtDebugProces
(
    IN     PBYTE  pCodeToHook,
    IN     DWORD  sCodeLength,
    IN     HANDLE hTargetProcessHandle,
       OUT PVOID *pHookedFunctionAddress
)
{
    if (sCodeLength < 5) return FALSE;

    PBYTE  pLocalMappedAddress     = nullptr,
           pExtrenalMappedAddress  = nullptr;
    HANDLE hFile                   = INVALID_HANDLE_VALUE;
    SIZE_T sRelativeVirtualAddress = 0x00000000; 
    
    pLocalMappedAddress            = static_cast<PBYTE>(MapViewOfFile(hFile, PAGE_EXECUTE_READWRITE, 0, 0, sCodeLength));
    
    pLocalMappedAddress[0]         = 0x90;

    pExtrenalMappedAddress         = static_cast<PBYTE>(MapViewOfFile2(hFile, hTargetProcessHandle, 0, nullptr, sCodeLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    return FALSE;
}



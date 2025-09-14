#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <detours.h>
#include <stdio.h>

#ifdef _M_X64
#pragma comment (lib, "detoursx64.lib")
#endif

#ifdef _M_IX86
#pragma comment (lib, "detoursx86.lib")
#endif

typedef HANDLE(WINAPI* fnOpenProcess)
(
	IN     DWORD dwDesiredAccess,
    IN     BOOL  bInheritHandle,
    IN     DWORD dwProcessId
);

typedef INT (WINAPI *fnMessageBoxA)
(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_     UINT uType
);


#ifdef __cplusplus
extern "C"
{
#endif

#ifdef __cplusplus
}
#endif

//fnMessageBoxA GlobalMessageBoxA;

//In Work
BOOLEAN HookWithVirtualAlloc
(
    IN     PVOID  pFunctionToHook,
    IN     PVOID  pAddressOfMyCode,
    IN     DWORD  sHookLength
);

BOOLEAN HookLocalThreadUsingDetours
(
    IN     PVOID   fnFunctionToHook,
    IN     PVOID   pDetourFunction,
    IN     HANDLE  hThreadToHook
);

BOOLEAN UnHookLocalThreadUsingDetours
(
    IN     PVOID   fnOriginalHookedFunction,
    IN     PVOID   pDetourFunction,
    IN     HANDLE  hThreadToUnHook
);

INT WINAPI HookedMessageBoxA
(
    HWND   hWindowHandle,
	LPCSTR lpEditedBodyText,
    LPCSTR lpEditedHeaderText,
    UINT   uiType
);
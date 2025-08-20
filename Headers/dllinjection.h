#pragma once
#include <Windows.h>
#include <avrfsdk.h>
#include <stdio.h>
#include "SystemInteraction.h"

typedef ULONG (WINAPI* fnVerifierEnumerateResource)(
HANDLE                           Process,
ULONG                            Flags,
ULONG                            ResourceType,
AVRF_RESOURCE_ENUMERATE_CALLBACK ResourceCallback,
PVOID                            EnumerationContext
);

BOOLEAN APCPayloadInjection
(
	IN     HANDLE hThread,
	IN     PUCHAR pPayloadAddress,
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
	IN     LPVOID  pPayload,
	IN     DWORD   sPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID * pInjectedPayloadAddress
);

BOOLEAN InjectCallbackPayloadEnumChildWindows
(
	IN     LPVOID  pPayload,
	IN     DWORD   sPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
);

BOOLEAN InjectCallbackPayloadEnumUILanguagesW
(
	IN     LPVOID  pPayload,
	IN     DWORD   sPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID * pInjectedPayloadAddress
);

BOOLEAN InjectCallbackPayloadEnumThreadWindows
(
	IN     LPVOID  pPayload,
	IN     DWORD   sPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID * pInjectedPayloadAddress
);

BOOLEAN InjectCallbackPayloadTimer //Possible beacon function 4 C2
(
	IN     PUCHAR  pPayload,
	IN     DWORD   sPayloadSize,
	   OUT PHANDLE phTimerHandle,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
);

BOOLEAN InjectCallbackPayloadEnumDisplayMonitors
(
	IN     LPVOID  pPayload,
	IN     DWORD   sPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
);

BOOLEAN InjectCallbackPayloadVerEnumResource
(
	IN     LPVOID  pPayload,
	IN     DWORD   sPayloadSize,
	   OUT PDWORD  pdwOldProtections,
	   OUT PVOID  *pInjectedPayloadAddress
);

BOOL InjectRemoteDll
(
	IN     PVOID   pPayload,
	IN	   HANDLE  hProcess, 
	IN	   LPSTR   TargetDllName,
	IN     LPSTR   TargetFunctionName,
	IN     SIZE_T  sSizeToWrite,
	   OUT PVOID  *pRemoteFunctionAddress
);

BOOL InjectPayloadLocalProcess
(
	IN     HANDLE hProcess,
	IN     PUCHAR pPayload,
	IN     SIZE_T sPayloadSize
);

BOOLEAN InjectPayloadRemoteProcess
(
	IN     HANDLE hProcessHandle,
	IN     PUCHAR pPayloadAddress,
	IN     SIZE_T sPayloadSize,
	   OUT PVOID *pExPayloadAddress
);


BOOL StompLocalFunction
(
	IN     PVOID  pTargetFuncAddress,
	IN	   PUCHAR pPayload,
	IN     SIZE_T sPayloadSize
);

BOOL StompRemoteFunction
(
	IN     PVOID  pTargetFuncAddress,
	IN     HANDLE hTargetProcess,
	IN	   PUCHAR pPayload,
	IN     SIZE_T sPayloadSize
);
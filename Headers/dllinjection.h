#pragma once
#include <Windows.h>

#include <stdio.h>

BOOL InjectDll(HANDLE hProcess, LPWSTR pDllName);

BOOLEAN InjectRemoteProcessShellcode
(
	IN     HANDLE hProcessHandle,
	IN     PUCHAR pShellcodeAddress,
	IN     SIZE_T sShellCodeSize,
	   OUT PVOID* ppExternalAddress
);

BOOL InjectShellcode(HANDLE hProcess, PBYTE pShellcode, SIZE_T sShellcode);
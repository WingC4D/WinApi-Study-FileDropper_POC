#pragma once
#include <Windows.h>

#include <stdio.h>

BOOL InjectDll(HANDLE hProcess, LPWSTR pDllName);

BOOL InjectShellcode(HANDLE hProcess, PBYTE pShellcode, SIZE_T sShellcode);
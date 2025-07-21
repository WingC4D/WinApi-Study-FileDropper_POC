#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

HANDLE FetchProcess(LPWSTR pProcessName, PDWORD pdwProcessId);

BOOL InjectDll(HANDLE hProcess, LPWSTR pDllName);
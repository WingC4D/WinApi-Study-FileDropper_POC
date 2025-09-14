#pragma once
#pragma comment (lib, "Wininet.lib")

#include <Windows.h>
#include <wininet.h>


BOOL FetchPayloadHttpStatic(LPWSTR lpwURLString, DWORD dwPayloadSize, PBYTE *pPayloadAddress);


BOOL FetchPayloadHttpDynamic(LPWSTR lpwURLString, PBYTE *pPayloadAddress, PDWORD pdwPayloadSize);
#pragma once
#pragma comment (lib, "Wininet.lib")

#include <Windows.h>
#include <wininet.h>


BOOL FetchPayloadHttpStatic(LPWSTR pURL, USHORT sPayload, LPVOID pPayload);


BOOL FetchPayloadHttpDynamic(LPWSTR pURL, PBYTE *pPayload, PSIZE_T psPayload);
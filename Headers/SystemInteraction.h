#pragma once
#include <Windows.h>
#include "Win32FindDataArray.h"
#include <TlHelp32.h>


BOOL FetchDrives(LPWSTR pPath);

HANDLE FetchProcess(LPWSTR pProcessName, PDWORD pdwProcessId);

LPWIN32_FIND_DATA_ARRAYW FetchFileArrayW(LPWSTR pPath);

LPWIN32_FIND_DATA_ARRAYW RefetchFilesArrayW(
    LPWSTR pPath,
    LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
);

HANDLE CreateVessel(LPWSTR pPath);
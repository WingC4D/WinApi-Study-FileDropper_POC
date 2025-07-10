#pragma once

#include <Windows.h>
#include <stdio.h>

typedef struct _WIN32_FILE {
    WIN32_FIND_DATAW data; // Pointer to the dynamically allocated array
    unsigned long ulindex;
}WIN32_FILE, *LPWIN32_FILE;

typedef struct _WIN32_FIND_DATA_ARRAYW {
    LPWIN32_FILE pFiles_arr;
    size_t count;                  // Number of actual files stored in the array
} WIN32_FIND_DATA_ARRAYW, *LPWIN32_FIND_DATA_ARRAYW;

LPWIN32_FIND_DATA_ARRAYW FetchSubFiles(LPWSTR pPath);

void FetchDrives(LPWSTR pPath);

BOOL CACDrives(LPWSTR pPath, WCHAR* pAnswer);

HANDLE CreateVessel(LPWSTR pPath);

void FreeFileArray(LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t);


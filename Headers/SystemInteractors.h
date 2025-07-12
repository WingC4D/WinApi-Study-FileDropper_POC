#pragma once

#include <Windows.h>
#include <stdio.h>
#include <math.h>


typedef struct _WIN32_FILE_IN_ARRAY {
    
    WIN32_FIND_DATAW file_data; 
    
    unsigned long index;
}WIN32_FILE_IN_ARRAY, *LPWIN32_FILE_IN_ARRAY;

typedef struct _WIN32_FIND_DATA_ARRAYW {
    LPWIN32_FILE_IN_ARRAY pFiles_arr;
    HANDLE hBaseFile;
    size_t count;                  
    unsigned short order_of_magnitude;
} WIN32_FIND_DATA_ARRAYW, *LPWIN32_FIND_DATA_ARRAYW;

LPWIN32_FIND_DATA_ARRAYW FetchFileArrayW(
    LPWSTR pPath
);
LPWIN32_FIND_DATA_ARRAYW RefetchFilesArrayW(
    LPWSTR pPath,
    LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
);

BOOL FetchDrives(
    LPWSTR pPath
);

BOOL HandleStringDrives(
    LPWSTR pPath, 
    LPWSTR pAnswer
);

BOOL TraverseFolders(
    LPWSTR pPath
);

HANDLE CreateVessel(
    LPWSTR pPath
);

void FreeFileArray(
    LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
);


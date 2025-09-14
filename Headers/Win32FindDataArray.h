#pragma once

#include <Windows.h>
#include <stdio.h>
#include <math.h>

typedef struct _WIN32_FILE_IN_ARRAY
{
    LPWSTR pFileName; 
    UINT   index;
}
WIN32_FILE_IN_ARRAY, *PWIN32_FILE_IN_ARRAY;

typedef struct _WIN32_FIND_DATA_ARRAYW
{
    PWIN32_FILE_IN_ARRAY pFilesArr;
    HANDLE               hBaseFile;
    USHORT               count;                  
    
}
WIN32_FIND_DATA_ARRAYW, *LPWIN32_FIND_DATA_ARRAYW;

BOOLEAN FileBufferRoundUP
(
    PDWORD                pdwArraySize,
    PWIN32_FILE_IN_ARRAY *pFilesNames_arrAddress
);

void FreeFileArray
(
    LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
);
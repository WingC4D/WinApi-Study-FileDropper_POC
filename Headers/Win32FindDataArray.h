#pragma once

#include <Windows.h>
#include <stdio.h>
#include <math.h>


typedef struct _WIN32_FILE_IN_ARRAY {
    
    LPWSTR pFileName; 
    UINT index;

}WIN32_FILE_IN_ARRAY, *PWIN32_FILE_IN_ARRAY;

typedef struct _WIN32_FIND_DATA_ARRAYW {
    PWIN32_FILE_IN_ARRAY pFilesArr;
    
    HANDLE hBaseFile;
  
    USHORT count;                  
    
} WIN32_FIND_DATA_ARRAYW, *LPWIN32_FIND_DATA_ARRAYW;




BOOL FileBufferRoundUP(
    size_t* psArray,
    PWIN32_FILE_IN_ARRAY *pFilesNames_arr
);



void FreeFileArray(LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t);
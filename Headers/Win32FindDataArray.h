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
    
    unsigned short highest_order_of_magnitude;

} WIN32_FIND_DATA_ARRAYW, *LPWIN32_FIND_DATA_ARRAYW;




BOOL FileBufferRoundUP(
    size_t* psArray,
    LPWIN32_FIND_DATAW* pFiles_arr
);



void FreeFileArray(LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t);
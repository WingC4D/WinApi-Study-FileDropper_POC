#pragma once

#include <Windows.h>
#include <stdio.h>


WIN32_FIND_DATAW FetchSubFolders();
BOOL FetchDrives(LPWSTR drives_arr);

#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

inline LPWSTR PrintDrives(LPWSTR pDesiredDrive);
inline void PrintCWD(LPWSTR pFilepath);
inline BOOL PrintUserName();
inline LPWSTR PrintSubFolders(LPWSTR pPath);

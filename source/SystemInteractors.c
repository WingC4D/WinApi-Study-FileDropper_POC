#include "SystemInetactors.h"

LPWSTR FetchDrives(void) 
{
	WCHAR drives_arr[27] = { L'\0' };
	DWORD dwBitMask = GetLogicalDrives();
	if (dwBitMask == 0) return drives_arr;
	WCHAR base_wide_character = L'A';
	unsigned short i = 0;
	for (WCHAR counter = 0; counter <= 26; counter++)
	{
		if (dwBitMask & (1 << counter))
		{
			wprintf(L"%c", drives_arr[i]);
			drives_arr[i] = base_wide_character + counter;
			i++;
		}
	}
	return &drives_arr;
}
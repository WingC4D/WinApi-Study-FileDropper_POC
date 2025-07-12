#include "Printers.h"
#include "choosers.h"
#include "Externals.h"
#include "SystemInteractors.h"


int main(void) 
{
	call();
	
	WCHAR pPath[260] = { L'\0' };
	
	FetchDrives(pPath);
	
	if (pPath[0] == L'0')
	{
		printf("[X] Failed To Fetch Drives!\n[X] Exiting With Error Code: %x\n", GetLastError());
		return -1;
	}
	
	PrintDrives(pPath);
	
	while (!UserInputDrives(&pPath))
	{
		wprintf(
			L"[X] Wrong Input!\n"
		);
		PrintDrives(
			pPath
		);
	}
	
	PrintCWD(&pPath);
	
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t = FetchFileArrayW(&pPath);
	
	if (pFiles_arr_t == NULL) 
	{
		printf("[X] Folder Choosing || Printing Failed!\n[X] Exiting With Error Code : % x\n", GetLastError());
		return -2;
	}
	
	PrintSubFiles(pFiles_arr_t);
	
	while (!UserInputFolders(pPath, pFiles_arr_t)) {
		
		if (pFiles_arr_t == NULL) {
			printf("[!] No Files Under Current Folder.\n");
			break;
		}
		pFiles_arr_t = RefetchFilesArrayW(&pPath, pFiles_arr_t);
		PrintCWD(&pPath);
		PrintSubFiles(pFiles_arr_t);
	}
 	
	FreeFileArray(pFiles_arr_t);
	
	HANDLE hFile = INVALID_HANDLE_VALUE;
			/*
		 * GENERIC_READ = 0x80000000
		 * GENERIC_WRITE = 0x40000000. (0d1073741824).
		 * GENERIC_READ | GENERIC_WRITE = 0xC0000000. (0d3221225472).
		 */
	hFile = CreateFileW(//(Trying To Create Said Vessel.
		/*[In] */         &pPath, //{lpFileName} Casting The Program Made Path To A Long Pointer to a Constant Wide STRing &  Using It The Create The Vessel In The Dessired loaction.
		/*[In] */         GENERIC_READ | GENERIC_WRITE, // {dwDesiredAccess} Generic Read Write So it Can Be Wrote Into and Make Sure The Content Is As Expected.
		/*[In]*/          FILE_SHARE_READ, // {dwShareMode} Using Share_Read Security Attributes So Future Processes Can Read From It. (0d1).
		/*[In, Optional]*/NULL, // {lpSecurity Attributes} Currently No Other Process Is Going On Or Needs This File So NULL Is Assigned. (0d0).
		/*[In]*/          CREATE_ALWAYS, // {dwCreateDisposition} The Current Set-up Makes Sure To Create A *CLEAN* (i.e. Turncated!) File.(0d2).
		/*[In]*/          FILE_ATTRIBUTE_NORMAL, //{dwFlagsAndAttributes} Currently The Procces Doesn't Want Nor Need Any Special Attributes, Therefor FILE_ATTRIBUTES_NORMAL Is Passed. (0x80 || 0d128).
		/*[In, Optional]*/NULL // {hTemplateFile} Currently The Procces Doesnt Need Or Require A Template File Although This Seems To Be An Extremly Usefull Arguemnt. (0d0).
	);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[X] Failed To Fetch File Handle!\n[X] Exiting With Error Code: %x\n", GetLastError());
		return -3;
	}

	CloseHandle(hFile);
	printf("[#] Payload Created Successfully! :)\n");
	printf("[#] Press 'Enter' To Exit! :)");
	return 0;
}


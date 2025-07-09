#include "choosers.h"
#include "Printers.h"
#include "ErrorHandlers.h"

HANDLE CreateVessel(LPWSTR pPath) 
{
	printf("[#] Please Enter Your Desired File Name and Format Under Your Chosen Folder!\n");//Letting The User Know What Input Is Needed.
	printf("[#] %d Characters of your Input Will Be Addmited.\n", (int)(MAX_PATH - wcslen(pPath)));
	WCHAR pAnswer[MAX_PATH] = { L'\0' };//Allocating Memory For The User's Anser.
	wscanf_s(L"%259s", &pAnswer, (unsigned int)_countof(pAnswer));//Taking In User's Input. 
	int iPathLength = wcslen(pPath);//Saving The Path Length To Avoind Function Calls At Each Iteraion Of The For Loop.
	for (int i = 259; i >= (MAX_PATH - iPathLength); i--) //Cleanup Loop For User Input Exceeding The Remaining Amount Of Characters.
	{
		printf("Index: %d\n", i);
		pAnswer[i] = L'\0';
	}
	int iAnswerLength = (int)wcslen(pAnswer);
	wcscat_s(pPath, MAX_PATH, pAnswer);//Concatinating The Scanned Input Into the FilePath.
	wprintf(L"Trying To Place Payload Vessel At: %s\n",pPath);// Printing The Path To Show The User Where The Payload/File Was Trying to Be Created. 
	//SECURITY_ATTRIBUTES SecurityAttributes_t =  {NULL}; //Initialising A Security Attributes Structre With All Data Members Set To Null
	//SecurityAttributes_t.bInheritHandle = TRUE;// Setting The Structure's InheritHandle Data Member To TRUE So Another Process Can Read The Vessel's Content's If Needed.
	/* 
	* Storing The Result Of The Payload Creation Attempt To A Variable Of Type HANDLE.
	* A HANDLE Is A DWORD Value Representing The I / O Device For The Kernel.
	* DWORD = 4 bytes. This Means There Are 2 ^ 32 | 4,294,967,296 Values To Store The Result, I.E. a number ranging from 0 -> ({2^32} - 1).
	*/
	HANDLE hFile = CreateFileW(//(Trying To Create Said Vessel.
/*[In] */         (LPCWSTR)pPath, //{lpFileName} Casting The Program Made Path To A Long Pointer to a Constant Wide STRing &  Using It The Create The Vessel In The Dessired loaction.
			   /*
			    * GENERIC_READ = 0x80000000 
				* GENERIC_WRITE = 0x40000000. (0d1073741824).
			    * GENERIC_READ | GENERIC_WRITE = 0xC0000000. (0d3221225472).
				*/				
/*[In] */         GENERIC_READ | GENERIC_WRITE, // {dwDesiredAccess} Generic Read Write So it Can Be Wrote Into and Make Sure The Content Is As Expected.
/*[In]*/          FILE_SHARE_READ, // {dwShareMode} Using Share_Read Security Attributes So Future Processes Can Read From It. (0d1).
/*[In, Optional]*/NULL, // {lpSecurity Attributes} Currently No Other Process Is Going On Or Needs This File So NULL Is Assigned. (0d0).
/*[In]*/          CREATE_ALWAYS, // {dwCreateDisposition} The Current Set-up Makes Sure To Create A *CLEAN* (i.e. Turncated!) File.(0d2).
/*[In]*/          FILE_ATTRIBUTE_NORMAL, //{dwFlagsAndAttributes} Currently The Procces Doesn't Want Nor Need Any Special Attributes, Therefor FILE_ATTRIBUTES_NORMAL Is Passed. (0x80 || 0d128).
/*[In, Optional]*/NULL // {hTemplateFile} Currently The Procces Doesnt Need Or Require A Template File Although This Seems To Be An Extremly Usefull Arguemnt. (0d0).
	);
	return hFile;//Returning The Payload Vessel's File HANDLE Value To The main() Function Control Flow.
}

BOOL ChooseSubFolder(LPWSTR pPath, LPWIN32_FIND_DATAW aFolders, int i) 
{
	SIZE_T OccupiedCharacters = (SIZE_T)(wcslen(pPath) + 1);//Calculating The Amount Of Wchar's Lef
	LPWSTR pOriginalPath = calloc(OccupiedCharacters , sizeof(WCHAR));
	if (pOriginalPath == NULL)
	{ 
		PrintMemoryError(L"Original Path Copy Buffer In ChooseSubFolder");
		exit(-11);//
	}
	wcscpy_s(pOriginalPath, OccupiedCharacters, pPath);
	unsigned int sUnOccupiedCharacters = ((size_t)MAX_PATH - OccupiedCharacters) ;//
	LPWSTR pAnswer = malloc(sUnOccupiedCharacters * sizeof(WCHAR));//creating a wchar buffer with a WinAPI datatype for the user's answer
	if (pAnswer == NULL) 
	{
		free(pOriginalPath);
		PrintMemoryError(L"The User's Answer In ChooseSubFolder");
		return FALSE;
	}
	pAnswer[0] = L'\0';
	wscanf_s(L"%64s", pAnswer, sUnOccupiedCharacters);//Scan for the desired folder name; options include the ID or a full string
	int ASCII_Value = (int)pAnswer[0] - 48;
	if (0 <= ASCII_Value && (ASCII_Value <= 9 && ASCII_Value <= i))
	{
		wcscpy_s(pAnswer, sUnOccupiedCharacters, aFolders[ASCII_Value].cFileName);
	}
	wcscat_s(pPath, sUnOccupiedCharacters, pAnswer);
	wcscat_s(pPath, sUnOccupiedCharacters, L"\\");
	PrintCWD(pPath);
	if (!FolderDebugger(pPath, pOriginalPath))
	{
		free(pOriginalPath);
		free(pAnswer);
		return FALSE;
	}
	free(pOriginalPath);
	free(pAnswer);	
	return TRUE;
}

BOOL ChooseDrive(LPWSTR pPath, LPWSTR pValidCharacters)
{
	wprintf(L"Please Choose a Drive\n");
	WCHAR pAnswer [2];
	wscanf_s(L"%1s", pAnswer, 2);
	pAnswer[0] = towupper(pAnswer[0]);
	unsigned int uiAmount = (unsigned int)wcslen(pValidCharacters);
	//start cut
	for (unsigned int i = 0; i < uiAmount; i++)
	{
		if (pAnswer[0] == pValidCharacters[i])
		{
			break;
		}
		if (i == uiAmount - 1)
		{
			return FALSE;
		}
	}
	//end 
	wcscpy_s(pPath, MAX_PATH, pAnswer);
	wcscat_s(pPath, MAX_PATH, L":\\");
	PrintCWD(pPath);
	return TRUE;
}


#include "choosers.h"
#include "Printers.h"
#include "ErrorHandlers.h"

HANDLE CreateVessel(LPWSTR pPath) 
{
	
	SIZE_T sCharactersLeft = MAX_PATH - wcslen(pPath);//Calculating Dynamycally The Amount Of Character Left Out The System's Max Path Global Constant.
	LPWSTR pAnswer = malloc(sCharactersLeft * sizeof(WCHAR));//Allocating The Amount of Memory Left Without a Syscall for teh File Name.
	wprintf(L"Please Enter Your Desired File Name and Format Under Your Chosen Folder: \n");//Letting The User Know What Input Is Needed.
	/* { Currently Takes In 64 Wide Characters Untill I learn How To Dynammically Choose The Amount Of Chars Scanned In C. }*/
	wscanf_s(L"%64s", pAnswer, sCharactersLeft);//Taking In User's Input. 
	wcscat_s(pPath, MAX_PATH, pAnswer);//Concatinating The Scanned Input Into the FilePath.
	free(pAnswer);//Freeing Input's Buffer.
	wprintf(L"Trying To Place Payload Vessel At: %s\n",pPath);// Printing The Path To Show The User Where The Payload/File Was Trying to Be Created. 
	SECURITY_ATTRIBUTES SecurityAttributes_t =  {NULL}; //Initialising A Security Attributes Structre With All Data Members Set To Null
	SecurityAttributes_t.bInheritHandle = TRUE;// Setting The Structure's InheritHandle Data Member To TRUE So Another Process Can Read The Vessel's Content's If Needed.
	
	/* 
	* Storing The Result Of The Payload Creation Attempt To A Variable Of Type HANDLE.
	* A HANDLE Is A DWORD Value Representing The I / O Device For The Kernel.
	* DWORD = 4 bytes. This Means There Are 2 ^ 32 | 4,294,967,296 Values To Store The Result, I.E. a number ranging from 0 -> ({2^32} - 1).
	*/
	HANDLE hFile = CreateFileW //Trying To Create Said Vessel.
	(		
/*[In] */         (LPCWSTR)pPath, //{lpFileName} Casting The Program Made Path To A Long Pointer to a Constant Wide STRing &  Using It The Create The Vessel In The Dessired loaction.
			   /*
			    * GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000. (0d1073741824).
			    * GENERIC_READ | GENERIC_WRITE = 0xC0000000. (0d3221225472).
				*/				
/*[In] */         GENERIC_READ | GENERIC_WRITE, // {dwDesiredAccess} Generic Read Write So it Can Be Wrote Into and Make Sure The Content Is As Expected.
/*[In]*/          FILE_SHARE_READ, // {dwShareMode} Using Share_Read Security Attributes So Future Processes Can Read From It. (1)
/*[In, Optional]*/NULL, // {lpSecurity Attributes} Currently No Other Process Is Going On Or Needs This File So NULL Is Assigned. 
/*[In]*/          CREATE_ALWAYS, // {dwCreateDisposition}The Current Set-up Makes Sure To Create A *CLEAN* (i.e. Turncated!) File.(2)
/*[In]*/          FILE_ATTRIBUTE_NORMAL, //Currently The Procces Doesn't Want Nor Need Any Special Attributes, Therefor FILE_ATTRIBUTES_NORMAL Is Passed. (0x80 || 0d128)
/*[In, Optional]*/NULL //
	);
	if (hFile == INVALID_HANDLE_VALUE)//Checking If The Vessel Creation Succeeded Or Failed.
	{
		printf("Failed To Create The Vessel! :(\nExiting With Error Code: %lu\n", GetLastError());//Letting The User Know The Vessel Creation Failed And Retriving The Last OS-Provided Error Code.
		free(pPath);//Freeing The Main Buffer.
	  /*DeleteFileW();*/ //Wanted To Implament And Saw The Inherant Race Condition.
		CloseHandle(hFile);//Colsing The Allocated Association Made By The OS So This Process Can Manipulate It.
		exit (-30);//Exiting The Process With Devloper-Provided Error Code -30.
	}
	return hFile;//Returning The Payload Vessel's File HANDLE Value To The main() Function Control Flow.
}

void ChooseSubFolder(LPWSTR pPath, LPWIN32_FIND_DATAW aFolders, int i) 
{
	size_t sPathWordCount = (size_t)(wcslen(pPath) + 1);
	LPWSTR pOriginalPath = malloc(MAX_PATH * sizeof(WCHAR));
	wcscpy_s(pOriginalPath, sPathWordCount, pPath);
	if (pOriginalPath == NULL) {
		free(pPath);
		PrintMemoryError(L"Original Path Copy Buffer In ChooseSubFolder");
		exit(-11);//
	}
	size_t sCharacters = (MAX_PATH - wcslen(pPath) - 1) ;//
	LPWSTR pAnswer = malloc(sCharacters * sizeof(WCHAR));//creating a wchar buffer with a WinAPI datatype for the user's answer
	if (!pAnswer) 
	{
		free(pPath);
		free(pOriginalPath);
		PrintMemoryError(L"The User's Answer In ChooseSubFolder");
		exit(-12);
	}
	wscanf_s(L"%64s", pAnswer, sCharacters);//Scan for the desired folder name; options include the ID or a full string
	int ASCII_Value = (int)pAnswer[0] - 48;
	if (0 <= ASCII_Value && (ASCII_Value <= 9 && ASCII_Value <= i))
	{
		wcscpy_s(pAnswer, sCharacters, aFolders[ASCII_Value].cFileName);
	}
	wcscat_s(pPath, sCharacters, pAnswer);
	wcscat_s(pPath, sCharacters, L"\\");
	PrintCWD(pPath);
	if (!FolderDebugger(pPath, pOriginalPath))
	{
		free(pOriginalPath);
		//free(pPath);
		free(pAnswer);
		exit(-13);
	}
	free(pAnswer);	
	return;
}

void ChooseDrive(LPWSTR pPath, LPWSTR pValidCharacters)
{
	LPWSTR pAnswer = calloc(2, sizeof(WCHAR));
	if (pAnswer == NULL)
	{
		PrintMemoryError(L"The User's Answer In ChooseDrive");
		free(pPath);
		free(pValidCharacters);
		exit(-19);
	}
	wprintf(L"Please Choose a Drive\n");
	wscanf_s(L"%1s", pAnswer, 2);
	pAnswer[0] = towupper(pAnswer[0]);
	wprintf(L"pAnwer: %s\n", pAnswer);
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
			free(pAnswer);
			printf("Please Chose A Valid Drive\n");
			return PrintDrives(pPath);
		}
	}
	//end 
	wcscpy_s(pPath, MAX_PATH, pAnswer);
	free(pAnswer);
	wcscat_s(pPath, MAX_PATH, L":\\");
	PrintCWD(pPath);
	return;
}


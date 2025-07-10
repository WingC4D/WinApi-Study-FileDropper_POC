#include "SystemInteractors.h"

void FetchDrives(LPWSTR pPath)
{
	DWORD dwDrivesBitMask = GetLogicalDrives();//notice Dword 32bits If the function succeeds, the return value is a bitmask representing the currently available disk drives. Bit position 0 (the least-significant bit) is drive A, bit position 1 is drive B, bit position 2 is drive C, and so on.
	if (dwDrivesBitMask == 0) return FALSE;
	WCHAR base_wchar = L'A';//Holding the value 0x41 (0d65) as a WideChracter (A) and using it as the base character
	unsigned short drives_index = 0;
	for (WCHAR loop_index = 0; loop_index <= 26; loop_index++)//Casting the value of the integer held under the loopcounter to be interpeted as a wide character for human readable formatting
	{
		if (dwDrivesBitMask & (1 << loop_index))//Checking if the loop_index binary value of the loop_index (*with one bit shifted left) is bitwise and equvilant to the bistmask's values
		{
			wprintf(L"%c", pPath[drives_index]);
			pPath[drives_index] = base_wchar + loop_index;//adding the values of the loop counter + 0x41 to recive the hex value of the current wchar
			drives_index++;
		}
	}
	pPath[drives_index + 1] = (LPWSTR)L'\0';
	return;
}


BOOL CACDrives(LPWSTR pPath, WCHAR* pAnswer) {
	unsigned short buffer_length = wcslen(pPath);
	for (unsigned int i = 0; i < buffer_length; i++)
	{
		if (pAnswer[0] == pPath[i])
		{
			pPath[0] = pPath[i];
			pPath[1] = L'\0';
			break;
		}
	}
	if (pPath[1] != L'\0' || pPath[0] == L'\0') return FALSE;
	wcscat_s(pPath, MAX_PATH, L":\\");
	return TRUE;
}

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
	wprintf(L"Trying To Place Payload Vessel At: %s\n", pPath);// Printing The Path To Show The User Where The Payload/File Was Trying to Be Created. 
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


void FetchFirstFolder(LPWSTR pPath, PHANDLE phFile)
{
	
	//Adding the needed wildcard for the search
	if (phFile == INVALID_HANDLE_VALUE) //checking if the search for the first File succeeded or not.
	{
		return ;
	}
	//Deleting The Asteriks Wildcard that was used for the Search.
	
	return;
}
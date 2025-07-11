#include "SystemInteractors.h"
//Automates Taking All System-Available Drive Letter And Inputing Them To A Path Buffer.
BOOL FetchDrives(LPWSTR pPath)
{
	DWORD dwDrivesBitMask = GetLogicalDrives();//notice Dword 32bits If the function succeeds, the return value is a bitmask representing the currently available disk drives. Bit position 0 (the least-significant bit) is drive A, bit position 1 is drive B, bit position 2 is drive C, and so on.
	if (dwDrivesBitMask == 0) return FALSE;// If No Bit Was Set As 1 (i.e. 0b00000000 {Which Is 0}) The Function Failed And False Is Returned
	WCHAR base_wchar = L'A';//Holding the value 0x41 (0d65) as a WideChracter (A) and using it as the base character
	unsigned drives_index = 0;//An Index Used To Track The Amount Of Drives In The System, It's Needed Because Of the Choice To Not Dynamically Allocate Memory For The First Answer As The Start Of A Working Path Follows Very Strict Rulling Which Helps Avoid Said Dynamic Allocation and TF The Responsibility To Free The Data (Helps With Recursion & Reusability).
	for (WCHAR loop_index = 0; loop_index <= 26; loop_index++)//Casting the value of the integer held under the loopcounter to be interpeted as a wide character for human readable formatting
	{
		if (dwDrivesBitMask & (1 << loop_index))//Checking if the loop_index binary value of the loop_index (*with one bit shifted left) is bitwise and equvilant to the bistmask's values
		{
			pPath[drives_index] = base_wchar + loop_index;//adding the values of the loop counter + 0x41 to recive the hex value of the current wchar
			drives_index++;//Because A Drive Was Found Incrementing The Drives Tracking Index By 1.
		}
	}
	pPath[drives_index + 1] = L'\0';//Making Sure That Even If The User Didn't Initiate The Path Buffer As All Null Terminators That The Wide String Will Be Handeled Correctly
	return TRUE;//Returining True, The Function Succeeded.
}

//Handles String Clean Up For The Drives As They Are Loaded Into The Path Buffer.
BOOL CACDrives(
	LPWSTR pPath, 
	WCHAR* pAnswer
) {
	//The Buffer's Length is Always Shorter Than 260 and is Always possitive, TF uint.
	unsigned  buffer_length = wcslen(pPath);//Retrives The Neded Amount Of Iterations To Compare User;s Input Against.
	for (unsigned i = 0; i < buffer_length; i++)//Iterating Over The Letters Representing The Available Drives In The System.
	{
		if (pAnswer[0] == pPath[i])//Comparing The Users Inputed Answer {Always 1 w/char Long} To The Value In Each Index The Path.
		{
			pPath[0] = pPath[i];//IF It Is Taking The Value In The Index And Making It 
			pPath[1] = L'\0';//Ending The String Early So cat/cpy Functions Will Disrigard The Rest Of The Drive Letters.
			break;//Breaking The Loop, We Found Our Target, No Need To Waste Any More CPU Cycles.
		}
	}//End Of Loop Scope.
	if (pPath[1] != L'\0' || pPath[0] == L'\0') return FALSE;//If We Reached The End Of the Loop And The Second Char Isn't A Null Terminator We Return False As The User's Input Didn't Fit Any Of The Drive Character's on The System And There Was More Than One Drive.
	wcscat_s(pPath, MAX_PATH, L":\\");//This Phase Is Reached Only If The Buffer Is Ready For The Concatinating To The Path Staring String.
	return TRUE;//Returning True As Our Path Buffer Is ready For Further Use & Manipulation.
}

//Needs Work.
HANDLE CreateVessel(LPWSTR pPath)
{ 
	printf("[#] Please Enter Your Desired File Name and Format Under Your Chosen Folder!\n");//Letting The User Know What Input Is Needed.
	printf("[#] %u Characters of your Input Will Be Addmited.\n", (unsigned)(MAX_PATH - wcslen(pPath)));
	WCHAR pAnswer[MAX_PATH] = { L'\0' };//Allocating Memory For The User's Anser.
	wscanf_s(L"%259s", &pAnswer, MAX_PATH);//Taking In User's Input. 
	unsigned iPathLength = (unsigned)wcslen(pPath);//Saving The Path Length To Avoind Function Calls At Each Iteraion Of The For Loop.
	for (size_t i = 259; i >= (MAX_PATH - iPathLength); i--) //Cleanup Loop For User Input Exceeding The Remaining Amount Of Characters.
	{
		printf("Index: %d\n", i);
		pAnswer[i] = L'\0';
	}
	unsigned iAnswerLength = (unsigned)wcslen(pAnswer);
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

//Handles Dynamic Small (RN Not As Possible) Memory Allocation For The Creation Of The Files Array Struct.
BOOL FileBufferRoundUP(size_t *sArraySize, LPWIN32_FIND_DATAW *pFiles_arr)
{
	*sArraySize = *sArraySize  * 2;//Doubling The Wanted Array Size
	LPWIN32_FIND_DATAW pTemp = (LPWIN32_FIND_DATAW)realloc(*pFiles_arr, *sArraySize * sizeof(WIN32_FIND_DATAW)); //Reallocating The Scaled Up Array Size;
	if (pTemp == NULL) return FALSE; //If The Reallction failed returning False.
	*pFiles_arr = pTemp;//Chaniging the Pointer's Value To The New Address.
	return TRUE;
}

//Automates The Freeing Of The Dynamic Allocation For The Files Array Struct & All Of It's Nested Dynamic Allocations.
void FreeFileArray(LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t) 
{
	free(pFiles_arr_t->pFiles_arr);
	free(pFiles_arr_t);
	return;
}

/*
 * Shortens and Automates The Fetching of Files Under A Working Path, Using Only, Said Path .
 * Returing All The Files In An Struct Holding The Array For Easier Further Manipulation. 
 */
LPWIN32_FIND_DATA_ARRAYW CreateFilesArrayW(
	LPWSTR pPath
)
{
	//Initilizing Data Needed.
	HANDLE hFile = INVALID_HANDLE_VALUE;//Initializing The hFile Value as INVAILD_HANDLE_VALUE As A Net To Catch Any Reason The First File Finding Filed
	WIN32_FIND_DATAW find_data_t;//Allocating memory for a Find_Data Structure to hold the file's info.
	size_t sArraySize = 3;//Initail Array Size
	LPWIN32_FILE pFiles_arr = calloc(sArraySize, sizeof(WIN32_FILE));//Creating a Dynamic Buffer To Hold The Folder Data Structs
	if (pFiles_arr == NULL) return FALSE;
	//Creating The Needed Search Path
	wcscat_s(pPath, MAX_PATH, L"*");//Adding the needed wildcard for the search.
	hFile = FindFirstFileW(pPath, &find_data_t);//using the Path With The Asteriks Wild Card to Look Under The Current Path For The First File HANDLE & Storing The WIN32_Find_DATA At An Initialized and refrenced Address.
	//Clearing Path
	pPath[wcslen(pPath) - 1] = L'\0';//Deleting The Asteriks Wildcard that was used for the Search.
	//Saftey Net
	if (hFile == INVALID_HANDLE_VALUE)  return NULL;//checking if the search for the first File succeeded or not.
	unsigned i = 0;//Running Index
	//File Retrival
	while (FindNextFileW(hFile, &find_data_t)) //checks if there are any more files, while there are, the returned value is a BOOL holding "TRUE" else it is "FALSE"
	{	
		pFiles_arr[i].data = find_data_t;
		pFiles_arr[i].ulindex = i;
		if ((i == sArraySize / 2) && 
			(FileBufferRoundUP(&sArraySize, &pFiles_arr) == FALSE))
			return NULL; //If The Buffer Reallocation Failed Return NULL
		i++;
	}
	WIN32_FIND_DATA_ARRAYW *pFiles_arr_t = malloc(i * sizeof(WIN32_FIND_DATA_ARRAYW));
	pFiles_arr_t->pFiles_arr = pFiles_arr;
	pFiles_arr_t->count = i;
	return pFiles_arr_t;
}
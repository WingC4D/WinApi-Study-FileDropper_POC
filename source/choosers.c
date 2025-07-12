#include "choosers.h"
#include "Printers.h"
#include "ErrorHandlers.h"
#include "SystemInteractors.h"

BOOL UserInputDrives(
	LPWSTR pPath
)
{
	wprintf(L"Please Choose a Drive\n");
	
	WCHAR pAnswer[2];
	
	wscanf_s(L"%1s", pAnswer, 2);
	
	pAnswer[0] = towupper(pAnswer[0]);
	
	return HandleStringDrives(pPath, &pAnswer);
}


BOOL UserInputFolders(
	LPWSTR pPath,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
)
{
	UserAnswer_t Answer_t = { NULL };
	
	WCHAR answer[MAX_PATH] = { L'\0' };
	
	wscanf_s(L"%259s", &answer, MAX_PATH);
	
	Answer_t.string = &answer;
	
	Answer_t.length = wcslen(answer);
	
	Answer_t.in_index = FALSE;
	
	CheckUserInputOuputAnswerFolders(
		pPath,
		pFiles_arr_t,
		&Answer_t
	);
	
	return UserIOTraverseFolders();
}

BOOL CheckUserInputOuputAnswerFolders(
	LPWSTR pPath, 
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t, 
	pUserAnswer_t pAnswer_t
) 
{
	int remainder = pFiles_arr_t->count;//Initilizing The Remainder with The Value Of the Count Files In The Array As None Was Scanned Yet
	
	int Power2Raise2 = pFiles_arr_t->order_of_magnitude;//Holding The Order Of Magnitude In A Second So We Can Manipulate This Number Without Manipulating The Original Data Member
		
	for (unsigned i = 0; i <= pFiles_arr_t->order_of_magnitude; i++)
	{
		if (pAnswer_t->length > pFiles_arr_t->order_of_magnitude + 1) break;
		CheckIfAnswerIsIndex(
			pFiles_arr_t,
			pAnswer_t,
			&remainder,
			&Power2Raise2,
			&i
		);
		
		if (pAnswer_t->in_index) break;
		
		Power2Raise2 -= 1;
	}
	if (pAnswer_t->in_index) AddFolder2PathIndex(pPath, pAnswer_t, pFiles_arr_t);
	
	else AddFolder2PathString(pPath, pAnswer_t);
	wcscat_s(pPath, MAX_PATH, L"\\");
	return TRUE;
}

void CheckIfAnswerIsIndex(
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t,
	pUserAnswer_t pAnswer_t,
	int *pRemainder,
	int *pPower2Raise2,
	int *pIndex
)
{
	int max_num_in_index = floor(*pRemainder / pow(10, *pPower2Raise2));

	int index_real_value = max_num_in_index * pow(10, *pPower2Raise2);

	pRemainder -= index_real_value;

	int ASCIIValue = pAnswer_t->string[*pIndex] - 48;

	if ((0 < ASCIIValue && ASCIIValue < max_num_in_index) && pPower2Raise2 == 0)
	{
		
		pAnswer_t->in_index = TRUE;
		return;
	}
	else if (*pIndex == 0 && ASCIIValue == max_num_in_index)
	{
		for (int i = *pIndex; i <= pFiles_arr_t->order_of_magnitude; i++)
		{
			if (max_num_in_index > ASCIIValue || ASCIIValue > 0) return;
		}
		
		pAnswer_t->in_index = TRUE;
		return;
	}
	
	else if ((0 <= ASCIIValue && ASCIIValue < 10)) {
		pAnswer_t->in_index = TRUE;
		return;
	}
	
	return;
}

void AddFolder2PathString(
	LPWSTR pPath,
	pUserAnswer_t pAnswer_t
)
{
	unsigned index = wcslen(pPath);
	
	unsigned leftchars = MAX_PATH - index;
	
	unsigned AnswerLength = wcslen(pAnswer_t->string);
	
	if (wcslen(pAnswer_t->string) > leftchars)
	{
		for (unsigned i = 259; i > index; i--)
		{
			pAnswer_t->string[i] = L'\0';
		}
	}
	wcscat_s(pPath, MAX_PATH, pAnswer_t->string);
	
	return;
}

void AddFolder2PathIndex(
	LPWSTR pPath,
	pUserAnswer_t pAnswer_t,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
) 
{
	int index = 0;
	
	
	for (int i = 0; i < pAnswer_t->length; i++) {
		index += (pAnswer_t->string[i] - 48) * pow(10, pAnswer_t->length - i - 1);
	}
	
	size_t filename_length = wcslen(pFiles_arr_t->pFiles_arr[index].file_data.cFileName);
	
	pFiles_arr_t->pFiles_arr[index].file_data.cFileName[filename_length] = L'\0';
	
	wcscat_s(pPath, MAX_PATH, pFiles_arr_t->pFiles_arr[index].file_data.cFileName);
	
	return;
}

BOOL UserIOTraverseFolders(
	void 
) 
{
	printf("Are You Finished Traversing The System?\n");
	BOOL result = TRUE;
	
	WCHAR answer[2] = { L'\0' };
	
	wscanf_s(L"%1s", &answer, 2);
	
	switch (answer[0])
	
	{
	case L'y':
	
	case L'Y':
	
		break;
	
	case L'n':
	
	case L'N':
		
		result = FALSE;
		
		break;
	}
	
	return result;
}
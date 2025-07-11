#include "choosers.h"
#include "Printers.h"
#include "ErrorHandlers.h"
#include "SystemInteractors.h"
#include <math.h>

BOOL UserIODrives(
	LPWSTR pPath
)
{
	wprintf(L"Please Choose a Drive\n");
	WCHAR pAnswer[2];
	wscanf_s(L"%1s", pAnswer, 2);
	pAnswer[0] = towupper(pAnswer[0]);
	BOOL result = CACDrives(pPath, &pAnswer);
	return result;

}

BOOL UserIOFolders(
	LPWSTR pPath,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
)
{
	UserAnswer_t Answer_t = { NULL };
	LPWSTR pAnswer[MAX_PATH] = { L'\0' };
	wscanf_s(L"%259s", pAnswer, MAX_PATH);
	Answer_t.data = &pAnswer;
	Answer_t.length = wcslen(pAnswer);
	CheckFoldersAnswer(
		pPath,
		pFiles_arr_t,
		&Answer_t
	);
	return UserIOTraverseFolders();
}

BOOL CheckFoldersAnswer(
	LPWSTR pPath, 
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t, 
	pUserAnswer_t pAnswer_t
) 
{
	//Calculating How Manny Possible characters can be numbers that represent an index and the highest value of each indavidual char.
	int remainder = pFiles_arr_t->count;//Checking The count Data Member Of The Files Array Struct
	pFiles_arr_t->OOM = floor(log10(pFiles_arr_t->count));//Checking The Counts Order Of Magnitude; To Be Moved
	int Power2Raise2 = pFiles_arr_t->OOM;
	WCHAR index_text[10];
	//printf("Start Value: %d\nCurrent Power Of 10: %d\n", remainder, OrderOfMagnitduted);
	pAnswer_t->in_index = FALSE;
	for (unsigned i = 0; i <= pFiles_arr_t->OOM; i++)
	{
		if (pAnswer_t->length > pFiles_arr_t->OOM + 1) break;
		int max_value_in_Index_i = floor(remainder / pow(10, Power2Raise2));
		int current_order_value = max_value_in_Index_i * pow(10, Power2Raise2);
		remainder -= current_order_value;
		int ASCII_Value = pAnswer_t->data[i] - 48;
		//wprintf(L"Value in ASCII: %d\nMax Value In Index i:%d\n", ASCII_Value, max_value_in_Index_i);
		if ((0 < ASCII_Value  && ASCII_Value < max_value_in_Index_i) && i == 0) 
		{
			pAnswer_t->in_index = TRUE;
			break;
		}
		else if(i == 0 && ASCII_Value == max_value_in_Index_i)
		{
			pAnswer_t->in_index = TRUE;
			for (i; i <= pFiles_arr_t->OOM; i++) 
			{
				if (max_value_in_Index_i > ASCII_Value || ASCII_Value > 0) 
				{
					pAnswer_t->in_index = TRUE;
					break;
				}
			}	
			break;
		}
		else if ((0 <= ASCII_Value && ASCII_Value < 10)) 
		{

			pAnswer_t->in_index = TRUE;
			break;
		}
		Power2Raise2 -= 1;
	}
	FolderPathCat(
		pPath,
		pAnswer_t, 
		pFiles_arr_t
	);//Calling FolderPathCat; A Function I Built To Handle The Path Buffer Values & Append Correctly The Folder To The Path.
	return TRUE;
}

void FolderPathCat(
	LPWSTR pPath, 
	pUserAnswer_t pAnswer_t,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
) 
{
	if (pAnswer_t->in_index) 
	{
		NumFolderPathCat(
			pPath,
			pAnswer_t,
			pFiles_arr_t
		);
	}
	else 
	{
		TextFolderPathCat(
			pPath,
			pAnswer_t
		);
	}
	wcscat_s(
		pPath,
		MAX_PATH, 
		L"\\\0"
	);
	PrintCWD(pPath);
	return;
}

void TextFolderPathCat(
	LPWSTR pPath,
	pUserAnswer_t pAnswer_t
)
{
	unsigned index = wcslen(pPath);
	unsigned leftchars = MAX_PATH - index;
	unsigned AnswerLength = wcslen(pAnswer_t->data);
	if (wcslen(pAnswer_t->data) > leftchars)
	{
		for (unsigned i = 259; i > index; i--)
		{
			pAnswer_t->data[i] = L'\0';
		}
	}
	wcscat_s(pPath, MAX_PATH, pAnswer_t->data);
	return;
}


void NumFolderPathCat(
	LPWSTR pPath,
	pUserAnswer_t pAnswer_t,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
) 
{
	int index = 0;
	for (int i = 0; i < pAnswer_t->length; i++)
	{
		index += (pAnswer_t->data[i] - 48) * pow(10, pAnswer_t->length - i - 1);
	}
	pFiles_arr_t->pFiles_arr[index].data.cFileName[wcslen(pFiles_arr_t->pFiles_arr[index].data.cFileName)] = L'\0';
	wcscat_s(pPath, MAX_PATH, pFiles_arr_t->pFiles_arr[index].data.cFileName);
	return;
}

BOOL UserIOTraverseFolders(
	void 
) 
{
	printf("Are You Finished Traversing The System?\n");
	BOOL result = TRUE;
	WCHAR pAnswer[2] = { L'\0' };
	wscanf_s(L"%1s", &pAnswer, 2);
	switch (pAnswer[0])
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
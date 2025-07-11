#include "choosers.h"
#include "Printers.h"
#include "ErrorHandlers.h"
#include "SystemInteractors.h"
#include <math.h>

BOOL CheckFoldersAnswer(
	LPWSTR pPath, 
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t, 
	LPWSTR pAnswer
) {
	//Calculating How Manny Possible characters can be numbers that represent an index and the highest value of each indavidual char.
	int remainder = pFiles_arr_t->count;
	int OrderOfMagnitduted = floor(log10(pFiles_arr_t->count));
	int Power2Raise2 = OrderOfMagnitduted;
	int* file_index = (int*)malloc(((OrderOfMagnitduted + 1) * sizeof(int)) + 1);
	WCHAR index_text[10];
	if (!file_index) return FALSE;
	//printf("Start Value: %d\nCurrent Power Of 10: %d\n", remainder, OrderOfMagnitduted);
	for (unsigned i = 0; i <= OrderOfMagnitduted; i++)
	{
		int max_value_in_Index_i = floor(remainder / pow(10, Power2Raise2));
		int current_order_valuse = max_value_in_Index_i * pow(10, Power2Raise2);
		remainder -= current_order_valuse;
		WCHAR ASCII_Value = pAnswer[i] - 48;
		if (!(0 <= ASCII_Value < max_value_in_Index_i)) break;
		//printf("Remainder: %d\n", remainder);
		file_index[i] = (int)ASCII_Value;
		index_text[i] = (WCHAR)pAnswer[i];
		index_text[i + 1] = L'\0';
		Power2Raise2 -= 1;
	}
	FolderPathCat(pPath, index_text, pAnswer, file_index, pFiles_arr_t);
	return TRUE;
}

void FolderPathCat(
	LPWSTR pPath, 
	LPWSTR index_text, 
	LPWSTR pAnswer,
	int *file_index,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
) {
	size_t index_len = wcslen(index_text);
	if (index_len > 0) {
		int starting_point = wcslen(pPath);
		int index = 0;
		for (int i = 0; i < index_len; i++)
		{
			index += file_index[i] * pow(10, (index_len - 1 - i));
			//printf("Index Result: %d\n", file_index[i]);
		}
		//printf("%d\n", index);
		pFiles_arr_t->pFiles_arr[index].data.cFileName[wcslen(pFiles_arr_t->pFiles_arr[index].data.cFileName)] = L'\0';
		wcscat_s(pPath, MAX_PATH, pFiles_arr_t->pFiles_arr[index].data.cFileName);
	}
	else
	{
		unsigned index = wcslen(pPath);
		for (unsigned i = 259; i > index; i--)
		{
			pAnswer[i] = L'\0';
		}
		wcscat_s(pPath, MAX_PATH, pAnswer);
	}
	wcscat_s(pPath, MAX_PATH, L"\\\0");
	return;
}



BOOL UserIODrives(LPWSTR pPath)
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
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t) 
{
	WCHAR pAnswer[MAX_PATH] = { L'\0' };
	wscanf_s(L"%99s", &pAnswer, 260);
	BOOL result = CheckFoldersAnswer(pPath, pFiles_arr_t, pAnswer);
	return result;
}
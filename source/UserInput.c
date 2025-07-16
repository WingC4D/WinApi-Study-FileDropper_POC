#include "UserInput.h"

BOOL UserInputDrives(
	const LPWSTR pPath
)
{
	wprintf(L"Please Choose a Drive\n");
	
	WCHAR *pAnswer[2];
	
	wscanf_s(L"%1s", pAnswer, 2);
	
	pAnswer[0] = towupper(pAnswer[0]);
	
	return HandleStringDrives(pPath, pAnswer);
}


BOOL UserInputFolders(
	const LPWSTR pPath,
	const LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
)
{
	UserAnswer_t Answer_t = { NULL };
	
	WCHAR answer[MAX_PATH] = { L'\0' };
	
	wscanf_s(L"%259s", &answer, MAX_PATH);
	
	Answer_t.string = &answer;

	Answer_t.length = wcslen(answer);
	
	Answer_t.in_index = FALSE;
	
	CheckUserInputFolders(
		pPath,
		pFiles_arr_t,
		&Answer_t
	);
	
	return UserInputContinueFolders();
}

BOOL CheckUserInputFolders(
	const LPWSTR pPath,
	const LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t,
	const pUserAnswer_t pAnswer_t
) 
{
	int remainder = pFiles_arr_t->count;
	
	int curr_order_of_magnitude = pFiles_arr_t->highest_order_of_magnitude;

	IsInputIndexed(
		pFiles_arr_t,
		pAnswer_t
	);
		
	if (pAnswer_t->in_index) AddFolder2PathIndex(pPath, pAnswer_t, pFiles_arr_t);
	else AddFolder2PathString(pPath, pAnswer_t);

	wcscat_s(pPath, MAX_PATH, L"\\");

	return TRUE;
}

void IsInputIndexed(
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t,
	pUserAnswer_t pAnswer_t
)
{
	int order_of_magnitude = pFiles_arr_t->highest_order_of_magnitude;

	int remainder = pFiles_arr_t->count;
		
	int index_char_value = floor(remainder / pow(10, order_of_magnitude));

	int index_num_value = index_char_value * pow(10, order_of_magnitude);

	remainder -= index_num_value;

	unsigned int curr_index = 0;

	int curr_ASCII_value = pAnswer_t->string[curr_index] - '0';

	if (0 < curr_ASCII_value && curr_ASCII_value < index_char_value)
	{
		
		pAnswer_t->in_index = TRUE;
		return;
	}
	if (curr_index == 0 && curr_ASCII_value == index_char_value)
	{

		curr_index++;
		for (curr_index; curr_index <= pFiles_arr_t->highest_order_of_magnitude; curr_index++)
		{

			order_of_magnitude--;

			int current_max_char = remainder / (int)pow(10, order_of_magnitude);

			int current_character = pAnswer_t->string[curr_index] - '0';

			if (current_max_char < current_character || (current_character) < 0) return;

			if (current_character != current_max_char) break;
		}
		pAnswer_t->in_index = TRUE;
		return;
	}
}



BOOL UserInputContinueFolders(
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
#include "UserInput.h"

BOOL UserInputDrives(
	const LPWSTR pPath
)
{
	wprintf(L"Please Choose a Drive\n");
	
	WCHAR *pAnswer[2];
	
	fgets(pAnswer,2, stdin);
	
	pAnswer[0] = towupper(pAnswer[0]);
	
	return HandleStringDrives(pPath, pAnswer);
}


void UserInputFolders(
	LPWSTR pPath,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
)
{
	USHORT sAnswer;
	
	getchar();
	printf("Which folder would you like to choose?\n");
	
	WCHAR pAnswer[MAX_PATH];
	
	fgetws(pAnswer, MAX_PATH - 1, stdin);
	
	sAnswer = wcslen(pAnswer) -1;
	pAnswer[sAnswer] = '\0';
	
	if (sAnswer < 1) UserInputFolders(pPath, pFiles_arr_t);
	
	if (!IsInputIndexed(pFiles_arr_t, pAnswer, sAnswer)) AddFolder2PathString(pPath, pAnswer, sAnswer);
	else AddFolder2PathIndex(pPath, pAnswer, sAnswer, pFiles_arr_t);

	wcscat_s(pPath, MAX_PATH,L"\\");
}

BOOL CheckUserInputFolders(
	const LPWSTR pPath,
	const LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t,
	const pUserAnswer_t pAnswer_t
) 
{
	
	
	

	wcscat_s(pPath, MAX_PATH, L"\\");

	return TRUE;
}

BOOL IsInputIndexed(
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t,
	PWCHAR pAnswer,
	USHORT sAnswer
)
{
	USHORT order_of_magnitude = floor(log10(pFiles_arr_t->count));
	
	USHORT remainder = pFiles_arr_t->count;
	
	USHORT index_char_value = floor(remainder / pow(10, order_of_magnitude));

	USHORT index_num_value = index_char_value * pow(10, order_of_magnitude);

	remainder -= index_num_value;

	USHORT curr_index = 0;

	int curr_ASCII_value = pAnswer[curr_index] - '0';

	if (0 <= curr_ASCII_value && curr_ASCII_value < index_char_value)
	{
		return TRUE;
	}
	if ((sAnswer < order_of_magnitude + 1) && (0 <= curr_ASCII_value <= 9)) return TRUE;
	if (curr_index == 0 && curr_ASCII_value == index_char_value)
	{
		curr_index++;
		for (curr_index; curr_index <= order_of_magnitude; curr_index++)
		{

			order_of_magnitude--;

			USHORT current_max_char = remainder / (int)pow(10, order_of_magnitude);

			USHORT current_character = pAnswer[curr_index] - '0';

			if (current_max_char < current_character || current_character <= 0) return FALSE;

			if (current_character != current_max_char) break;
		}
		return TRUE;
	}
	return FALSE;
}



BOOL UserInputContinueFolders(
	void 
) 
{
	printf("Are You Finished Traversing The System?\n");
	BOOL result = TRUE;
	
	WCHAR answer[2] = { L'\0' };
	
	fgets(answer, 2, stdin);
	
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
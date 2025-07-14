#include "StringHandlers.h"

BOOL HandleStringDrives(
	LPWSTR pPath,
	LPWSTR pAnswer
) {

	unsigned  buffer_length = wcslen(pPath);

	for (unsigned i = 0; i < buffer_length; i++)
	{
		if (pAnswer[0] == pPath[i])
		{
			pPath[0] = pPath[i];

			pPath[1] = L'\0';

			break;
		}
	}
	if (pAnswer[0] != pPath[0]) return FALSE;

	wcscat_s(pPath, MAX_PATH, L":\\");

	return TRUE;
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
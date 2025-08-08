#include "UserInput.h"

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
	PWCHAR pAnswer,
	USHORT sAnswer
)
{
	UINT index = strlen(pPath);

	USHORT leftchars = MAX_PATH - index;

	if (sAnswer > leftchars)
	{
		for (unsigned i = 259; i > index; i--)
		{
			pAnswer[i] = L'\0';
		}
	}
	wcscat_s(pPath, MAX_PATH, pAnswer);

	return;
}

void AddFolder2PathIndex(
	LPWSTR pPath,
	const PWCHAR pAnswer,
	USHORT sAnswer,
	LPWIN32_FIND_DATA_ARRAYW pFiles_arr_t
)
{
	USHORT index = 0;
		for (int i = 0; i < sAnswer; i++) {
		index += (pAnswer[i] - L'0') * pow(10, sAnswer - i - 1);
	}
	wcscat_s(pPath, MAX_PATH, pFiles_arr_t->pFilesArr[index].pFileName);
	
}
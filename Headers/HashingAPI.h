#pragma once
#include <Windows.h>
#ifdef __cplusplus
extern "C" {
#endif

DWORD HashStringDjb2W
(
	IN     LPWSTR pwStringToHash,
	IN     DWORD  dwInitialHash,
	IN     DWORD  dwInitialSeed
);

DWORD HashStringDjb2A
(
	IN	   LPSTR  pStringToHash,
	IN     DWORD  dwInitialHash,
	IN     DWORD  dwInitialSeed
);

DWORD HashStringJenkinsOneEachTime32BitA
(
	IN     LPSTR pStringToHash,
	IN     DWORD dwInitialSeed
);

DWORD HashStringJenkinsOneEachTime32BitW
(
	IN     LPWSTR pStringToHash,
	IN     DWORD  dwInitialSeed
);

DWORD HashStringLoseLoseA
(
	IN	   LPSTR pStringToHash,
	IN	   DWORD dwInitialSeed
);

DWORD HashStringLoseLoseW
(
	IN	   LPWSTR pStringToHash,
	IN	   DWORD  dwInitialSeed
);

DWORD HashStringRotr32A
(
	IN     LPSTR pStringToHash,
	IN     DWORD dwInitialSeed
);

DWORD HashStringRotr32W
(
	IN     LPWSTR pStringToHash,
	IN	   DWORD  dwInitialSeed
);
#ifdef __cplusplus
}
#endif
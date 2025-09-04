#include "../HashingAPI.h"
extern"C" {
	DWORD HashStringDjb2A
	(
		IN	   LPSTR  pStringToHash,
		IN     DWORD  dwInitialHash,
		IN     DWORD  dwInitialSeed
	)
	{
		DWORD dwHash = dwInitialHash;
		CHAR  cChar = 0x0;

		while ((cChar = *pStringToHash++) != 0x0)
		{
			dwHash = (dwHash << dwInitialSeed) + dwHash + static_cast<DWORD>(cChar);
		}

		return dwHash;
	}

	DWORD HashStringDjb2W
	(
		IN     LPWSTR pwStringToHash,
		IN     DWORD  dwInitialHash,
		IN     DWORD  dwInitialSeed
	)
	{
		DWORD dwHash = dwInitialHash;
		WORD  wChar = 0x0;


		while ((wChar = *pwStringToHash++) != 0x0)
		{
			dwHash = (dwHash << dwInitialSeed) + dwHash + static_cast<DWORD>(wChar);
		}
		return dwHash;
	}

	DWORD HashStringJenkinsOneEachTime32BitA
	(
		IN	   LPSTR pStringToHash,
		IN	   DWORD dwInitialSeed
	)
	{
		BYTE  bChar = 0x0;
		DWORD dwHash = 0x0;

		while ((bChar = *pStringToHash++) != 0)
		{
			dwHash += bChar;
			dwHash += dwHash << dwInitialSeed;
			dwHash ^= dwHash >> 6;
		}

		dwHash += dwHash << 3;
		dwHash ^= dwHash >> 11;
		dwHash += dwHash << 15;

		return dwHash;
	}

	DWORD HashStringJenkinsOneEachTime32BitW
	(
		IN     LPWSTR pStringToHash,
		IN     DWORD  dwInitialSeed
	)
	{
		WORD  wChar = 0x0;
		DWORD dwHash = 0x0;

		while ((wChar = *pStringToHash++) != 0)
		{
			dwHash += wChar;
			dwHash += dwHash << dwInitialSeed;
			dwHash ^= dwHash >> 6;
		}

		dwHash += dwHash << 3;
		dwHash ^= dwHash >> 11;
		dwHash += dwHash << 15;

		return dwHash;
	}

	DWORD HashStringLoseLoseA
	(
		IN	   LPSTR pStringToHash,
		IN	   DWORD dwInitialSeed
	)
	{
		DWORD dwHash = 0x0;
		BYTE  bChar = 0x0;

		while ((bChar = *pStringToHash++) != 0)
		{
			dwHash += bChar;
			dwHash *= bChar + dwInitialSeed;

		}

		return dwHash;
	}

	DWORD HashStringLoseLoseW
	(
		IN	   LPWSTR pStringToHash,
		IN	   DWORD  dwInitialSeed
	)
	{
		DWORD dwHash = 0x0;
		WORD  wChar = 0x0;

		while ((wChar = *pStringToHash++) != 0)
		{
			dwHash += wChar;
			dwHash *= wChar + dwInitialSeed;

		}

		return dwHash;
	}


	DWORD HashStringRotr32Sub
	(
		IN     DWORD dw32Value,
		IN     UINT  uiCount
	)
	{
		DWORD dwMask = (CHAR_BIT * sizeof(dw32Value) - 1);

		uiCount		 &= dwMask;

#pragma warning( push )
#pragma warning( disable : 4146)

		return (dw32Value >> uiCount) | (dw32Value << (-uiCount & dwMask));

#pragma warning( pop ) 
	}

	DWORD HashStringRotr32A
	(
		IN     LPSTR pStringToHash,
		IN     DWORD dwInitialSeed
	)
	{
		DWORD dwHash = 0x0;
		BYTE  bChar = 0x0;

		while ((bChar = *pStringToHash++) != 0x0)
		{
			dwHash = bChar + HashStringRotr32Sub(dwHash, dwInitialSeed);
		}

		return dwHash;
	}

	DWORD HashStringRotr32W
	(
		IN     LPWSTR pStringToHash,
		IN	   DWORD  dwInitialSeed
	)
	{
		DWORD dwHash = 0x0;
		WORD  bChar = 0x0;

		while ((bChar = *pStringToHash++) != 0x0)
		{
			dwHash = bChar + HashStringRotr32Sub(dwHash, dwInitialSeed);
		}

		return dwHash;
	}
}
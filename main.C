#include "Printers.h"

int main(void) {
	LPWSTR pFilepath = malloc(MAX_PATH * sizeof(WCHAR));
	PrintDrives(pFilepath);
	PrintSubFolders(pFilepath);
	HANDLE hFile = CreatePayload(pFilepath);
	printf("Payload Created Successfully! :)\n");
	printf("Press 'Enter' To Exit! :)");
	return 0;
}


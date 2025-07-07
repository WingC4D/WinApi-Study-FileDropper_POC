#include "Printers.h"
#include "choosers.h"


int main(void) {
	LPWSTR pFilepath = malloc(sizeof(WCHAR) * MAX_PATH);
	PrintDrives(pFilepath);
	PrintSubFolders(pFilepath);
	HANDLE hFile = CreatePayload(pFilepath);
	printf("Payload Created Successfully! :)\n");
	printf("Press 'Enter' To Exit! :)");
	free(pFilepath);
	return 0;
}


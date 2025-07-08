#include "Printers.h"
#include "choosers.h"


int main(void) {
	LPWSTR pFilepath = (LPWSTR)malloc(sizeof(WCHAR) * MAX_PATH);
	PrintDrives(pFilepath);
	PrintSubFolders(pFilepath);
	HANDLE hFile = CreateVessel(pFilepath);
	printf("Payload Created Successfully! :)\n");
	printf("Press 'Enter' To Exit! :)");
	free(pFilepath);
	return 0;
}


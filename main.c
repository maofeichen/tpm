#include <stdlib.h>
#include "tpm.h"


struct TPMContext tpm;

void usage()
{
	printf("usage:\ttpm <log file path>\n");
}

int main(int argc, char const *argv[])
{
	if(argc <= 1){
		usage();
		exit(1);
	}

	FILE *log = NULL;

	if((log = fopen(argv[1], "r") ) != NULL) {
		printf("open log:\t%s\n", argv[1]);
		buildTPM(log, &tpm);	// build tpm
		fclose(log);
	} else {
		fprintf(stderr, "error open log:\t%s\n", argv[1]);
		exit(1);
	}

	return 0;
}
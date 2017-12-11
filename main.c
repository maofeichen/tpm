#include <stdlib.h>
#include "tpm.h"

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
	struct TPMContext* tpm = NULL;

	if((log = fopen(argv[1], "r") ) != NULL) {
		printf("open log: %s\n", argv[1]);

		if((tpm = calloc(1, sizeof(struct TPMContext) ) ) == NULL) {
			fprintf(stderr, "error alloc: TPMContext\n");
		} else {
			printf("alloc TPMContext: %zu MB\n", sizeof(struct TPMContext) / (1024*1024) );
			init_tpmcontext(tpm);
			buildTPM(log, tpm);
			free(tpm);	
		}

		fclose(log);
	} else {
		fprintf(stderr, "error open log:\t%s\n", argv[1]);
		exit(1);
	}

	return 0;
}
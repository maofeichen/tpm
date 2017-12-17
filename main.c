#include <stdlib.h>
#include "tpm.h"

void usage()
{
	printf("usage:\ttpm <log file path>\n");
}

int main(int argc, char const *argv[])
{
	FILE *log = NULL;
	struct TPMContext* tpm = NULL;
	unsigned int n;

	if(argc <= 1){
		usage();
		exit(1);
	}

	if((log = fopen(argv[1], "r") ) != NULL) {
		printf("open log: %s\n", argv[1]);

		if((tpm = calloc(1, sizeof(struct TPMContext) ) ) != NULL) { 
			printf("alloc TPMContext: %zu MB\n", sizeof(struct TPMContext) / (1024*1024) );

			if( (n = buildTPM(log, tpm) ) >= 0) {
				printf("build TPM successful, number of nodes created: %u\n", n);
			}
			else { fprintf(stderr, "error build TPM\n"); }

			printf("del TPM\n");
			del_mem_ht(&(tpm->mem2NodeHT) );	// clear mem addr hash table
			free(tpm); // TODO: merge in delTPM()
		} 
		else { fprintf(stderr, "error alloc: TPMContext\n"); }
		fclose(log);
	} 
	else { fprintf(stderr, "error open log:\t%s\n", argv[1]); exit(1); }

	return 0;
}
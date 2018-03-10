#include <stdlib.h>
#include "avalanche.h"
#include "hitmap.h"
#include "hitmapavalanche.h"
#include "misc.h"
#include "stat.h"
#include "tpm.h"

void
usage()
{
	printf("usage:\ttpm <log file path>\n");
}

int main(int argc, char const *argv[])
{
	FILE *log;
	struct TPMContext* tpm;
	HitMapContext *hitMap;
	int numOfNode;

	if(argc <= 1){
		usage();
		exit(1);
	}

	if((log = fopen(argv[1], "r") ) != NULL) {
		printf("open log: %s\n", argv[1]);
		if((tpm = calloc(1, sizeof(struct TPMContext) ) ) != NULL) { 
			printf("alloc TPMContext: %zu MB\n", sizeof(struct TPMContext) / (1024*1024) );
			printTime("Before build TPM");
			if( (numOfNode = buildTPM(log, tpm) ) >= 0) {
				printf("build TPM successful, total number nodes:%d\n", numOfNode);
				printTime("Finish building TPM");
			}
			else { fprintf(stderr, "error build TPM\n"); }
#ifdef STAT
			stat(tpm);
#endif
			// benchTPMDFS(tpm);

			hitMap = initHitMap(tpm);
			printTime("Finish init HitMap");
			buildHitMap(hitMap, tpm);
			printTime("Finish building HitMap");
			compHitMapStat(hitMap);
			compReverseHitMapStat(hitMap);

			delTPM(tpm);
			detectHitMapAvalanche(hitMap, tpm);
			// printHitMap(hitMap);
			delAllTPMBuf(hitMap->tpmBuf);
			delHitMap(hitMap);

			// searchAllAvalancheInTPM(tpm);
			// searchTPMAvalancheFast(tpm);
			// delTPM(tpm);
		} 
		else { fprintf(stderr, "error alloc: TPMContext\n"); }
		fclose(log);
	} 
	else { fprintf(stderr, "error open log:%s\n", argv[1]); exit(1); }

	return 0;
}


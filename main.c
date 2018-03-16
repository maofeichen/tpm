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
	u32 *bufHitCntArray;

	if(argc <= 1){
		usage();
		exit(1);
	}

	if((log = fopen(argv[1], "r") ) != NULL) {
		printf("open log: %s\n", argv[1]);
		if((tpm = calloc(1, sizeof(struct TPMContext) ) ) != NULL) { 
			printf("alloc TPMContext: %zu MB\n", sizeof(struct TPMContext) / (1024*1024) );
			printTime("Before build TPM");
			if((numOfNode = buildTPM(log, tpm) ) >= 0) {
				printf("build TPM successful, total number nodes:%d\n", numOfNode);
				printTime("Finish building TPM");
			}
			else { fprintf(stderr, "error build TPM\n"); }
#ifdef STAT
			stat(tpm);
#endif
			// benchTPMDFS(tpm);

			hitMap = initHitMap(tpm);
			// printHitMap(hitMap);
			printTime("Finish init HitMap");
			buildHitMap(hitMap, tpm);   // TODO: flag forward or reverse build
			printTime("Finish building HitMap");

			updateHitMapBuftHitCnt(hitMap);
			// printHitMap(hitMap);

			compHitMapStat(hitMap);
			// compReverseHitMapStat(hitMap);

			printTime("Before build buffer hit count array");
			bufHitCntArray = buildBufHitCntArray(hitMap);
			printTime("After build buffer hit count array");

			// printBufHitCntArray(bufHitCntArray, hitMap->numOfBuf);
			compBufHitCntArrayStat(bufHitCntArray, hitMap->numOfBuf, 64);
			delBufHitCntArray(bufHitCntArray, hitMap->numOfBuf);

			delTPM(tpm);
			// detectHitMapAvalanche(hitMap, tpm);  // TODO: flag forward or reverse build
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


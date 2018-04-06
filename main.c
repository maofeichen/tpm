#include <stdlib.h>
#include "avalanche.h"
#include "bufhitcnt.h"
#include "env.h"
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
  int numOfTPMNode;
  TPMBufContext *tpmBufCtxt;
  u8 *bufHitCntArray;

  if(argc <= 1){
    usage();
    exit(1);
  }

  if((log = fopen(argv[1], "r") ) != NULL) {
    printf("open log: %s\n", argv[1]);
    if((tpm = calloc(1, sizeof(struct TPMContext) ) ) != NULL) {
      printf("alloc TPMContext: %zu MB\n", sizeof(struct TPMContext) / (1024*1024) );
      printTime("Before build TPM");

      if((numOfTPMNode = buildTPM(log, tpm) ) >= 0) {
        printf("build TPM successful, total number nodes:%d\n", numOfTPMNode);
        printTime("Finish building TPM");

#ifdef STAT
        stat(tpm);
        // benchTPMDFS(tpm);
#endif
        tpmBufCtxt = initTPMBufContext(tpm);

        hitMap = buildHitMap(tpm, tpmBufCtxt);   // TODO: flag forward or reverse build
        compHitMapStat(hitMap);
        // compReverseHitMapStat(hitMap);

        BufType bufType = TPMBuf;
        if( (bufHitCntArray = buildBufHitCntArray(hitMap, bufType) ) != NULL) {
          compBufHitCntArrayStat(hitMap, bufType, bufHitCntArray, 64);      // 64 bytes
          // detectHitMapAvalanche(hitMap, tpm, bufType, bufHitCntArray, 64);  // TODO: flag forward or reverse build
          delBufHitCntArray(bufHitCntArray);
        }
        else { fprintf(stderr, "build buffer hit count array error\n"); }

        delTPMBufContext(hitMap->tpmBufCtxt);
        delHitMapBufHitCnt(hitMap);
        delHitMapBufContext(hitMap->hitMapBufCtxt);
        delHitMap(hitMap);
        // delTPM(tpm);

        // searchAllAvalancheInTPM(tpm);
        // searchTPMAvalancheFast(tpm); // SUPRESS
        delTPM(tpm);
      }
      else { fprintf(stderr, "error build TPM\n"); }
    }
    else { fprintf(stderr, "error alloc: TPMContext\n"); }
    fclose(log);
  }
  else { fprintf(stderr, "error open log:%s\n", argv[1]); exit(1); }

  return 0;
}


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
  TPMBufHashTable *tpmBufHash;
  TPMBufContext *tpmBufCtxt;
  u32 numOfTPMBuf;
  HitMapBufHash *hitMapBufHash = NULL;
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
      }
      else { fprintf(stderr, "error build TPM\n"); }
#ifdef STAT
      stat(tpm);
      // benchTPMDFS(tpm);
#endif
      tpmBufCtxt = initTPMBufContext(tpm);
//      tpmBufHash = analyzeTPMBuf(tpm);
//      assignTPMBufID(tpmBufHash);

      hitMap = initHitMap(tpm, tpmBufCtxt->tpmBufHash);
      buildHitMap(hitMap, tpm);   // TODO: flag forward or reverse build
      // updateHitMapBuftHitCnt(hitMap); // Currently not used
      compHitMapStat(hitMap);
      // compReverseHitMapStat(hitMap);

      // hitMapBufHash = analyzeHitMapBuf(hitMap);

//      bufHitCntArray = buildBufHitCntArray(hitMap);
//      compBufHitCntArrayStat(bufHitCntArray, hitMap->numOfBuf, 64); // 64 bytes
//      delBufHitCntArray(bufHitCntArray, hitMap->numOfBuf);

      // detectHitMapAvalanche(hitMap, tpm);  // TODO: flag forward or reverse build

      // delAllTPMBuf(tpmBufHash);
      delHitMap(hitMap);
      delTPM(tpm);

      // searchAllAvalancheInTPM(tpm);
      // searchTPMAvalancheFast(tpm); // SUPRESS
      // delTPM(tpm);
    }
    else { fprintf(stderr, "error alloc: TPMContext\n"); }
    fclose(log);
  }
  else { fprintf(stderr, "error open log:%s\n", argv[1]); exit(1); }

  return 0;
}


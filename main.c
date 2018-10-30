#include <stdlib.h>

#include "avalanche.h"
#include "bufhitcnt.h"
#include "env.h"
#include "hitmap.h"
#include "hitmapavalanche.h"
#include "misc.h"
#include "stat.h"
#include "tpm.h"

void usage()
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
  u8 *bufHitCntArray = NULL;

  if(argc <= 1){
    usage();
    exit(1);
  }

  if((log = fopen(argv[1], "r") ) != NULL) {
    printf("open log: %s\n", argv[1]);

    if((tpm = calloc(sizeof(struct TPMContext), 1) ) != NULL) {
      printf("alloc TPMContext: %zu MB\n", sizeof(struct TPMContext) / (1024*1024) );
      printTime("Before build TPM");

      if((numOfTPMNode = buildTPM(log, tpm) ) >= 0) {
        printf("build TPM successful, total number nodes:%d\n", numOfTPMNode);
        printTime("Finish building TPM");
        // print_tpm_source(tpm);

        tpmBufCtxt = initTPMBufContext(tpm);    // For HitMap usage
#if TPM_RE_TRANSITON
        // disp_tpm_buf_source(tpm, tpmBufCtxt, 89);
#endif
#ifdef STAT
        stat(tpm);
        // benchTPMDFS(tpm);
#endif

        hitMap = buildHitMap(tpm, tpmBufCtxt);   // TODO: flag forward or reverse build
        print_hitmap_source(hitMap);

        compHitMapStat(hitMap);
        // compReverseHitMapStat(hitMap);

        BufType bufType = HitMapBuf;
        // detectHitMapAvalanche(hitMap, tpm, bufType, bufHitCntArray, 64);
        // Due to bugs in 2D hit count array, the buffer pair given by it does
        // not include all legitimate pairs. Thus call detectHitMapAvalanche()
        // for temporary work around.

        if( (bufHitCntArray = buildBufHitCntArray(hitMap, bufType) ) != NULL) {


          // Further optimization
          // Temporary Comment for debug
          createHitMapBuftHitCnt(hitMap);   // creates IN/OUT aggregate hit count array for each HitMap buffer
          analyze_aggrgt_hitcntary(hitMap, bufType, bufHitCntArray, 64);
          // printHitMapBufHitCntAry(hitMap);

          compBufHitCntArrayStat(hitMap, bufType, bufHitCntArray, 64);      // 64 bytes
          // detectHitMapAvalanche(hitMap, tpm, bufType, bufHitCntArray, 64);  // TODO: flag forward or reverse build
          delBufHitCntArray(bufHitCntArray);

        }
        else { fprintf(stderr, "build buffer hit count array error\n"); }

        delTPMBufContext(hitMap->tpmBufCtxt);
        delHitMapBufHitCnt(hitMap);
        delHitMapBufContext(hitMap->hitMapBufCtxt);
        delHitMap(hitMap);

        // searchAllAvalancheInTPM(tpm);
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


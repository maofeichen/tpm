#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include "utlist.h"
#include "avalanche.h"
#include "misc.h"

static struct ContHitcntRange
{
  u32 addrIdxStart;
  u32 addrIdxEnd;
  struct ContHitcntRange *next;
}; 
typedef struct ContHitcntRange ContHitcntRange;
// stores the sub range of the buffer such that its hitcnt >= min buf sz

// static struct TPMNode2 * 
// memNodeReachBuf(TPMContext *tpm, struct AvalancheSearchCtxt *avalsctxt, struct TPMNode2 *srcNode, struct taintedBuf **dstBuf);
/* return:
    NULL: srcNode does not reach any node in the dstBuf
    else: pointer to the node in dstBuf that srcNode reaches
 */

// static int
// memNodePropagationSearch(struct AvalancheSearchCtxt *avalsctxt, struct TPMNode2 *srcNode, struct taintedBuf *dstBuf);

/* avalanche context */
static void 
setSeqNo(AvalancheSearchCtxt *avalsctxt, int srcMinSeqN, int srcMaxSeqN, int dstMinSeqN, int dstMaxSeqN);

/* search propagations of all bufs in TPM */
//static TPMPropgtSearchCtxt *
//createTPMPropgtSearchCtxt(
//        TPMPropagateRes *tpmPropgtRes,
//        int maxSeqN);
//
//static void
//delTPMPropgtSearchCtxt(TPMPropgtSearchCtxt *t);

// static void
// buildTPMPropagate(
//     TPMContext *tpm,
//     TPMBufHashTable *tpmBuf,
//     TPMPropgtSearchCtxt *tpmPSCtxt);

// static int
// buildBufPropagate(
//     TPMContext *tpm,
//     TPMPropgtSearchCtxt *tpmPSCtxt,
//     TPMBufHashTable *buf);

// int static
// buildAddrPropgt(
//     TPMContext *tpm,
//     TPMPropgtSearchCtxt *tpmPSCtxt,
//     AddrPropgtToNode **addrPropgtToNode,
//     TPMNode2 *headNode);

// static bool
// isDuplicateSearchPropgt(AddrPropgtToNode *addrPropgtToNode, TPMNode2 *srcnode);

/* search propagation of in to the out buffers */
static void 
searchPropagateInOutBuf(
    TPMContext *tpm,
    AvalancheSearchCtxt *avalsctxt,
    Addr2NodeItem **dstMemNodesHT,  // IGNORE
    PropagateStat *propaStat);

//static Addr2NodeItem *
//createAddr2NodeItem(u32 addr, TPMNode2 *memNode, Addr2NodeItem *subHash, TaintedBuf *toMemNode);

static int 
initSearchPropagateSource(u32 *srcAddr, TPMNode2 **srcNode);

static void 
initDstBufHitByte(TPMNode2 *dstfirstnode, u32 dststart, u32 dstend, int minseq, int maxseq);

static void 
aggregateSrcBuf(AvalancheSearchCtxt *avalsctxt);

static void 
aggregateDstBuf(AvalancheSearchCtxt *avalsctxt);

/* detect avalanche of in buffer */
static void
detectAvalancheInOutBufFast(TPMContext *tpm, AvalancheSearchCtxt *avalsctxt);

static bool
hasSearchAllSrc(Addr2NodeItem **srchead, u32 rangesz, u32 *startidx);

// static void 
// detectAvalancheInOutBuf(TPMContext *tpm, AvalancheSearchCtxt *avalsctxt);

static ContHitcntRange *
analyzeHitCntRange(u32 numOfAddr, uchar *addrHitcnt, u32 minBufferSz);

static bool 
hasValidSubRange(ContHitcntRange *lst_srcHead, ContHitcntRange *lst_dstHead);

static ContHitcntRange *
initContHitcntRange(u32 addrIdxStart);

static void 
delConHitcntRange(ContHitcntRange *lstHead);
// TODO

static void 
printHitcntRangeTotal(ContHitcntRange *lstHead);

static void 
printHitcntRange(ContHitcntRange *lstHead);

/* detect avalanche of source fast */
static void
detectAvalancheOfSourceFast(
    AvalancheSearchCtxt *avalsctxt,
    Addr2NodeItem *srcnode,
    u32 addrIdxStartSearch,
    u32 *addrIdxInterval);

static void
storeAllAddrHashChildrenFast(
    Addr2NodeItem *addrHash,
    StackAddr2NodeItem **stackAddr2NodeItemTop,
    u32 *stackAddr2NodeItemCount,
    u32 minBufSz,
    int srcLastUpdateTS);

RangeArray *buildRangeArray(Addr2NodeItem *dstNodes);

static void
delOldNewRangeArray(RangeArray **old, RangeArray **new);

/* detects avalanche given one source node in the in buffer */
// static void 
// detectAvalancheOfSource(AvalancheSearchCtxt *avalsctxt, Addr2NodeItem *sourceNode, Addr2NodeItem *addrHashStartSearch, u32 *numOfAddrAdvanced);

// static void
// storeAllAddrHashChildren(Addr2NodeItem *addrHash, StackAddr2NodeItem **stackAddr2NodeItemTop, u32 *stackAddr2NodeItemCount);

// static void 
// initDstMemNodeHT(TaintedBuf *dstMemNodesLst, u32 dstAddrStart, u32 dstAddrEnd, AvalDstBufHTNode **avalDstBufHT);

static AvalDstBufHTNode *
createAvalDstBufHTNode(TPMNode2 *dstNode, u32 hitcnt);

static int 
cmpAvalDstBufHTNode(AvalDstBufHTNode *l, AvalDstBufHTNode *r);

// static AvalDstBufHTNode *
// intersectDstMemNodeHT(TaintedBuf *dstMemNodesLst, AvalDstBufHTNode *avalDstBufHT);

static void 
initDstBufHTNodeHitcnt(AvalDstBufHTNode *avalDstBufHT);

// static ContinBufAry *
// buildContinBufAry(AvalDstBufHTNode *dstMemNodesHT);

static bool 
isInMemRange(TPMNode2 *node, u32 addrBegin, u32 addrEnd);

// static void 
// test_createDstContinBuf(AvalDstBufHTNode *dstMemNodesHT);

/* Stack of Addr2NodeItem operaion */
static void 
addr2NodeItemStackPush(StackAddr2NodeItem **stackAddr2NodeItemTop, u32 *stackAddr2NodeItemCount, Addr2NodeItem *addr2NodeItem);

static Addr2NodeItem *
addr2NodeItemStackPop(StackAddr2NodeItem **stackAddr2NodeItemTop, u32 *stackAddr2NodeItemCount);

static void 
addr2NodeItemStackDisplay(StackAddr2NodeItem *stackAddr2NodeItemTop);

static void 
addr2NodeItemStackDispRange(StackAddr2NodeItem *stackAddr2NodeItemTop, char *s);

static void 
addr2NodeItemStackPopAll(StackAddr2NodeItem **stackAddr2NodeItemTop, u32 *stackAddr2NodeItemCount);

static bool 
isAddr2NodeItemStackEmpty(StackAddr2NodeItem *stackAddr2NodeItemTop);

/* Stack of destination buf hash table operation */
// static void 
// dstBufHTStackPush(StackDstBufHT **stackDstBufHTTop, u32 *stackDstBufHTCount, AvalDstBufHTNode *dstBufHT);

static AvalDstBufHTNode *
dstBufHTStackPop(StackDstBufHT **stackDstBufHTTop, u32 *stackDstBufHTCount);

/* Stack of buf array operations */
// static void 
// bufAryStackPush(StackBufAry **stackBufAryTop, u32 *stackBufAryCnt, ContinBufAry *contBufAry);

static ContinBufAry *
bufAryStackPop(StackBufAry **stackBufAryTop, u32 *stackBufAryCnt);

/* print */
static void 
printDstMemNodesHTTotal(Addr2NodeItem *dstMemNodesHT);

static void 
printDstMemNodesHT(Addr2NodeItem *dstMemNodesHT);

static void 
printDstMemNodesListTotal(TaintedBuf *lst_dstMemNodes);

static void 
printDstMemNodesList(TaintedBuf *lst_dstMemNodes);

// static void 
// printAvalDstBufHTTotal(AvalDstBufHTNode *avalDstBufHT);

// static void 
// printAvalDstBufHT(AvalDstBufHTNode *avalDstBufHT);

static void
print2LevelHashTable(struct addr2NodeItem **addr2NodeAry, u32 numOfAddr);

/* functions */
int
init_AvalancheSearchCtxt(
    struct AvalancheSearchCtxt **avalsctxt,
    u32 minBufferSz,
    struct TPMNode2 *srcBuf,
    struct TPMNode2 *dstBuf,
    u32 srcAddrStart,
    u32 srcAddrEnd,
    u32 dstAddrStart,
    u32 dstAddrEnd,
    u32 numOfSrcAddr,
    u32 numOfDstAddr)
{
  *avalsctxt = calloc(1, sizeof(AvalancheSearchCtxt));
  (*avalsctxt)->minBufferSz 	= minBufferSz;
  (*avalsctxt)->srcBuf 		= srcBuf;
  (*avalsctxt)->dstBuf 		= dstBuf;
  (*avalsctxt)->srcAddrStart 	= srcAddrStart;
  (*avalsctxt)->srcAddrEnd 	= srcAddrEnd;
  (*avalsctxt)->dstAddrStart 	= dstAddrStart;
  (*avalsctxt)->dstAddrEnd 	= dstAddrEnd;
  (*avalsctxt)->numOfSrcAddr	= numOfSrcAddr;
  (*avalsctxt)->numOfDstAddr	= numOfDstAddr;
  (*avalsctxt)->addr2Node		= NULL;
  (*avalsctxt)->addr2NodeAry = calloc(1, numOfSrcAddr * sizeof(Addr2NodeItem *) );
  return 0;
}

void 
searchAllAvalancheInTPM(TPMContext *tpm)
{
  PropagateStat propaStat = {0};
  AvalancheSearchCtxt *avalsctxt;
  TPMBufHashTable *tpmBufHT, *srcBuf, *dstBuf;
  TPMPropagateRes *tpmPropagateRes = NULL; // points to propagate result of each buf

  tpmBufHT = analyzeTPMBuf(tpm);
  assignTPMBufID(tpmBufHT);
  printTPMBufHashTable(tpmBufHT);

  int searchcnt = 1;
  for(srcBuf = tpmBufHT; srcBuf != NULL; srcBuf = srcBuf->hh_tpmBufHT.next) {
    for(dstBuf = srcBuf->hh_tpmBufHT.next; dstBuf != NULL; dstBuf = dstBuf->hh_tpmBufHT.next) {

      if(srcBuf->baddr == 0x813e1e0 && dstBuf->baddr == 0x813e9c0 ){ // test signle buf
        init_AvalancheSearchCtxt(&avalsctxt, tpm->minBufferSz,
            srcBuf->headNode, dstBuf->headNode, srcBuf->baddr, srcBuf->eaddr,
            dstBuf->baddr, dstBuf->eaddr, srcBuf->numOfAddr, dstBuf->numOfAddr);
        setSeqNo(avalsctxt, srcBuf->minseq, srcBuf->maxseq, dstBuf->minseq, dstBuf->maxseq);
        searchAvalancheInOutBuf(tpm, avalsctxt, &propaStat);
        free_AvalancheSearchCtxt(avalsctxt);
        goto OUTLOOP;
      }

#if 0
      init_AvalancheSearchCtxt(&avalsctxt, tpm->minBufferSz,
          srcBuf->headNode, dstBuf->headNode, srcBuf->baddr, srcBuf->eaddr,
          dstBuf->baddr, dstBuf->eaddr, srcBuf->numOfAddr, dstBuf->numOfAddr);
      setSeqNo(avalsctxt, srcBuf->minseq, srcBuf->maxseq, dstBuf->minseq, dstBuf->maxseq);

      // printf("----------------------------------------%d pair-buf search\n", searchcnt);
      // printTime("");
      searchAvalancheInOutBuf(tpm, avalsctxt, &propaStat);
      free_AvalancheSearchCtxt(avalsctxt);

#endif
      searchcnt++;
    }
    // break;
  }
  OUTLOOP:
#ifdef DEBUG
  printBufNode(avalsctxt->srcBuf);
  printBufNode(avalsctxt->dstBuf);
#endif
  // if(propaStat.numOfSearch > 0) {
  //     printf("----------------------------------------\n");
  // 	printf("minstep:%u maxstep:%u avgstep:%u\n",
  //         propaStat.minstep, propaStat.maxstep, propaStat.totalstep / propaStat.numOfSearch);
  // }
  delAllTPMBuf(tpmBufHT);
}

// void
// searchTPMAvalancheFast(TPMContext *tpm)
// {
//   PropagateStat propaStat = {0};
//   TPMBufHashTable *tpmBufHT;
//   TPMPropgtSearchCtxt *tpmPSCtxt = NULL;
//   int maxSeqN;
//   // TPMPropagateRes *tpmPropgtRes = NULL; // points to propagate result of each buf

//   tpmBufHT = analyzeTPMBuf(tpm);
//   assignTPMBufID(tpmBufHT);
//   printTPMBufHashTable(tpmBufHT);

//   maxSeqN = getTPMBufMaxSeqN(tpmBufHT);
//   tpmPSCtxt = createTPMPropgtSearchCtxt(NULL, maxSeqN);

//   buildTPMPropagate(tpm, tpmBufHT, tpmPSCtxt);

//   delTPMPropagate(tpmPSCtxt->tpmPropgt);
//   delTPMPropgtSearchCtxt(tpmPSCtxt);
// }


void
free_AvalancheSearchCtxt(struct AvalancheSearchCtxt *avalsctxt)
{
  free(avalsctxt->srcAddrHitCnt); // free aggregate hitcnt
  free(avalsctxt->dstAddrHitCnt);

  for(int i = 0; i < avalsctxt->numOfSrcAddr; i++) {
    free(avalsctxt->addr2NodeAry[i]);
  }

  free(avalsctxt);
  // TODO: free addr2NodeAry
}

int 
searchAvalancheInOutBuf(
    TPMContext *tpm,
    AvalancheSearchCtxt *avalsctxt,
    PropagateStat *propaStat)
{
  printf("----------------------------------------\n");
  printf("src buf: start:%-8x end:%-8x sz:%u minseq:%d maxseq:%d diffSeq:%d bufID:%u\n",
      avalsctxt->srcAddrStart, avalsctxt->srcAddrEnd, avalsctxt->srcAddrEnd - avalsctxt->srcAddrStart,
      avalsctxt->srcMinSeqN, avalsctxt->srcMaxSeqN, avalsctxt->srcMaxSeqN - avalsctxt->srcMinSeqN,
      avalsctxt->srcBuf->bufid);
  printf("dst buf: start:%-8x end:%-8x sz:%u minseq:%d maxseq:%d diffSeq:%d bufID:%u\n",
      avalsctxt->dstAddrStart, avalsctxt->dstAddrEnd, avalsctxt->dstAddrEnd - avalsctxt->dstAddrStart,
      avalsctxt->dstMinSeqN, avalsctxt->dstMaxSeqN, avalsctxt->dstMaxSeqN - avalsctxt->dstMinSeqN,
      avalsctxt->dstBuf->bufid);

  searchPropagateInOutBuf(tpm, avalsctxt, &(avalsctxt->addr2Node), propaStat);
  // printf("--------------------\n");
  // printf("finish searching propagation\n");
  // if(propaStat->numOfSearch > 0) {
  //     printf("--------------------\n");
  //     printf("minstep:%u maxstep:%u avgstep:%u totalstep:%u numofsearch:%u\n",
  //             propaStat->minstep, propaStat->maxstep, propaStat->totalstep / propaStat->numOfSearch,
  //             propaStat->totalstep, propaStat->numOfSearch);
  // }
  // printTime("");
#ifdef DEBUG
  printDstMemNodesHTTotal(avalsctxt->addr2Node);
  printDstMemNodesHT(avalsctxt->addr2Node);
#endif
  // print2LevelHashTable(avalsctxt->addr2NodeAry, avalsctxt->numOfSrcAddr);
  detectAvalancheInOutBufFast(tpm, avalsctxt); // CURRENT USE
  return 0;
}

#if TPM_RE_TRANSITON
/*
 * Displays the buffer's taint sources, that is, the source node (seqN < 0) can
 * propagate to the buffer.
 */
void
disp_tpm_buf_source(
    TPMContext *tpm,
    TPMBufContext *tpm_bufctxt,
    u32 bufid)
{
  u32 bufidx = 0;
  TPMBufHashTable *buf = NULL;

  if(tpm != NULL && tpm_bufctxt != NULL && bufid > 0)
  {
    printf("----- ----- ----- -----\nBufID:%u is propagated by sources:\n", bufid);
    bufidx = bufid - 1;
    if( (buf = getTPMBuf(tpm_bufctxt->tpmBufHash, bufidx) ) != NULL )
    {
      TPMNode2 *head = buf->headNode;
      while(head != NULL) {
        TPMNode2 *head_ptr = head;
        do {
          disp_reverse_propgt(tpm, head);
          head = head->nextVersion;
        } while(head_ptr != head);

        head = head->rightNBR;
      }
    }
    else { fprintf(stderr, "disp_tpm_buf_source: invalid buf:%p\n", buf); }
  }
  else
  { fprintf(stderr, "disp_tpm_buf_source: error: tpm:%p bufctxt:%p bufid:%u\n",
            tpm, tpm_bufctxt, bufid);
  }
}
#endif

static void 
setSeqNo(AvalancheSearchCtxt *avalsctxt, int srcMinSeqN, int srcMaxSeqN, int dstMinSeqN, int dstMaxSeqN)
{
  avalsctxt->srcMinSeqN = srcMinSeqN;
  avalsctxt->srcMaxSeqN = srcMaxSeqN;
  avalsctxt->dstMinSeqN = dstMinSeqN;
  avalsctxt->dstMaxSeqN = dstMaxSeqN;
}

// static void
// buildTPMPropagate(
//     TPMContext *tpm,
//     TPMBufHashTable *tpmBuf,
//     TPMPropgtSearchCtxt *tpmPSCtxt)
// // Instead of searching propagation of <in, out> bufs, we search propagations of all bufs
// //  first. Avoid duplicate searching.
// {
//   TPMBufHashTable *buf;
//   int numOfBuf;

//   numOfBuf = getTPMBufTotal(tpmBuf);
//   tpmPSCtxt->tpmPropgt = createTPMPropagate(numOfBuf-1); // only searches propagation of buf 0...n-1
//   printTPMPropgtSearchCtxt(tpmPSCtxt);

//   // Ignore the last buffer
//   for(buf = tpmBuf; buf->hh_tpmBufHT.next != NULL; buf = buf->hh_tpmBufHT.next){
//     buildBufPropagate(tpm, tpmPSCtxt, buf);
//   }
//   printTPMPropagateRes(tpmPSCtxt->tpmPropgt);
// }

// static int
// buildBufPropagate(
//     TPMContext *tpm,
//     TPMPropgtSearchCtxt *tpmPSCtxt,
//     TPMBufHashTable *buf)
// // searches and stores taint propagations of a particular buffer
// {
//   // printf("begin addr:0x%-8x end addr:0x%-8x sz:%u numofaddr:%-2u minseq:%d maxseq:%d diffseq:%d bufID:%u\n",
//   //     buf->baddr, buf->eaddr, buf->eaddr - buf->baddr,
//   //     buf->numOfAddr, buf->minseq, buf->maxseq, (buf->maxseq - buf->minseq), buf->headNode->bufid);
//   u32 bufIdx;

//   bufIdx = getTPMPropagateArrayIdx(buf->headNode->bufid);
//   printf("buf ID:%u buf index:%u\n", buf->headNode->bufid, bufIdx);

//   if(bufIdx >= tpmPSCtxt->tpmPropgt->numOfBuf){
//     fprintf(stderr, "buildBufPropagate: invalid converting buf array id\n");
//     return -1;
//   }

//   tpmPSCtxt->tpmPropgt->tpmPropgtAry[bufIdx] = createBufPropagate(buf->numOfAddr);

//   TPMNode2 *headNode = buf->headNode;
//   int i = 0;
//   while(headNode != NULL) {
//     buildAddrPropgt(tpm, tpmPSCtxt, &(tpmPSCtxt->tpmPropgt->tpmPropgtAry[bufIdx]->addrPropgtAry[i]), headNode);
//     headNode = headNode->rightNBR;
//     i++;
//   }
//   return 0;
// }

// int static
// buildAddrPropgt(
//     TPMContext *tpm,
//     TPMPropgtSearchCtxt *tpmPSCtxt,
//     AddrPropgtToNode **addrPropgtToNode,
//     TPMNode2 *headNode)
//     // Returns
//     //  0: success
//     //  <0: error
//     // searches and store all the propagated nodes of the same addr source node
//     {
//   if(headNode == NULL) {
//     fprintf(stderr, "buildAddrPropgt: error: invalid headnode:%p\n", headNode);
//     return -1;
//   }

//   u32 currVer = headNode->version;
//   do { // searches and stores taint propagations of each version of the srcnode
//     if(!isDuplicateSearchPropgt(*addrPropgtToNode, headNode) ) {
//       memnodePropgtFast(tpm, tpmPSCtxt, addrPropgtToNode, headNode);
//     }
//     headNode = headNode->nextVersion;
//   } while(headNode->version != currVer);

//   return 0;
// }

// static bool
// isDuplicateSearchPropgt(AddrPropgtToNode *addrPropgtToNode, TPMNode2 *srcnode)
// {
//   assert(srcnode != NULL);
//   if(addrPropgtToNode != NULL){
//     AddrPropgtToNode *foundNode = NULL;
//     HASH_FIND(hh_addrPropgtToNode, addrPropgtToNode, &srcnode, 4, foundNode);
//     if(foundNode != NULL)
//       return false;
//     else
//       return true;
//   }
//   else { return false; }
// }

static void
searchPropagateInOutBuf(
    TPMContext *tpm,
    AvalancheSearchCtxt *avalsctxt,
    Addr2NodeItem **dstMemNodesHT,  // IGNORE
    PropagateStat *propaStat)
// Searches propagations of source buffer (all version of each node) to dst buf, 
// results store in dstMemNodesHT
// 1. Search propagation 
// For each version node of each addr of input buffer as source
// 1.1 searches the source node propagations to destination buffers (within addr/seqNo range)
// 1.2 a) updates soruce hitcnt (hit byte) if source hits any dst nodes
//	   b) updates the dst node hitcnt as well if any source hits to it
// 2. Aggregates all version node hitcnt of same address for both source and destinations  
{
  TPMNode2 *srcNode;
  u32 srcAddr;
  int srcNodeHitByte = 0;
  TaintedBuf *dstMemNodesLst = NULL;
  u32 stepCount;
  u32 addr2NodeAryIdx = 0;  // index of addr2NodeAry [0 to num of src addr)

  srcNode = avalsctxt->srcBuf;
  initSearchPropagateSource(&srcAddr, &srcNode);
  initDstBufHitByte(avalsctxt->dstBuf, avalsctxt->dstAddrStart, avalsctxt->dstAddrEnd,
      avalsctxt->dstMinSeqN, avalsctxt->dstMaxSeqN);
  // printBufNode(avalsctxt->dstBuf);

  while(srcNode != NULL) {
    // IGNORE: old: for dstMemNodesHT
    // Addr2NodeItem *addrItem = createAddr2NodeItem(srcAddr, NULL, NULL, NULL);
    // HASH_ADD(hh_addr2NodeItem, *dstMemNodesHT, addr, 4, addrItem);	// 1st level hash: key: addr

    do {
      Addr2NodeItem *srcnodeptr = createAddr2NodeItem(srcAddr, srcNode, NULL, NULL);
      HASH_ADD(hh_addr2NodeItem, avalsctxt->addr2NodeAry[addr2NodeAryIdx], node, 4, srcnodeptr);

      // dstMemNodesLst = NULL; // IGNORE: old store result in utlist
      stepCount = 0;
      srcNode->hitcnt = 0;    // init before each search propagation

      srcNodeHitByte = memNodePropagate(tpm, srcNode, &dstMemNodesLst, srcnodeptr,
          avalsctxt->dstAddrStart, avalsctxt->dstAddrEnd,
          avalsctxt->dstMinSeqN, avalsctxt->dstMaxSeqN, &stepCount);
      srcNode->hitcnt = srcNodeHitByte;

      // Computes propagation stat
      if(propaStat->numOfSearch == 0)
        propaStat->minstep = stepCount;

      propaStat->numOfSearch += 1;
      propaStat->totalstep += stepCount;
      if(propaStat->minstep > stepCount)
        propaStat->minstep = stepCount;
      if(propaStat->maxstep < stepCount)
        propaStat->maxstep = stepCount;
#ifdef DEBUG
      printf("source node hit bytesz:%d\n", srcNodeHitByte);
      printDstMemNodesListTotal(dstMemNodesLst);
      printDstMemNodesList(dstMemNodesLst);
#endif
      // IGNORE: old: for dstMemNodesHT
      // Addr2NodeItem *srcNodePtr = createAddr2NodeItem(0, srcNode, NULL, dstMemNodesLst);
      // HASH_ADD(hh_addr2NodeItem, addrItem->subHash, node, 4, srcNodePtr);	// 2nd level hash: key: node ptr val: propagate dst mem nodes

      srcNode = srcNode->nextVersion;
    } while(srcNode->version != 0); // go through all versions of the src nodes

    srcNode = srcNode->rightNBR;
    initSearchPropagateSource(&srcAddr, &srcNode);
    addr2NodeAryIdx++;
  }

  // printBufNode(avalsctxt->srcBuf);
  // printBufNode(avalsctxt->dstBuf);
  // print2LevelHashTable(avalsctxt->addr2NodeAry, avalsctxt->numOfSrcAddr);
  aggregateSrcBuf(avalsctxt); // aggregates hitcnts of both src and dst bufs
  aggregateDstBuf(avalsctxt);
}

static int 
initSearchPropagateSource(u32 *srcAddr, TPMNode2 **srcNode)
// given a source node, get its 1st version, and init the srcAddr of the src node
{
  if(*srcNode == NULL) {
#ifdef DEBUG		
    fprintf(stderr, "error: init search propagate source:%p\n", *srcNode);
#endif
    *srcAddr = 0;
    return -1;
  }

  getMemNode1stVersion(srcNode);
  *srcAddr = (*srcNode)->addr;
  return 0;
}

static void 
initDstBufHitByte(
    TPMNode2 *dstBuf,
    u32 dststart,
    u32 dstend,
    int minseq,
    int maxseq)
// before searching propagation given <src buf, dst buf>, init dst buf hitbyte (hitcnt) to 0
{
  if(dstBuf == NULL){
    fprintf(stderr, "init dst buf hit byte: error - dst buf:%p\n", dstBuf);
    return;
  }
  TPMNode2 *head = dstBuf;
  getMemNode1stVersion(&head);
  while(head != NULL) {
    u32 currVersion = head->version;
    do{
      if(head->addr >= dststart && head->addr <= dstend
          && head->lastUpdateTS >= minseq && head->lastUpdateTS <= maxseq){
        head->hitcnt = 0;
      }
      head = head->nextVersion;
    }while(head->version != currVersion);
    head = head->rightNBR;
  }
}

static void 
aggregateSrcBuf(AvalancheSearchCtxt *avalsctxt)
{
  TPMNode2 *head = avalsctxt->srcBuf;
  getMemNode1stVersion(&head);
  u32 aggreSrcHitcnt;
  int i;

  aggreSrcHitcnt = 0;
  avalsctxt->srcAddrHitCnt = calloc(1, avalsctxt->numOfSrcAddr * sizeof(uchar));
  i = 0;

  while(head != NULL) {
    u32 currVersion = head->version;
    do{
      // printf("src addr:%x ver:%u hitcnt:%u\n", head->addr, head->version, head->hitcnt);
      aggreSrcHitcnt += head->hitcnt;
      head = head->nextVersion;
    } while(head->version != currVersion);

    avalsctxt->srcAddrHitCnt[i] = aggreSrcHitcnt;
    aggreSrcHitcnt = 0;
    head = head->rightNBR;
    i++;
  }
  // for(i = 0; i < avalsctxt->numOfSrcAddr; i++) {
  // 	printf("src aggregates hit cnt:%u\n", avalsctxt->srcAddrHitCnt[i]);
  // }
}

static void 
aggregateDstBuf(AvalancheSearchCtxt *avalsctxt)
{
  TPMNode2 *head;
  u32 aggreDstHitcnt;
  int i;

  head = avalsctxt->dstBuf;
  getMemNode1stVersion(&head);
  avalsctxt->dstAddrHitCnt = calloc(1, avalsctxt->numOfDstAddr * sizeof(uchar));

  aggreDstHitcnt = 0;
  i = 0;
  while(head != NULL) {
    u32 currVersion = head->version;
    do{
      // printf("dst addr:%x ver:%u hitcnt:%u\n", head->addr, head->version, head->hitcnt);
      aggreDstHitcnt += head->hitcnt;
      head = head->nextVersion;
    } while(head->version != currVersion);

    avalsctxt->dstAddrHitCnt[i] = aggreDstHitcnt;
    aggreDstHitcnt = 0;
    head = head->rightNBR;
    i++;
  }
  // for(i = 0; i < avalsctxt->numOfDstAddr; i++) {
  // 	printf("dst aggregates hit cnt:%u\n", avalsctxt->dstAddrHitCnt[i]);
  // }
}

// ------------------------------------------------------------
// detects avalanche given <in, out> buf pair
// ------------------------------------------------------------
static void
detectAvalancheInOutBufFast(TPMContext *tpm, AvalancheSearchCtxt *avalsctxt)
{
  ContHitcntRange *lst_srcHitcntRange;    // list of ranges s.t. aggregate hitcnt >= min buf sz
  ContHitcntRange *lst_dstHitcntRange;

  lst_srcHitcntRange = analyzeHitCntRange(avalsctxt->numOfSrcAddr, avalsctxt->srcAddrHitCnt, avalsctxt->minBufferSz);
  lst_dstHitcntRange = analyzeHitCntRange(avalsctxt->numOfDstAddr, avalsctxt->dstAddrHitCnt, avalsctxt->minBufferSz);
#ifdef DEBUG
  printHitcntRangeTotal(lst_srcHitcntRange);
  printHitcntRange(lst_srcHitcntRange);
  printHitcntRangeTotal(lst_dstHitcntRange);
  printHitcntRange(lst_dstHitcntRange);
#endif
  if(!hasValidSubRange(lst_srcHitcntRange, lst_dstHitcntRange))
    return;

  ContHitcntRange *range;
  int detectcnt = 1;
  // node first addr second
  LL_FOREACH(lst_srcHitcntRange, range) {
    int addridx = range->addrIdxStart;

    while(addridx < range->addrIdxEnd) {    // no need to search last addr node
      u32 maxAddrIdxInterval = 1; // max interval s.t. avalanche detected given a src node
      u32 addrIdxInterval = 1;    // interval s.t. avalanche detected given a src node
      Addr2NodeItem *srcnode = avalsctxt->addr2NodeAry[addridx];
      
      for(; srcnode != NULL; srcnode = srcnode->hh_addr2NodeItem.next) {
        if(srcnode->node->hitcnt >= avalsctxt->minBufferSz){    // only considers nodes satisfy min buf sz
          printf("--------------------%d detect avalanche\n", detectcnt);
          printf("begin node:addr:%x version:%u\n", srcnode->node->addr, srcnode->node->version);
          printTime("");
          detectAvalancheOfSourceFast(avalsctxt, srcnode, addridx+1, &addrIdxInterval);
          // goto OUTLOOP;

          if(addrIdxInterval > maxAddrIdxInterval)
            maxAddrIdxInterval = addrIdxInterval;

          detectcnt++;
        }
      }
      addridx += maxAddrIdxInterval;  // advances addr by interval
    }
  }

#if 0
  // addr first node second search
  LL_FOREACH(lst_srcHitcntRange, range) {
    int rangesz = range->addrIdxEnd - range->addrIdxStart + 1;
    Addr2NodeItem *srchead[rangesz];
    for(int i = 0; i < rangesz; i++){
      srchead[i] = avalsctxt->addr2NodeAry[i + range->addrIdxStart];
    }

    int startidx = 0, addridx = 0;
    bool hasSearchAll = false;
    while(!hasSearchAll) {
      addridx = startidx;
      while(addridx < rangesz-1) { // last addr node can't be
        u32 addrIdxInterval = 1;
        if(srchead[addridx] != NULL) {
          Addr2NodeItem *srcnode = srchead[addridx];
          // detects here
          if(srcnode->node->hitcnt >= avalsctxt->minBufferSz){
            printMemNode(srcnode->node);
            detectAvalancheOfSourceFast(avalsctxt, srcnode, addridx+1, &addrIdxInterval);
            // goto OUTLOOP;
          }
          srchead[addridx] = srcnode->hh_addr2NodeItem.next;
        }
        addridx += addrIdxInterval;
      }
      hasSearchAll = hasSearchAllSrc(srchead, rangesz, &startidx);
    }
  }
#endif
  OUTLOOP:
  printf("");
}

static bool
hasSearchAllSrc(Addr2NodeItem **srchead, u32 rangesz, u32 *startidx)
{
  for(int addridx = 0; addridx < rangesz-1; addridx++){ // ignore last addr
    if(srchead[addridx] != NULL){
      *startidx = addridx;
      return false;
    }
  }
  return true;
}


// static void 
// detectAvalancheInOutBuf(TPMContext *tpm, AvalancheSearchCtxt *avalsctxt)
// // TODO: comment out
// {
//   u32 maxNumOfAddrAdvanced = 0, numOfAddrAdvanced = 0;
//   u32 addrIdx = 0;
//   Addr2NodeItem *addrHash, *nodeHash;

//   ContHitcntRange *lst_srcHitcntRange = analyzeHitCntRange(avalsctxt->numOfSrcAddr, avalsctxt->srcAddrHitCnt, avalsctxt->minBufferSz);
//   ContHitcntRange *lst_dstHitcntRange = analyzeHitCntRange(avalsctxt->numOfDstAddr, avalsctxt->dstAddrHitCnt, avalsctxt->minBufferSz);
// #ifdef DEBUG	
//   printHitcntRangeTotal(lst_srcHitcntRange);
//   printHitcntRange(lst_srcHitcntRange);
//   printHitcntRangeTotal(lst_dstHitcntRange);
//   printHitcntRange(lst_dstHitcntRange);
// #endif
//   if(!hasValidSubRange(lst_srcHitcntRange, lst_dstHitcntRange))
//     return;

//   for(addrHash = avalsctxt->addr2Node; addrHash != NULL; addrHash = addrHash->hh_addr2NodeItem.next) { // go through each addr
//     // printf("addr:%x hitcnt:%u\n", addrHash->addr, avalsctxt->srcAddrHitCnt[addrIdx]);
//     for(nodeHash = addrHash->subHash; nodeHash != NULL; nodeHash = nodeHash->hh_addr2NodeItem.next) {	// go through each node of addr
//       TPMNode2 *node = nodeHash->node;
//       // printf("addr:%x ver:%u hitcnt:%u\n", node->addr, node->version, node->hitcnt);
//       if(node->hitcnt < avalsctxt->minBufferSz)
//         continue;

//       if(addrHash->hh_addr2NodeItem.next != NULL) { // if has right neighbor addr
//         Addr2NodeItem *next = addrHash->hh_addr2NodeItem.next;
//         detectAvalancheOfSource(avalsctxt, nodeHash, next, &numOfAddrAdvanced);

//         if(numOfAddrAdvanced > maxNumOfAddrAdvanced)
//           maxNumOfAddrAdvanced = numOfAddrAdvanced;
//       }
//     }
//     addrIdx++;

//     while(maxNumOfAddrAdvanced-1 > 0) {
//       if(addrHash->hh_addr2NodeItem.next != NULL)
//         addrHash = addrHash->hh_addr2NodeItem.next;
//       maxNumOfAddrAdvanced--;
//     }
//   }
// }

static ContHitcntRange *
analyzeHitCntRange(u32 numOfAddr, uchar *addrHitcnt, u32 minBufferSz)
// Returns:
// list of sub range of buffer that aggregate hitcnt >= min buf sz
{
  ContHitcntRange *lst_hitcntSubbuf = NULL, *range = NULL;
  u32 addrIdx;

  // scans all buf hitcnt
  for(addrIdx = 0; addrIdx < numOfAddr; addrIdx++) {
    // printf("addr hitcnt:%u\n", addrHitcnt[addrIdx]);
    u32 currIdx = addrIdx;
    if(addrHitcnt[addrIdx] >= minBufferSz) {
      if(range == NULL) {
        range = initContHitcntRange(addrIdx);
        // printf("cont hitcnt range:%p\n", range);
      }
      else {
        range->addrIdxEnd = addrIdx;
      }
    }else {
      if(range != NULL) { // already has sub range
        if(range->addrIdxEnd - range->addrIdxStart >= 1){ // TODO: assume addr is 4 bytes might change later
          LL_APPEND(lst_hitcntSubbuf, range);
        }
        range = NULL;
      }
      else {}
    }
  }
  if(range != NULL && (range->addrIdxEnd - range->addrIdxStart >= 1))
    LL_APPEND(lst_hitcntSubbuf, range);

  return lst_hitcntSubbuf;
}

static bool 
hasValidSubRange(ContHitcntRange *lst_srcHead, ContHitcntRange *lst_dstHead)
{
  ContHitcntRange *temp;
  int srcRangeCnt = 0, dstRangeCnt = 0;
  LL_COUNT(lst_srcHead, temp, srcRangeCnt);
  LL_COUNT(lst_dstHead, temp, dstRangeCnt);
  if(srcRangeCnt > 0 && dstRangeCnt > 0) {
    return true;
  }
  printf("hasValidSubRange: no valid ranges src range cnt:%d dst range cnt:%d\n", srcRangeCnt, dstRangeCnt);
  return false;
}

static ContHitcntRange *
initContHitcntRange(u32 addrIdxStart)
{
  ContHitcntRange *buf = calloc(1, sizeof(ContHitcntRange));
  buf->addrIdxStart = addrIdxStart;
  buf->addrIdxEnd = addrIdxStart;
  return buf;
}

static void 
printHitcntRangeTotal(ContHitcntRange *lstHead)
{
  if(lstHead == NULL)
    return;

  ContHitcntRange *temp;
  int count;
  LL_COUNT(lstHead, temp, count);
  printf("total number of subbuffer:%d\n", count);
}

static void 
printHitcntRange(ContHitcntRange *lstHead)
{
  if(lstHead == NULL)
    return;

  ContHitcntRange *temp;
  LL_FOREACH(lstHead, temp) {
    printf("addr idx start:%u end:%u\n", temp->addrIdxStart, temp->addrIdxEnd);
  }
}

static void 
detectAvalancheOfSourceFast(
    AvalancheSearchCtxt *avalsctxt,
    Addr2NodeItem *srcnode,
    u32 addrIdxStartSearch,
    u32 *addrIdxInterval)
// if valid intersect ra, continue to next addr node
// otherwise if the source node > min buf sz, get avalnche, print out
//           else rewind to prev node?
{
  Addr2NodeItem *oldsrcnode, *newsrcnode;
  RangeArray *oldra = NULL, *newra = NULL;
  RangeArray *oldintersct_ra = NULL, *newintersct_ra = NULL;

  StackAddr2NodeItem *stckTravrsTop = NULL;   // maintains the travers nodes during search
  u32 stckTravrsCnt = 0;

  StackAddr2NodeItem *stckSrcTop = NULL; // maintains the source nodes that has avalanche
  u32 stckSrcCnt = 0;

  bool hasPrint = false;  // if avalanche has been printed, avoid duplication

  // gdb
  // if(srcnode->addr == 0x813e220)
  //    printf("addr: 0x813e220\n");

  oldsrcnode = srcnode;
  addr2NodeItemStackPush(&stckSrcTop, &stckSrcCnt, oldsrcnode);
  oldra = buildRangeArray(oldsrcnode->subHash);
  // printRangeArray(oldra, "old ra");

  storeAllAddrHashChildrenFast(avalsctxt->addr2NodeAry[addrIdxStartSearch],
      &stckTravrsTop, &stckTravrsCnt,
      avalsctxt->minBufferSz, oldsrcnode->node->lastUpdateTS);

  while(!isAddr2NodeItemStackEmpty(stckTravrsTop) ) {
    newsrcnode = addr2NodeItemStackPop(&stckTravrsTop, &stckTravrsCnt);
    // printMemNode(newsrcnode->node);
    // printMemNode(oldsrcnode->node);

    // TODO: add comment
    // newnode's addr <= oldnode's addr, indicates the stack is bouncing back
    if(newsrcnode->node->addr <= oldsrcnode->node->addr) {
      if(!hasPrint){
        if(stckSrcCnt >= 2 && stckSrcCnt >= *addrIdxInterval) {
          printf("--------------------\n");
          addr2NodeItemStackDispRange(stckSrcTop, "avalanche found:\nsrc buf:");
          printf("-> dst buf:\n");
          printRangeArray(oldintersct_ra, "\t");

          *addrIdxInterval = stckSrcCnt;  // set to max num src node has avalanche
        }
      }

      while(newsrcnode->node->addr <= stckSrcTop->addr2NodeItem->node->addr) {
        addr2NodeItemStackPop(&stckSrcTop, &stckSrcCnt);
        addrIdxStartSearch--;
      }

      delOldNewRangeArray(&oldra, &newra);
      delOldNewRangeArray(&oldintersct_ra, &newintersct_ra);

      oldsrcnode = stckSrcTop->addr2NodeItem;
      oldra = buildRangeArray(oldsrcnode->subHash);
      // printMemNode(oldsrcnode->node);
      // printRangeArray(oldra, "old ra");
    }

    // can't delete here, due to in the yes case below, newra is assigned to oldra,
    // if delete newra, then oldra will be deleted also. Now I set new to NULL if the case.
    newra = buildRangeArray(newsrcnode->subHash);
    // printRangeArray(newra, "newra");
    // printRangeArray(oldra, "oldra");
    newintersct_ra = getIntersectRangeArray(oldsrcnode, oldra, newsrcnode, newra);
    // printRangeArray(newintersct_ra, "new intersect ra");

    if(newintersct_ra->rangeAryUsed > 0) { // valid intersection range array
      if(oldintersct_ra != NULL &&
         !is_rangearray_same(oldintersct_ra, newintersct_ra) ) {
        goto NEW_BLOCK;
      }

      oldsrcnode = newsrcnode;
      addr2NodeItemStackPush(&stckSrcTop, &stckSrcCnt, oldsrcnode);

      delRangeArray(&oldra);
      delRangeArray(&oldintersct_ra);

      oldra = newra;
      oldintersct_ra = newintersct_ra;
      // printRangeArray(oldra, "old ra");
      // printRangeArray(oldintersct_ra, "old intersect ra");

      newra = NULL;   // since newra assigns to oldra, set it to NULL after
      newintersct_ra = NULL;

      hasPrint = false;   // only has new src aval node, indicating new aval
    }
    else {
NEW_BLOCK:
      if(!hasPrint){
        if(stckSrcCnt >= 2 && stckSrcCnt >= *addrIdxInterval) {
          printf("--------------------\n");
          addr2NodeItemStackDispRange(stckSrcTop, "avalanche found:\nsrc buf:");
          printf("-> dst buf:\n");
          printRangeArray(oldintersct_ra, "\t");

          *addrIdxInterval = stckSrcCnt;  // set to max num src node has avalanche
        }

        hasPrint = true;
      }

      delRangeArray(&newra);  // only del new ones due to invalid
      delRangeArray(&newintersct_ra);
      continue;   // no valid intersect propagation, no need to go further (as dfs)
    }

    if(addrIdxStartSearch < avalsctxt->numOfSrcAddr){ // push nodes of rightNBR only once
      addrIdxStartSearch++;
      if(addrIdxStartSearch < avalsctxt->numOfSrcAddr) // TODO: reorg
        storeAllAddrHashChildrenFast(avalsctxt->addr2NodeAry[addrIdxStartSearch],
            &stckTravrsTop, &stckTravrsCnt,
            avalsctxt->minBufferSz, oldsrcnode->node->lastUpdateTS);
    }

  }

  // handle last case
  if(!hasPrint){
    if(stckSrcCnt >= 2 && stckSrcCnt >= *addrIdxInterval) {
      printf("--------------------\n");
      addr2NodeItemStackDispRange(stckSrcTop, "avalanche found:\nsrc buf:");
      printf("-> dst buf:\n");
      printRangeArray(oldintersct_ra, "\t");

      *addrIdxInterval = stckSrcCnt;  // set to max num src node has avalanche
    }
  }

  delOldNewRangeArray(&oldra, &newra);
  delOldNewRangeArray(&oldintersct_ra, &newintersct_ra);
}

static void
storeAllAddrHashChildrenFast(
    Addr2NodeItem *addrHash,
    StackAddr2NodeItem **stackAddr2NodeItemTop,
    u32 *stackAddr2NodeItemCount,
    u32 minBufSz,
    int srcLastUpdateTS)
{
  Addr2NodeItem *nodeHash;

  if(addrHash == NULL) {
    fprintf(stderr, "storeAllAddrHashChildrenFast: error: invalid addrHash:%p\n", addrHash);
    return;
  }

  for(nodeHash = addrHash; nodeHash != NULL; nodeHash = nodeHash->hh_addr2NodeItem.next) {
    if(nodeHash->node->hitcnt >= minBufSz ){ // only push nodes satisfy the min sz requirement
      if(nodeHash->node->lastUpdateTS < 0
          && srcLastUpdateTS < 0) {    // if both < 0, smaller is later
        addr2NodeItemStackPush(stackAddr2NodeItemTop, stackAddr2NodeItemCount, nodeHash);
        // if(nodeHash->node->lastUpdateTS < srcLastUpdateTS){
        //   addr2NodeItemStackPush(stackAddr2NodeItemTop, stackAddr2NodeItemCount, nodeHash);
        // }
      }
      else{
        if(nodeHash->node->lastUpdateTS > srcLastUpdateTS) {
          addr2NodeItemStackPush(stackAddr2NodeItemTop, stackAddr2NodeItemCount, nodeHash);
        }
      }
    }
  }
}


RangeArray *
buildRangeArray(Addr2NodeItem *dstNodes)
{
  RangeArray *ra;
  Range *r;

  if(dstNodes == NULL)
    return NULL;

  ra = initRangeArray();
  r = initRange();

  r->start = dstNodes->node->addr;
  r->end = dstNodes->node->addr + dstNodes->node->bytesz;
  u32 currRangeStart = r->start;
  u32 currRangeEnd = r->end;

  Addr2NodeItem *dstNode = dstNodes->hh_addr2NodeItem.next;
  for(; dstNode != NULL; dstNode = dstNode->hh_addr2NodeItem.next){
    TPMNode2 *node = dstNode->node;
    u32 currNodeStart = node->addr;
    if(currRangeEnd > currNodeStart) {
      // TODO: propagate to multiple version of same addr, handles latter
      // printf("buildRangeAry: TODO: multiple version of same addr:%x\n", currNodeStart);
    }
    else if(currRangeEnd == currNodeStart) {
      r->end += node->bytesz;
      currRangeEnd += node->bytesz;
    }
    else{ // new range
      add2Range(ra, r);

      r = initRange();
      r->start = node->addr;
      r->end = node->addr + node->bytesz;

      currRangeStart = r->start;
      currRangeEnd = r->end;
    }
  }
  add2Range(ra, r);   // add the last range
  return ra;
}

static void
delOldNewRangeArray(RangeArray **old, RangeArray **new)
{
  if(*old == *new) { delRangeArray(old); }
  else {
    delRangeArray(old);
    delRangeArray(new);
  }
}


// static void
// detectAvalancheOfSource(AvalancheSearchCtxt *avalsctxt, Addr2NodeItem *sourceNode, Addr2NodeItem *addrHashStartSearch, u32 *numOfAddrAdvanced)
// // TODO: comment out
// // Given a single node in the 2-level hash table, searches itself and its rest addresses nodes has avalanche effect.
// // addr first version second search (dfs)
// {

//   StackAddr2NodeItem *stackTraverseTop = NULL; // maintains the nodes during search
//   u32 stackTraverseCount = 0;

//   StackAddr2NodeItem *stackSourceTop = NULL; // maintains the source nodes that has avalanche
//   u32 stackSourceCount = 0;

//   StackDstBufHT *stackDstBufHTTop = NULL; // maintains the accumulated buf hash table,
//   u32 stackDstBufHTCnt = 0;				// for source nodes propagate to common dst node, store in hash table

//   StackBufAry *stackBufAryTop = NULL;	// maintains the accumulated buf array
//   u32 stackBufAryCnt = 0;				// for source node propagate to common bufs, store in buf ary

//   AvalDstBufHTNode *oldAvalDstBufHT = NULL;
//   AvalDstBufHTNode *newAvalDstBufHT = NULL;

//   ContinBufAry *oldContBufAry, *extendBufAry, *newContBufAry;

//   TaintedBuf *dstMemNodesLst;

//   dstMemNodesLst = sourceNode->toMemNode;

//   if(dstMemNodesLst == NULL)
//     return;

//   // initDstMemNodeHT(dstMemNodesLst, 0x804c170, 0x804c1B0, &oldAvalDstBufHT); // TODO: intersect with dst buf range
//   initDstMemNodeHT(dstMemNodesLst, avalsctxt->dstAddrStart, avalsctxt->dstAddrEnd, &oldAvalDstBufHT); // TODO: intersect with dst buf range
//   dstBufHTStackPush(&stackDstBufHTTop, &stackDstBufHTCnt, oldAvalDstBufHT); // stores source node's propagation that common with dst buf

//   if(HASH_CNT(hh_avalDstBufHTNode, oldAvalDstBufHT) == 0)
//     return;

//   oldContBufAry = buildContinBufAry(oldAvalDstBufHT);	// init the buf ary based on the dst buf hash table
//   bufAryStackPush(&stackBufAryTop, &stackBufAryCnt, oldContBufAry);

//   if(!hasMinSzContBuf(oldContBufAry, 8)) {	// if the init node doesn't has mim buf sz, no need to search
//     // TODO: del all stacks; hard code 8
//     return;
//   }

// #ifdef DEBUG
//   printAvalDstBufHTTotal(oldAvalDstBufHT);
//   printAvalDstBufHT(oldAvalDstBufHT);
//   printContinBufAry(oldContBufAry);
// #endif

//   addr2NodeItemStackPush(&stackSourceTop, &stackSourceCount, sourceNode); // stores souce node
//   u32 currTraverseAddr = addrHashStartSearch->addr;	// tracks the current traverse addr
//   storeAllAddrHashChildren(addrHashStartSearch, &stackTraverseTop, &stackTraverseCount); // stores all verson nodes of source' right neighbor addr

//   while(!isAddr2NodeItemStackEmpty(stackTraverseTop) ) { // simulates dfs search
//     Addr2NodeItem *nodeHash = addr2NodeItemStackPop(&stackTraverseTop, &stackTraverseCount);
//     // printf("node ptr:%p - node addr:%x - dstMemNodesLst ptr:%p\n", nodeHash->node, nodeHash->node->addr, nodeHash->toMemNode);

//     if(currTraverseAddr > nodeHash->node->addr) { // no further addr can explore, step back, already find longest posible source range,
//       // can stop due to prefer longest input buffer
//       *numOfAddrAdvanced = stackSourceCount;	// num of addr advanced
//       if(stackSourceCount > 1) {
//         printf("--------------------\n");
//         addr2NodeItemStackDispRange(stackSourceTop, "avalanche found:\nsrc buf:");
//         printf("aval to dst buf:\n");
//         printContBufAry_lit("\t", oldContBufAry);
//       }
//       break;
//       // TODO: clean
//     }

//     dstMemNodesLst = nodeHash->toMemNode;
//     newAvalDstBufHT = intersectDstMemNodeHT(dstMemNodesLst, oldAvalDstBufHT);
//     if(HASH_CNT(hh_avalDstBufHTNode, newAvalDstBufHT) == 0 )	// the new node doesn't has common with the current nodes, skip
//       continue;

//     extendBufAry = buildContinBufAry(newAvalDstBufHT);
//     newContBufAry = getBufAryIntersect(oldContBufAry, extendBufAry);

//     if(!hasMinSzContBuf(newContBufAry, 8)) {
//       continue;
//       // TODO: old will not change, free new, do sth?
//     }

//     // accumulates the new node
//     addr2NodeItemStackPush(&stackSourceTop, &stackSourceCount, nodeHash);
//     dstBufHTStackPush(&stackDstBufHTTop, &stackDstBufHTCnt, newAvalDstBufHT);
//     bufAryStackPush(&stackBufAryTop, &stackBufAryCnt, newContBufAry);

//     // update the old state to new
//     oldAvalDstBufHT = newAvalDstBufHT;
//     oldContBufAry	= newContBufAry;

//     // stores all version nodes of right neighbor addr
//     if(addrHashStartSearch->hh_addr2NodeItem.next != NULL) {
//       addrHashStartSearch = addrHashStartSearch->hh_addr2NodeItem.next;
//       if(addrHashStartSearch->addr > currTraverseAddr) { // for each addr hash, only push its sub hash nodes once (at first time)
//         storeAllAddrHashChildren(addrHashStartSearch, &stackTraverseTop, &stackTraverseCount);
//         currTraverseAddr = addrHashStartSearch->addr;
//       }
//     }
//   }
// }

// static void
// initDstMemNodeHT(TaintedBuf *dstMemNodesLst, u32 dstAddrStart, u32 dstAddrEnd, AvalDstBufHTNode **avalDstBufHT)
// // TODO: comment out
// {
//   TaintedBuf *itr;

//   LL_FOREACH(dstMemNodesLst, itr) {
//     if(isInMemRange(itr->bufstart, dstAddrStart, dstAddrEnd) ) {
//       AvalDstBufHTNode *dstMemNode = createAvalDstBufHTNode(itr->bufstart, 0);
//       HASH_ADD(hh_avalDstBufHTNode, *avalDstBufHT, dstNode, 4, dstMemNode);
//     }
//   }
//   HASH_SRT(hh_avalDstBufHTNode, *avalDstBufHT, cmpAvalDstBufHTNode);
// }

// static ContinBufAry *
// buildContinBufAry(AvalDstBufHTNode *dstMemNodesHT)
// // TODO: comment out
// // Returns:
// //	Continuous buffers array, based on the dst mem nodes hash table
// {	
//   // if(dstMemNodesHT == NULL)
//   // 	return NULL;

//   ContinBufAry *contBufAry;
//   ContinBuf *contBuf;
//   AvalDstBufHTNode *item, *temp;

//   contBufAry = initContBufAry();
//   contBuf = initContinBuf();

//   // init first node
//   u32 bufstart = dstMemNodesHT->dstNode->addr;
//   u32 bufsz    = dstMemNodesHT->dstNode->bytesz;
//   extendContinBuf(contBuf, dstMemNodesHT->dstNode);

//   for(item = dstMemNodesHT->hh_avalDstBufHTNode.next; item != NULL; item = item->hh_avalDstBufHTNode.next) {
//     // printf("addr:%x size:%u\n", item->dstNode->addr, item->dstNode->bytesz);

//     TPMNode2 *dstNode = item->dstNode;
//     u32 currNodeStart = dstNode->addr;
//     u32 currBufRange = bufstart + bufsz;

//     if(currBufRange > currNodeStart) {
//       // TODO: propagate to multiple version of same addr, handles latter
//       // printf("buildContinBufAry: TODO: multiple version of same addr:%x\n", currNodeStart);
//     }
//     else if(currBufRange == currNodeStart) {
//       extendContinBuf(contBuf, item->dstNode);
//       bufsz += item->dstNode->bytesz;
//     }
//     else { // a new buffer
//       appendContBufAry(contBufAry, contBuf);
//       contBuf = initContinBuf();
//       extendContinBuf(contBuf, dstNode);

//       bufstart = dstNode->addr;
//       bufsz = dstNode->bytesz;
//     }
//   }

//   appendContBufAry(contBufAry, contBuf);	// add the last continuous buffer
//   return contBufAry;
// }

// static void 
// storeAllAddrHashChildren(Addr2NodeItem *addrHash, StackAddr2NodeItem **stackAddr2NodeItemTop, u32 *stackAddr2NodeItemCount)
// // TODO: comment out
// // No need mark visited node, because for each addr hash, only need to
// // push once 
// {
//   Addr2NodeItem *nodeHash;
//   for(nodeHash = addrHash->subHash; nodeHash != NULL; nodeHash = nodeHash->hh_addr2NodeItem.next) {
//     addr2NodeItemStackPush(stackAddr2NodeItemTop, stackAddr2NodeItemCount, nodeHash);
//   }
// }

static AvalDstBufHTNode *
createAvalDstBufHTNode(TPMNode2 *dstNode, u32 hitcnt)
{
  AvalDstBufHTNode *i = NULL;
  i = malloc(sizeof(AvalDstBufHTNode) );
  i->dstNode = dstNode;
  i->hitcnt = hitcnt;
  return i;
}

static int 
cmpAvalDstBufHTNode(AvalDstBufHTNode *l, AvalDstBufHTNode *r)
{
  if(l->dstNode->addr < r->dstNode->addr) { return -1; }
  else if(l->dstNode->addr == r->dstNode->addr) { return 0; }
  else { return 1; }
}

// static AvalDstBufHTNode *
// intersectDstMemNodeHT(TaintedBuf *dstMemNodesLst, AvalDstBufHTNode *avalDstBufHT)
// // TODO: comment out
// // computes the intersected node between the dstMemNodeList and the avalDstBufHT,
// // updates the avalDstBufHT accordingly 
// {
//   AvalDstBufHTNode *intersect = NULL, *item, *temp;
//   TaintedBuf *intersectLst = NULL, *intersectItem, *itr;

//   initDstBufHTNodeHitcnt(avalDstBufHT);

//   LL_FOREACH(dstMemNodesLst, itr) {
//     TPMNode2 *dstNode = itr->bufstart;
//     // printMemNode(dstNode);
//     AvalDstBufHTNode *dstMemNode;
//     HASH_FIND(hh_avalDstBufHTNode, avalDstBufHT, &dstNode, 4, dstMemNode);
//     if(dstMemNode != NULL) {
//       (dstMemNode->hitcnt)++;
//     }
//   }

//   HASH_ITER(hh_avalDstBufHTNode, avalDstBufHT, item, temp) {
//     if(item->hitcnt == 1) { // intersection with the dstMemNode list
//       AvalDstBufHTNode *intersectNode = createAvalDstBufHTNode(item->dstNode, 0);
//       HASH_ADD(hh_avalDstBufHTNode, intersect, dstNode, 4, intersectNode);
//       // HASH_DELETE(hh_avalDstBufHTNode, *avalDstBufHT, item);
//       // free(item);
//     }
//   }
//   return intersect;
// }

static void 
initDstBufHTNodeHitcnt(AvalDstBufHTNode *avalDstBufHT)
// init all item's hitcnt in the hash table are 0s
{
  AvalDstBufHTNode *item, *temp;
  HASH_ITER(hh_avalDstBufHTNode, avalDstBufHT, item, temp){
    item->hitcnt = 0;
  }
}

static bool 
isInMemRange(TPMNode2 *node, u32 addrBegin, u32 addrEnd)
{
  assert(node != NULL);
  if(node->addr >= addrBegin && node->addr <= addrEnd) { return true; }
  else { return false; }
}

// static void 
// test_createDstContinBuf(AvalDstBufHTNode *dstMemNodesHT)
// // TODO: comment out
// {
//   ContinBuf *continBuf_l = NULL, *continBuf_r;
//   ContinBufAry *contBufAry_l = NULL, *contBufAry_r = NULL, *bufAryIntersect;
//   AvalDstBufHTNode *item, *temp;

//   /* test cont buf*/
//   continBuf_l = initContinBuf();
//   // printContinBuf(continBuf_l);
//   HASH_ITER(hh_avalDstBufHTNode, dstMemNodesHT, item, temp) {
//     // printf("addr:0x%x - ptr:%p\n", item->dstNode->addr, item->dstNode);
//     extendContinBuf(continBuf_l, item->dstNode);
//     // break;
//   }
//   // printContinBuf(continBuf_l);

//   continBuf_r = initContinBuf();
//   int i = 0;
//   HASH_ITER(hh_avalDstBufHTNode, dstMemNodesHT, item, temp) {
//     // printf("addr:0x%x - ptr:%p\n", item->dstNode->addr, item->dstNode);
//     if(i == 0) {
//       i++;
//       continue;
//     }
//     extendContinBuf(continBuf_r, item->dstNode);
//     i++;
//     if(i == 2)
//       break;
//   }

//   /* test cont buf ary*/
//   contBufAry_l = initContBufAry();
//   // printContinBufAry(contBufAry_l);
//   appendContBufAry(contBufAry_l, continBuf_l);
//   printContinBufAry(contBufAry_l);

//   contBufAry_r = initContBufAry();
//   appendContBufAry(contBufAry_r, continBuf_r);
//   printContinBufAry(contBufAry_r);

//   bufAryIntersect = getBufAryIntersect(contBufAry_l, contBufAry_r);
//   printf("Intersect buf ary:\n");
//   printContinBufAry(bufAryIntersect);

//   delContinBufAry(&contBufAry_l);
//   delContinBufAry(&contBufAry_r);
//   // printContinBufAry(contBufAry_l);
// }

static void
addr2NodeItemStackPush(StackAddr2NodeItem **stackAddr2NodeItemTop, u32 *stackAddr2NodeItemCount, Addr2NodeItem *addr2NodeItem)
{
  StackAddr2NodeItem *n = calloc(1, sizeof(StackAddr2NodeItem) );
  n->addr2NodeItem = addr2NodeItem;
  n->next = *stackAddr2NodeItemTop;
  *stackAddr2NodeItemTop = n;
  (*stackAddr2NodeItemCount)++;
}

static Addr2NodeItem *
addr2NodeItemStackPop(StackAddr2NodeItem **stackAddr2NodeItemTop, u32 *stackAddr2NodeItemCount)
{
  StackAddr2NodeItem *toDel;
  Addr2NodeItem *addr2NodeItem = NULL;

  if(*stackAddr2NodeItemTop != NULL) {
    toDel = *stackAddr2NodeItemTop;
    *stackAddr2NodeItemTop = toDel->next;
    addr2NodeItem = toDel->addr2NodeItem;
    free(toDel);
    (*stackAddr2NodeItemCount)--;
  }
  return addr2NodeItem;
}

static void 
addr2NodeItemStackDisplay(StackAddr2NodeItem *stackAddr2NodeItemTop)
{
  StackAddr2NodeItem *n = stackAddr2NodeItemTop;
  while(n != NULL) {
    TPMNode2 *node = n->addr2NodeItem->node;
    // printf("addr2NodeItem:%p - node ptr:%p - node addr:%x - dstMemNodesLst:%p\n",
    // 	n->addr2NodeItem, n->addr2NodeItem->node, n->addr2NodeItem->node->addr, n->addr2NodeItem->toMemNode);
    printf("addr:%x - ver:%u ", node->addr, node->version);
    n = n->next;
  }
  printf("\n");
}

static void 
addr2NodeItemStackDispRange(StackAddr2NodeItem *stackAddr2NodeItemTop, char *s)
{
  if(stackAddr2NodeItemTop == NULL)
    return;

  StackAddr2NodeItem *n = stackAddr2NodeItemTop;
  u32 bufstart, bufend;
  TPMNode2 *node;

  node = n->addr2NodeItem->node;
  bufend = node->addr + node->bytesz;

  printf("%s\n", s);
  while(n != NULL && n->next != NULL) {
    node = n->addr2NodeItem->node;
    // printf("\taddr:%x val:%x lastTS:%d hitcnt:%u version:%u\n",
    //         node->addr, node->val, node->lastUpdateTS, node->hitcnt, node->version);
    n = n->next;
  }

  node = n->addr2NodeItem->node; // last node
  // printf("\taddr:%x val:%x lastTS:%d hitcnt:%u version:%u\n",
  // 	    node->addr, node->val, node->lastUpdateTS, node->hitcnt, node->version);

  bufstart = n->addr2NodeItem->node->addr;
  printf("\tbufstart:%x bufend:%x sz:%u\n", bufstart, bufend, bufend-bufstart);
}

static void 
addr2NodeItemStackPopAll(StackAddr2NodeItem **stackAddr2NodeItemTop, u32 *stackAddr2NodeItemCount)
{
  while(*stackAddr2NodeItemTop != NULL) {
    addr2NodeItemStackPop(stackAddr2NodeItemTop, stackAddr2NodeItemCount);
  }
}

static bool 
isAddr2NodeItemStackEmpty(StackAddr2NodeItem *stackAddr2NodeItemTop)
{
  if(stackAddr2NodeItemTop == NULL)
    return true;
  else
    return false;
}

/* Stack of destination buf hash table operation */
// static void 
// dstBufHTStackPush(StackDstBufHT **stackDstBufHTTop, u32 *stackDstBufHTCount, AvalDstBufHTNode *dstBufHT)
// // TODO: comment out
// {
//   StackDstBufHT *n = calloc(1, sizeof(StackDstBufHT) );
//   n->dstBufHT = dstBufHT;
//   n->next = *stackDstBufHTTop;
//   *stackDstBufHTTop = n;
//   (*stackDstBufHTTop)++;
// }

static AvalDstBufHTNode*
dstBufHTStackPop(StackDstBufHT **stackDstBufHTTop, u32 *stackDstBufHTCount)
{
  StackDstBufHT *toDel;
  AvalDstBufHTNode *dstBufHT = NULL;

  if(*stackDstBufHTTop != NULL) {
    toDel = *stackDstBufHTTop;
    *stackDstBufHTTop = toDel -> next;
    dstBufHT = toDel->dstBufHT;
    free(toDel);
    (*stackDstBufHTCount)--;
  }
  return dstBufHT;
}

/* Stack of buf array operations */
// static void 
// bufAryStackPush(StackBufAry **stackBufAryTop, u32 *stackBufAryCnt, ContinBufAry *contBufAry)
// // TODO: comment out
// {
//   StackBufAry *n = calloc(1, sizeof(StackBufAry) );
//   n->contBufAry = contBufAry;
//   n->next = *stackBufAryTop;
//   *stackBufAryTop = n;
//   (*stackBufAryTop)++;
// }

static ContinBufAry *
bufAryStackPop(StackBufAry **stackBufAryTop, u32 *stackBufAryCnt)
{
  StackBufAry *toDel;
  ContinBufAry *contBufAry;

  if(*stackBufAryTop != NULL) {
    toDel = *stackBufAryTop;
    *stackBufAryTop = toDel->next;
    contBufAry = toDel->contBufAry;
    free(toDel);
    (*stackBufAryCnt)--;
  }
  return contBufAry;
}

static void 
printDstMemNodesHTTotal(Addr2NodeItem *dstMemNodesHT)
{
  int total;
  total = HASH_CNT(hh_addr2NodeItem, dstMemNodesHT);
  printf("total addr item in hash table:%d\n", total);
}

static void 
printDstMemNodesHT(Addr2NodeItem *dstMemNodesHT)
{
  Addr2NodeItem *item, *subitem, *temp, *subTemp;
  TaintedBuf *itr;
  int count, totalSubItem;

  HASH_ITER(hh_addr2NodeItem, dstMemNodesHT, item, temp) {
    totalSubItem = HASH_CNT(hh_addr2NodeItem, item->subHash);
    printf("addr:0x%x - total pointer item in sub hash table:%d\n", item->addr, totalSubItem);
    HASH_ITER(hh_addr2NodeItem, item->subHash, subitem, subTemp) {
      TaintedBuf *dstMemNodesLst = subitem->toMemNode;
      printf("addr:%-8x version:%u - ", (subitem->node)->addr, (subitem->node)->version);
      LL_COUNT(dstMemNodesLst, itr, count);
      printf("total propagate destination mem nodes:%d\n", count);
      printDstMemNodesList(dstMemNodesLst);
    }
  }
}

static void 
printDstMemNodesListTotal(TaintedBuf *dstMemNodesLst)
{	
  int count;
  TaintedBuf *itr;

  LL_COUNT(dstMemNodesLst, itr, count);
  printf("total item in list:%d\n", count);
}

static void 
printDstMemNodesList(TaintedBuf *dstMemNodesLst)
{
  TaintedBuf *itr;

  LL_FOREACH(dstMemNodesLst, itr) {
    printMemNode(itr->bufstart);
    // printf("\t-> addr:%-8x val:%-8x\n", itr->bufstart->addr, itr->bufstart->val);
  }
}

// static void 
// printAvalDstBufHTTotal(AvalDstBufHTNode *avalDstBufHT)
// // TODO: comment out
// {
//   int total;
//   total = HASH_CNT(hh_avalDstBufHTNode, avalDstBufHT);
//   printf("total nodes in destination range:%d\n", total);
// }

// static void 
// printAvalDstBufHT(AvalDstBufHTNode *avalDstBufHT)
// // TODO: comment out
// {
//   AvalDstBufHTNode *item, *temp;
//   HASH_ITER(hh_avalDstBufHTNode, avalDstBufHT, item, temp) {
//     printf("addr:0x%x - val:%x - ptr:%p hitcnt:%u\n", item->dstNode->addr, item->dstNode->val, item->dstNode, item->hitcnt);
//   }
// }

static void
print2LevelHashTable(struct addr2NodeItem **addr2NodeAry, u32 numOfAddr)
{
  Addr2NodeItem *src, *dst;
  int addridx = 0;
  for(; addridx < numOfAddr; addridx++) {
    for(src = addr2NodeAry[addridx]; src != NULL; src = src->hh_addr2NodeItem.next) {
      printf("--------------------2LHash\nsrc:\n");
      printMemNodeLit(src->node);
      printf("to:\n");
      for(dst = src->subHash; dst != NULL; dst = dst->hh_addr2NodeItem.next) {
        printMemNodeLit(dst->node);
      }
    }
  }
}

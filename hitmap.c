#include "env.h"
#include "hitmap.h"
#include "propagate.h"
#include "misc.h"
#include <assert.h>

/* build HitMap of each buffer in TPM*/
static BufContext *
initBufContext(
    TPMContext *tpm,
    HitMapContext *hitMap,
    TPMBufHashTable *buf);

// static BufHitcntCtxt *
// initBufHitCntCtxt(TPMBufHashTable *buf);

static void
buildBufContext(
    TPMContext *tpm,
    HitMapContext *hitMap,
    TPMBufHashTable *buf,
    u32 *nodeVisitIdx);

static void
delBufContext(BufContext *bufCtxt);

// static void
// getAggregtHitcnt(
//     HitMapNode *head,
//     u32 *aggregtHitcntIn,
//     u32 *aggregtHitcntOut);

/* build HitMap of each addr of each buffer */
static void
buildHitMapAddr(
    TPMContext *tpm,
    HitMapContext *hitMap,
    TPMNode2 *headNode,
    u32 *nodeVisitIdx);

static u32
getHitMapTotalNode(HitMapContext *hitMap);

static u32
getHitMapTotalTransaction(HitMapContext *hitMap);

static u32
getHitMapReverseTotalTrans(HitMapContext *hitMap);

static u32
getHitMapNodeTransactionNumber(HitMapNode *hmNode);

static u32
getHitMapNodeReverseTransNum(HitMapNode *hmNode);

static u32
getHitMapTotalIntermediateNode(HitMapContext *hitMapCtxt);

static u32
getHitMapIntermediateTotalTrans(HitMapContext *hitMap);

static void
compHitMapBufStat(
    HitMapNode *hmNode,
    u32 *baddr,
    u32 *eaddr,
    int *minseq,
    int *maxseq,
    u32 *numOfAddr,
    HitMapNode **firstnode,
    u32 *totalNode);

static HitMapNode *
getLeftMost(HitMapNode *node);

static bool
isAllVersionNodeLeftMost(HitMapNode *node);

static void
getFirstVerNode(HitMapNode **first);

/* HitMap buffer hash */
static HitMapBufHash *
initHitMapBufHTNode(
    u32 baddr,
    u32 eaddr,
    int minseq,
    int maxseq,
    u32 numOfAddr,
    HitMapNode *firstnode,
    u32 totalNode);

static int
cmpHitMapBufHashNode(HitMapBufHash *l, HitMapBufHash *r);

static int
cmp_HM_bufhash_byseqn(HitMapBufHash *l, HitMapBufHash *r);

static void
assignHitMapBufID(HitMapBufHash *headBuf);

/* HitMap buffer hit count array */
static int
initHitMapBufHitCntAray(HitMapContext *hitMap);

static int
createOneHMBufHitCntAry(
    u32 bufIdx,
    u32 numOfBuf,
    HitMapBufHash *buf,
    HitMapContext *hitMap);

static int
updateHMNodeHitCnt(
    HitMapNode *node,
    u32 *inBufHitCntAry,
    u32 *outBufHitCntAry,
    u32 bufStart,
    u32 bufEnd);

static void
printOneHMBufHitCntAry(
    u32 *bufHitCntAry,
    u32 bufStart,
    u32 bufEnd);

HitMapContext *
initHitMap(TPMContext *tpm, TPMBufContext *tpmBufCtxt)
{
  HitMapContext *hitMap;
  TPMBufHashTable *currBuf;
  int numOfBuf;
  u32 maxBufSeqN;

  hitMap = calloc(sizeof(HitMapContext), 1);
  assert(hitMap != NULL);

  hitMap->hitMapNodeHT = NULL;
  hitMap->intrtmdt2HitMapNodeHT = NULL;
  hitMap->maxBufSeqN = getTPMBufMaxSeqN(tpmBufCtxt->tpmBufHash);
  // printf("maxBufSeqN:%u\n", hitMap->maxBufSeqN);

  numOfBuf = HASH_CNT(hh_tpmBufHT, tpmBufCtxt->tpmBufHash);
  hitMap->numOfBuf = numOfBuf;
  hitMap->minBufSz = tpm->minBufferSz;
  hitMap->tpmBufCtxt = tpmBufCtxt;
  hitMap->tpmBuf = tpmBufCtxt->tpmBufHash;

  hitMap->bufArray = calloc(sizeof(BufContext *), numOfBuf);
  assert(hitMap->bufArray != NULL);
  // hitMap->bufHitcntInArray = calloc(sizeof(BufHitcntCtxt *), numOfBuf);
  // hitMap->bufHitcntOutArray = calloc(sizeof(BufHitcntCtxt *), numOfBuf);
  // assert(hitMap->bufHitcntInArray != NULL);
  // assert(hitMap->bufHitcntOutArray != NULL);

  int i = 0;
  for(currBuf = tpmBufCtxt->tpmBufHash; currBuf != NULL; currBuf = currBuf->hh_tpmBufHT.next) {
    hitMap->bufArray[i] = initBufContext(tpm, hitMap, currBuf);
    // hitMap->bufHitcntInArray[i] = initBufHitCntCtxt(currBuf); currently not used
    // hitMap->bufHitcntOutArray[i] = initBufHitCntCtxt(currBuf);
    i++;
  }
  printTime("Finish init HitMap");
  // printTPMBufHashTable(hitMap->tpmBuf);
  return hitMap;
}

HitMapContext *
buildHitMap(TPMContext *tpm, TPMBufContext *tpmBufCtxt)
{
  HitMapContext *hitMap;
  u32 maxBufSeqN;

  hitMap = initHitMap(tpm, tpmBufCtxt);

  int i      = 1;
  TPMBufHashTable *currBuf = hitMap->tpmBuf;

  u32 nodeVisitIdx = 1;

  for(; currBuf != NULL; currBuf = currBuf->hh_tpmBufHT.next) {
    buildBufContext(tpm, hitMap, currBuf, &nodeVisitIdx);
    printTime("build HitMap: ");
    printf("finished %u th buf\n", i);
    i++;
  }
  printTime("Finish building HitMap");
  updateHitMapBufContext(hitMap);   // create HitMap buffer hash
  return hitMap;
}

// static void
// getAggregtHitcnt(
//     HitMapNode *head,
//     u32 *aggregtHitcntIn,
//     u32 *aggregtHitcntOut)
// {
//   if(head == NULL)
//     return;

//   u32 ver = head->version;
//   do {
//     *aggregtHitcntIn += head->hitcntIn;
//     *aggregtHitcntOut += head->hitcntOut;

//     head = head->nextVersion;
//   } while(ver != head->version);
// }

void
compHitMapStat(HitMapContext *hitMap)
{
  u32 numOfNode, numOfIntermediateNode;
  u32 totalTrans, totalIntermediateTrans;

  sortHitMapHashTable(&(hitMap->hitMapNodeHT) );

  numOfNode = getHitMapTotalNode(hitMap);
  printf("----------\ntotal number of node in HitMap:%u\n", numOfNode);

  totalTrans = getHitMapTotalTransaction(hitMap);
  printf("total transitions: %u\n", totalTrans);

  numOfIntermediateNode = getHitMapTotalIntermediateNode(hitMap);
  printf("total number of intermediate node in HitMap:%u\n", numOfIntermediateNode);

  totalIntermediateTrans = getHitMapIntermediateTotalTrans(hitMap);
  printf("total intermediate transitions:%u\n", totalIntermediateTrans);
}

void
compReverseHitMapStat(HitMapContext *hitMap)
{
  u32 numOfNode, numOfIntermediateNode;
  u32 totalTrans, totalIntermediateTrans;

  sortHitMapHashTable(&(hitMap->hitMapNodeHT) );

  numOfNode = getHitMapTotalNode(hitMap);
  printf("----------\ntotal number of node in HitMap:%u\n", numOfNode);

  totalTrans = getHitMapReverseTotalTrans(hitMap);
  printf("total transitions: %u\n", totalTrans);
}

void
updateHitMapBufContext(HitMapContext *hitMap)
{
  HitMapBufContext *hitMapBufCtxt;
  hitMapBufCtxt = initHitMapBufContext(hitMap);
  hitMap->hitMapBufCtxt = hitMapBufCtxt;
}

HitMapBufContext *
initHitMapBufContext(HitMapContext *hitMap)
{
  HitMapBufContext *hitMapBufCtxt;

  hitMapBufCtxt = calloc(sizeof(HitMapBufContext), 1);
  assert(hitMapBufCtxt != NULL);

  hitMapBufCtxt->hitMapBufHash = analyzeHitMapBuf(hitMap);
  hitMapBufCtxt->numOfBuf = HASH_CNT(hh_hmBufHash, hitMapBufCtxt->hitMapBufHash);
  assignHitMapBufID(hitMapBufCtxt->hitMapBufHash);
  printHitMapBufHash(hitMapBufCtxt->hitMapBufHash);
  return hitMapBufCtxt;
}

void
delHitMapBufContext(HitMapBufContext *hitMapBufCtxt)
{
  delHitHitMapBufHash(hitMapBufCtxt->hitMapBufHash);
  free(hitMapBufCtxt);
  printf("del HitMap buffers context.\n");
}

HitMapBufHash *
analyzeHitMapBuf(HitMapContext *hitMap)
{
  HitMapBufNodePtr2NodeHashTable *hmBufNodeHash;
  HitMapBufHash *hitMapBufHash = NULL, *bufHash, *bufFound;

  HitMapNode *hitMapNode, *hitMapHeadNode;
  u32 baddr, eaddr, numOfAddr, totalNode = 0;
  int minseq, maxseq;

  hmBufNodeHash = hitMap->hitMapNodeHT;
  for(; hmBufNodeHash != NULL; hmBufNodeHash = hmBufNodeHash->hh_hitMapBufNode2NodeHT.next) {
    hitMapNode = hmBufNodeHash->toHitMapNode;

    HitMapNode *leftMost = getLeftMost(hitMapNode);
    // while(leftMost->leftNBR != NULL) { leftMost = leftMost->leftNBR; }
    baddr = leftMost->addr;
    HASH_FIND(hh_hmBufHash, hitMapBufHash, &baddr, 4, bufFound);
    if(bufFound != NULL)
      continue;

    // printf("-----\n");
    compHitMapBufStat(hitMapNode, &baddr, &eaddr, &minseq, &maxseq,
        &numOfAddr, &hitMapHeadNode, &totalNode);
    if(eaddr - baddr >= 8) { // TODO: add 8 to hitMap context
      bufHash = initHitMapBufHTNode(baddr, eaddr, minseq, maxseq,
          numOfAddr, hitMapHeadNode, totalNode);
      HASH_FIND(hh_hmBufHash, hitMapBufHash, &baddr, 4, bufFound);
      if(bufFound == NULL) {
        // printOneHitMapBufHash(bufHash);
        HASH_ADD(hh_hmBufHash, hitMapBufHash, baddr, 4, bufHash);
      }
      else { free(bufHash); bufHash = NULL; }
    }
  }
  HASH_SRT(hh_hmBufHash, hitMapBufHash, cmpHitMapBufHashNode);

  return hitMapBufHash;
}

HitMapBufHash *get_hitmap_buf(
    HitMapBufHash *buf_head,
    u32 buf_idx)
{
  u32 idx = 0;
  while(buf_head != NULL && idx < buf_idx) {
    buf_head = buf_head->hh_hmBufHash.next;
    idx++;
  }
  return buf_head;
}

void
delHitHitMapBufHash(HitMapBufHash *hitMapBufHash)
{
  HitMapBufHash *cur, *tmp;
  assert(hitMapBufHash != NULL);

  HASH_ITER(hh_hmBufHash, hitMapBufHash, cur, tmp) {
    HASH_DELETE(hh_hmBufHash, hitMapBufHash, cur);
    free(cur);
  }
  // printf("del HitMap buffers.\n");
}

int
createHitMapBuftHitCnt(HitMapContext *hitMap)
{
  HitMapBufHash *buf = NULL;
  u32 bufIdx = 0;

  if(initHitMapBufHitCntAray(hitMap) >= 0) {
    buf = hitMap->hitMapBufCtxt->hitMapBufHash;
    for(; buf != NULL; buf = buf->hh_hmBufHash.next) {
      if(createOneHMBufHitCntAry(bufIdx, hitMap->hitMapBufCtxt->numOfBuf, buf, hitMap) < 0 ) {
        goto error;
      }
      bufIdx++;
    }

    return 0;
  }
  else { goto error; }

error:
  fprintf(stderr, "createHitMapBuftHitCnt: fail\n");
  return -1;
}

void
delHitMapBufHitCnt(HitMapContext *hitMap)
{
  u32 bufIdx;
  if(hitMap != NULL && hitMap->hitMapBufCtxt != NULL) {
    if(hitMap->inHitCntBufAry != NULL) {
      for(bufIdx = 0; bufIdx < hitMap->hitMapBufCtxt->numOfBuf; bufIdx++) {
        if(hitMap->inHitCntBufAry[bufIdx] != NULL) {
          free(hitMap->inHitCntBufAry[bufIdx]);
          hitMap->inHitCntBufAry[bufIdx] = NULL;
        }
      }

      free(hitMap->inHitCntBufAry);
      hitMap->inHitCntBufAry = NULL;
      printf("del HitMap buffer In hit count array\n");
    }

    if(hitMap->outHitCntBufAry != NULL) {
      for(bufIdx = 0; bufIdx < hitMap->hitMapBufCtxt->numOfBuf; bufIdx++) {
        if(hitMap->outHitCntBufAry[bufIdx] != NULL) {
          free(hitMap->outHitCntBufAry[bufIdx]);
          hitMap->outHitCntBufAry[bufIdx] = NULL;
        }
      }

      free(hitMap->outHitCntBufAry);
      hitMap->outHitCntBufAry = NULL;
      printf("del HitMap buffer Out hit count array\n");
    }
  }
}

void
printHitMapBufHitCntAry(HitMapContext *hitMap)
{
  u32 numOfBuf = 0;
  u32 bufIdx = 0;
  HitMapBufHash *bufHead;
  if(hitMap != NULL && hitMap->hitMapBufCtxt != NULL) {
    numOfBuf = hitMap->hitMapBufCtxt->numOfBuf;

    for(bufHead = hitMap->hitMapBufCtxt->hitMapBufHash; bufHead != NULL; bufHead = bufHead->hh_hmBufHash.next) {
      assert(bufIdx < numOfBuf);

      printf("-----\n");
      printOneHitMapBufHash(bufHead);
      printf("In buffer hit count array:\n");
      if(hitMap->inHitCntBufAry != NULL)
        printOneHMBufHitCntAry(hitMap->inHitCntBufAry[bufIdx], bufHead->baddr, bufHead->eaddr);

      printf("Out buffer hit count array:\n");
      if(hitMap->outHitCntBufAry != NULL)
        printOneHMBufHitCntAry(hitMap->outHitCntBufAry[bufIdx], bufHead->baddr, bufHead->eaddr);
      bufIdx++;
    }
  }
}

static u32
getHitMapTotalNode(HitMapContext *hitMap)
{
  return HASH_CNT(hh_hitMapBufNode2NodeHT, hitMap->hitMapNodeHT);
}

static u32
getHitMapTotalTransaction(HitMapContext *hitMap)
{
  u32 totalTrans = 0;
  HitMapBufNodePtr2NodeHashTable *item, *temp;
  HASH_ITER(hh_hitMapBufNode2NodeHT, hitMap->hitMapNodeHT, item, temp ) {
    // printHitMapNode(item->toHitMapNode);
    totalTrans +=  getHitMapNodeTransactionNumber(item->toHitMapNode);
  }
  return totalTrans;
}

static u32
getHitMapReverseTotalTrans(HitMapContext *hitMap)
{
  u32 totalTrans = 0, totalNode = 0;
  HitMapBufNodePtr2NodeHashTable *item, *temp;
  HASH_ITER(hh_hitMapBufNode2NodeHT, hitMap->hitMapNodeHT, item, temp ) {
    // printHitMapNode(item->toHitMapNode);
    totalTrans += getHitMapNodeReverseTransNum(item->toHitMapNode);
    totalNode++;
  }
  // printf("total nodes:%u\n", totalNode);
  return totalTrans;
}

static u32
getHitMapNodeTransactionNumber(HitMapNode *hmNode)
{
  u32 numOfTrans = 0;
  HitTransition *firstChild = hmNode->firstChild;
  // printf("-----farther\n");
  // printHitMapNodeLit(hmNode);
  while(firstChild != NULL) {
    numOfTrans++;
    // printHitMapTransition(firstChild);
    firstChild = firstChild->next;
  }
  return numOfTrans;
}

static u32
getHitMapNodeReverseTransNum(HitMapNode *hmNode)
{
  u32 numOfTrans = 0;
  HitTransition *taintedBy = hmNode->taintedBy;
  while(taintedBy != NULL) {
    numOfTrans++;
    taintedBy = taintedBy->next;
  }
  return numOfTrans;
}

static u32
getHitMapTotalIntermediateNode(HitMapContext *hitMapCtxt)
{
  return HASH_CNT(hh_intrtmdtNode2HitMapNodeHT, hitMapCtxt->intrtmdt2HitMapNodeHT);
}

static u32
getHitMapIntermediateTotalTrans(HitMapContext *hitMap)
{
  u32 totalIntermediateTrans = 0;
  IntrtmdtNode2HitMapNodeHashTalbe *item, *temp;
  HASH_ITER(hh_intrtmdtNode2HitMapNodeHT, hitMap->intrtmdt2HitMapNodeHT, item, temp) {
    totalIntermediateTrans += getHitMapNodeTransactionNumber(item->toHitMapNode);
  }
  return totalIntermediateTrans;
}

static void
compHitMapBufStat(
    HitMapNode *hmNode,
    u32 *baddr,
    u32 *eaddr,
    int *minseq,
    int *maxseq,
    u32 *numOfAddr,
    HitMapNode **firstnode,
    u32 *totalNode)
{
  HitMapNode *b, *e, *lastend;
  u32 maxEndAddr;
  assert(hmNode != NULL);

  *totalNode = 0;
  *numOfAddr = 0;
  b = e = hmNode;

  // while(b->leftNBR != NULL) { b = b->leftNBR; }; // traverse to left most
  b = getLeftMost(hmNode);
  *baddr = b->addr;
  maxEndAddr = b->addr;
  *firstnode = b;
  getFirstVerNode(firstnode);

  *minseq = (*firstnode)->lastUpdateTS;
  *maxseq = (*firstnode)->lastUpdateTS;

  e = *firstnode;
  while(e != NULL) {
    u32 ver = e->version;
    int seqN = 0;
    do {
      // printHitMapNodeLit(e);
      seqN = e->lastUpdateTS;
      if(*minseq > seqN)
        *minseq = seqN;

      if(*maxseq < seqN)
        *maxseq = seqN;

      if(e->addr + e->bytesz > maxEndAddr)
        maxEndAddr = e->addr + e->bytesz;

      *totalNode += 1;
      e = e->nextVersion;
    } while (ver != e->version);

    lastend = e;
    e = e->rightNBR;
    (*numOfAddr)++;
  }
  if(lastend->addr + lastend->bytesz > maxEndAddr)
    maxEndAddr = lastend->addr + lastend->bytesz;

  *eaddr = maxEndAddr;
  // *eaddr = lastend->addr + lastend->bytesz;
  // printHitMapNodeLit(lastend);
}

static HitMapNode *
getLeftMost(HitMapNode *node)
{
  HitMapNode *leftMost = node;

  while (true) {
    if (isAllVersionNodeLeftMost(leftMost))
      break;

    if (leftMost->leftNBR != NULL) {
      leftMost = leftMost->leftNBR;
    } else {
      leftMost = leftMost->nextVersion;
    }
  }
  return leftMost;
}

static bool
isAllVersionNodeLeftMost(HitMapNode *node)
{
  u32 ver = node->version;
  do {
    if(node->leftNBR != NULL) {
      return false;
    }
    else {
      node = node->nextVersion;
    }
  } while(ver != node->version);
  return true;
}


static void
getFirstVerNode(HitMapNode **first)
{
  assert(*first != NULL);
  HitMapNode *node = *first;

  u32 ver = (*first)->version;
  do {
    if((*first)->version > node->version)
      *first = node;
    node = node->nextVersion;
  } while(ver != node->version);
}

static HitMapBufHash *
initHitMapBufHTNode(
    u32 baddr,
    u32 eaddr,
    int minseq,
    int maxseq,
    u32 numOfAddr,
    HitMapNode *firstnode,
    u32 totalNode)
{
  HitMapBufHash *node = calloc(1, sizeof(HitMapBufHash) );
  assert(node != NULL);

  node->baddr = baddr;
  node->eaddr = eaddr;
  node->minseq = minseq;
  node->maxseq = maxseq;
  node->numOfAddr = numOfAddr;
  node->headNode = firstnode;
  node->totalNode = totalNode;
  return node;
}

static int
cmpHitMapBufHashNode(HitMapBufHash *l, HitMapBufHash *r)
{
  //    if(l->minseq < r->minseq) { return -1; }
  //    else if(l->minseq == r->minseq) { return 0; }
  //    else { return 1; }
  if(l->headNode->bufId < r->headNode->bufId) { return -1; }
  else if(l->headNode->bufId == r->headNode->bufId) { return 0; }
  else { return 1; }
}

static int
cmp_HM_bufhash_byseqn(HitMapBufHash *l, HitMapBufHash *r)
{
  if(l->minseq < r->minseq) { return -1; }
  else if(l->minseq == r->minseq) { return 0; }
  else { return 1; }
}

void
delHitMap(HitMapContext *hitmap)
{
  if(hitmap == NULL)
    return;

  for(int i = 0; i < hitmap->numOfBuf; i++) {
    delBufContext(hitmap->bufArray[i]);
    hitmap->bufArray[i] = NULL;
  }

  free(hitmap->bufArray);
  hitmap->bufArray = NULL;
  free(hitmap);
  printf("del HitMap\n");
}


void
printHitMap(HitMapContext *hitmap)
{
  if(hitmap == NULL) {
    fprintf(stderr, "printHitMap:%p\n", hitmap);
    return;
  }

  printf("HitMap: num of buf:%u maxSeqN:%u\n", hitmap->numOfBuf, hitmap->maxBufSeqN);
  for(int i = 0; i < hitmap->numOfBuf; i++) {
    printf("--------------------Buf Idx:%d\n", i);
    printHitMapBuf(hitmap->bufArray[i]);
    // printf("----------\nBuf Hitcnt In array:\n");
    // printHitMapBufHitCnt(hitmap->bufHitcntInArray[i]);
    // printf("----------\nBuf Hitcnt out array:\n");
    // printHitMapBufHitCnt(hitmap->bufHitcntOutArray[i]);
  }
}

void
printHitMapLit(HitMapContext *hitmap)
{
  if(hitmap == NULL) {
    fprintf(stderr, "printHitMapLit:%p\n", hitmap);
    return;
  }

  printf("HitMap Summary: TPMBufHTPtr:%p HitMapNodeHTPtr:%p maxBufSeqN:%u num of Bufs:%u buf context ary ptr:%p\n",
      hitmap->tpmBuf, hitmap->hitMapNodeHT, hitmap->maxBufSeqN, hitmap->numOfBuf, hitmap->bufArray);
}

void
printHitMapBuf(BufContext *hitMapBuf)
{
  if(hitMapBuf == NULL) {
    printf("HitMapBuf:%p\n", hitMapBuf);
    return;
  }
  printf("----------\nHitMapBuf: num of addr:%u\n", hitMapBuf->numOfAddr);
  for(int i = 0; i < hitMapBuf->numOfAddr; i++) {
    printf("HitMapBuf addr:%p\n", hitMapBuf->addrArray[i]);
    printHitMapNodeAllVersion(hitMapBuf->addrArray[i]);
  }
}

// void
// printHitMapBufHitCnt(BufHitcntCtxt *bufHitcntCtxt)
// {
//   if(bufHitcntCtxt == NULL) { return; }
//   printf("HitMap Buf Hitcnt: num of addr:%u\n", bufHitcntCtxt->numOfAddr);
//   for(int i = 0; i < bufHitcntCtxt->numOfAddr; i++) {
//     printf("addr Hitcnt:%u\n", *(bufHitcntCtxt->addrHitcntArray[i]) );
//   }
// }

void
printOneHitMapBufHash(HitMapBufHash *buf)
{
  if(buf != NULL) {
    printf("begin:0x%-8x end:0x%-8x sz:%-4u numofaddr:%-4u minseq:%-7d maxseq:%-7d diffseq:%-7d bufID:%u total nodes:%u\n",
        buf->baddr, buf->eaddr, buf->eaddr - buf->baddr,
        buf->numOfAddr, buf->minseq, buf->maxseq, (buf->maxseq - buf->minseq),
        buf->headNode->bufId, buf->totalNode);
  }
}


void
printHitMapBufHash(HitMapBufHash *hitMapBufHash)
{
  HitMapBufHash *buf, *tmp;
  int bufCnt = 0;
  u32 avg_node, minNode, maxNode, totalNode;

  bufCnt = HASH_CNT(hh_hmBufHash, hitMapBufHash);
  printf("---------------------\ntotal hit map buffer:%d - minimum buffer size:%u\n", bufCnt, 8);

  totalNode = 0;
  minNode = hitMapBufHash->totalNode;
  maxNode = hitMapBufHash->totalNode;

  HASH_ITER(hh_hmBufHash, hitMapBufHash, buf, tmp) {
    printf("begin:0x%-8x end:0x%-8x sz:%-4u numofaddr:%-4u minseq:%-7d maxseq:%-7d diffseq:%-7d bufID:%u total nodes:%u\n",
        buf->baddr, buf->eaddr, buf->eaddr - buf->baddr,
        buf->numOfAddr, buf->minseq, buf->maxseq, (buf->maxseq - buf->minseq),
        buf->headNode->bufId, buf->totalNode);
    assert(isAllHMNodeSameBufID(buf->headNode->bufId, buf->headNode) == true);
    print_HM_all_buf_node(buf->headNode);

    if(buf->totalNode < minNode)
      minNode = buf->totalNode;
    if(buf->totalNode > maxNode)
      maxNode = buf->totalNode;
    totalNode += buf->totalNode;
  }
  printf("minimum num of node:%u - maximum num of node:%u - total num of node:%u "
      "- total buf:%u - avg num of node:%u\n",
      minNode, maxNode, totalNode, bufCnt, totalNode / bufCnt);
}

void print_hitmap_source(HitMapContext *hitmap)
{
  HitMapBufNodePtr2NodeHashTable *nodeHash;
  HitMapBufHash *bufHashHead = NULL, *bufHash, *bufFound;
  HitMapNode *node;

  nodeHash = hitmap->hitMapNodeHT;
  printf("--------------------\nHitMap Source\n");
  for(; nodeHash != NULL; nodeHash = nodeHash->hh_hitMapBufNode2NodeHT.next) {
    node = nodeHash->toHitMapNode;
    if(node ->lastUpdateTS < 0)
    {
      u32 baddr = node->addr;
        bufHash = initHitMapBufHTNode(node->addr, node->addr+node->bytesz,
                                      node->lastUpdateTS, node->lastUpdateTS, 1, node, 1);
        HASH_FIND(hh_hmBufHash, bufHashHead, &baddr, 4, bufFound);
        if(bufFound == NULL)
        {
          HASH_ADD(hh_hmBufHash, bufHashHead, baddr, 4, bufHash);
        }
        else { free(bufHash); bufHash = NULL; }
    }
  }

  HASH_SRT(hh_hmBufHash, bufHashHead, cmp_HM_bufhash_byseqn);
  HASH_ITER(hh_hmBufHash, bufHashHead, bufHash, bufFound) {
    node = bufHash->headNode;
    printHitMapNodeLit(node);
    HASH_DELETE(hh_hmBufHash, bufHashHead, bufHash);
    free(bufHash);
  }
}

static BufContext *
initBufContext(
    TPMContext *tpm,
    HitMapContext *hitMap,
    TPMBufHashTable *buf)
{
  BufContext *bufCtxt;
  u32 numOfAddr;

  bufCtxt = calloc(1, sizeof(BufContext));
  assert(bufCtxt != NULL);

  numOfAddr= buf->numOfAddr;
  bufCtxt->numOfAddr = numOfAddr;
  bufCtxt->addrArray = calloc(1, sizeof(HitMapNode *) * numOfAddr);
  for(int i = 0; i < numOfAddr; i++)
    bufCtxt->addrArray[i] = NULL;

  return bufCtxt;
}

// static BufHitcntCtxt *
// initBufHitCntCtxt(TPMBufHashTable *buf)
// {
//   BufHitcntCtxt *bufHitCntCtxt;
//   u32 numOfAddr;

//   bufHitCntCtxt = calloc(1, sizeof(BufHitcntCtxt) );
//   assert(bufHitCntCtxt != NULL);

//   numOfAddr = buf->numOfAddr;
//   bufHitCntCtxt->numOfAddr = numOfAddr;

// #if defined ENV32
//   // printf("init buf hit count context 32 bit\n");
//   bufHitCntCtxt->addrHitcntArray = calloc(1, sizeof(u32) * numOfAddr);
// #elif defined ENV64
//   // printf("init buf hit count context 64 bit\n");
//   bufHitCntCtxt->addrHitcntArray = calloc(1, sizeof(u64) * numOfAddr);
// #endif
//   assert(bufHitCntCtxt->addrHitcntArray != NULL);

//   for(int i = 0; i < numOfAddr; i++) {
//     bufHitCntCtxt->addrHitcntArray[i] = 0;
//   }

//   return bufHitCntCtxt;
// }

static void
buildBufContext(
    TPMContext *tpm,
    HitMapContext *hitMap,
    TPMBufHashTable *buf,
    u32 *nodeVisitIdx)
{
  // printf("----------\nbegin addr:0x%-8x end addr:0x%-8x sz:%u numofaddr:%-2u minseq:%d maxseq:%d diffseq:%d bufID:%u\n",
  //         buf->baddr, buf->eaddr, buf->eaddr - buf->baddr,
  //         buf->numOfAddr, buf->minseq, buf->maxseq, (buf->maxseq - buf->minseq), buf->headNode->bufid);
  // printMemNode(buf->headNode);

  TPMNode2 *bufHead = buf->headNode;
  while(bufHead != NULL) {
    // printMemNodeLit(bufHead);
    buildHitMapAddr(tpm, hitMap, bufHead, nodeVisitIdx);
    bufHead = bufHead->rightNBR;
  }
}

static void
delBufContext(BufContext *bufCtxt)
{
  if(bufCtxt == NULL)
    return;

  free(bufCtxt->addrArray);
  bufCtxt->addrArray = NULL;
  free(bufCtxt);
}

static void
buildHitMapAddr(
    TPMContext *tpm,
    HitMapContext *hitMap,
    TPMNode2 *headNode,
    u32 *nodeVisitIdx)
{
  if(hitMap == NULL || headNode == NULL){
    fprintf(stderr, "hitMap:%p headNode:%p\n", hitMap, headNode);
    return;
  }
  else {
    if(headNode->version != 0) {
      fprintf(stderr, "headnode version:%u\n", headNode->version);
      return;
    }
  }
  // printMemNode(headNode);
  u32 currVersion = headNode->version;

  do {
    if(headNode->lastUpdateTS < 0) {
      bufnodePropgt2HitMapNode(tpm, headNode, hitMap, nodeVisitIdx);
      (*nodeVisitIdx)++;
      //    printf("node visit index:%u\n", *nodeVisitIdx);
    }
    headNode = headNode->nextVersion;
  } while (currVersion != headNode->version);
}

static void
assignHitMapBufID(HitMapBufHash *headBuf)
{
  assert(headBuf != NULL);
  HitMapBufHash *headBufHash = headBuf;

  u32 bufID = 1;
  for(; headBufHash != NULL; headBufHash = headBufHash->hh_hmBufHash.next) {
    HitMapNode *headNode = headBufHash->headNode;
    assert(headBufHash->baddr == headNode->addr);

    while(headNode != NULL) {
      u32 ver = headNode->version;
      do {
        headNode->bufId = bufID;
        headNode = headNode->nextVersion;
      } while(ver != headNode->version);

      headNode = headNode->rightNBR;
    }
    // assert( (headNode->addr + headNode->bytesz) == headBufHash->eaddr);
    bufID++;
  }
}

static int
initHitMapBufHitCntAray(HitMapContext *hitMap)
{
  if(hitMap != NULL && hitMap->hitMapBufCtxt != NULL) {
    u32 numOfBuf = hitMap->hitMapBufCtxt->numOfBuf;
    hitMap->inHitCntBufAry = calloc(sizeof(u32 *), numOfBuf);
    hitMap->outHitCntBufAry = calloc(sizeof(u32 *), numOfBuf);
    if(hitMap->inHitCntBufAry != NULL && hitMap->outHitCntBufAry != NULL)
      return 0;
  }
  fprintf(stderr, "initHitMapBufHitCntAray: fails init\n");
  return -1;
}

static int
createOneHMBufHitCntAry(
    u32 bufIdx,
    u32 numOfBuf,
    HitMapBufHash *buf,
    HitMapContext *hitMap)
// Returns
//  0: success
//  <0: fail
{
  if(bufIdx < numOfBuf &&
     buf != NULL && hitMap != NULL) {
    u32 bufSz = buf->eaddr - buf->baddr;
    HitMapNode *node;

    hitMap->inHitCntBufAry[bufIdx] = calloc(sizeof(u32), bufSz);
    hitMap->outHitCntBufAry[bufIdx] = calloc(sizeof(u32), bufSz);
    assert(hitMap->inHitCntBufAry != NULL);
    assert(hitMap->outHitCntBufAry != NULL);

    // printf("-----\n");
    // printOneHitMapBufHash(buf);
    // iterates each version of each address
    node = buf->headNode;
    assert(node->addr == buf->baddr);
    while(node != NULL) {
      u32 ver = node->version;
      do {
        /// printHitMapNodeLit(node);
        assert(node->addr >= buf->baddr && node->addr + node->bytesz <= buf->eaddr);
        if(updateHMNodeHitCnt(node, hitMap->inHitCntBufAry[bufIdx], hitMap->outHitCntBufAry[bufIdx], buf->baddr, buf->eaddr) < 0)
          goto error;

        node = node->nextVersion;
      } while(ver != node->version);

      // if(node->rightNBR == NULL)
      //   assert(node->addr + node->bytesz == buf->eaddr);

      node = node->rightNBR;
    }
    return 0;
  } else { goto error; }

error:
  fprintf(stderr, "createOneHitMapBufHitCntAry: error\n");
  return -1;
}

static int
updateHMNodeHitCnt(
    HitMapNode *node,
    u32 *inBufHitCntAry,
    u32 *outBufHitCntAry,
    u32 bufStart,
    u32 bufEnd   )
{
  if(node != NULL && inBufHitCntAry != NULL && outBufHitCntAry != NULL) {
//    printf("-----\nHitMap Buf: start:%x end:%x\n", bufStart, bufEnd);
//    printf("HMNode: addr:%x version:%u byteSz:%u inHitCnt:%u outHitCnt:%u\n",
//           node->addr, node->version, node->bytesz, node->hitcntIn, node->hitcntOut);

    if(node->addr < bufStart || node->addr + node->bytesz > bufEnd)
      return 0;

    u32 byteIdxStart = node->addr - bufStart;
    for(u32 byteSz = 0; byteSz < node->bytesz; byteSz++ ) {
      u32 byteIdx = byteIdxStart+byteSz;
      assert(byteIdx < bufEnd - bufStart);

      // u32 avgInHitCnt = node->hitcntIn / node->bytesz; // SUPRESS
      // inBufHitCntAry[byteIdx] += avgInHitCnt;
      inBufHitCntAry[byteIdx] += node->hitcntIn;  /* we don't use the avg hit count 
      due to a 4-byte src node 's out hit count is 4, indicates all its 4 bytes can propagate 
      to 4 other bytes. It's not correct to avg. */

      // u32 avgOutHitCnt = node->hitcntOut / node->bytesz; // SUPRESS
      // outBufHitCntAry[byteIdx] += avgOutHitCnt;
      outBufHitCntAry[byteIdx] += node->hitcntOut;  // same reason here

      // printf("avg IN hit count:%u avg Out hit count:%u\n", avgInHitCnt, avgOutHitCnt);
//      printf("update HMNode of buf hit count array: in:%u out:%u\n", inBufHitCntAry[byteIdx], outBufHitCntAry[byteIdx]);
    }
    return 0;
  }
  else {
    fprintf(stderr, "updateHMNodeHitCnt: error: node:%p inbBufHitCntAry:%p outBufHitCntAry:%p\n",
            node, inBufHitCntAry, outBufHitCntAry);
    return -1;
  }
}

static void
printOneHMBufHitCntAry(
    u32 *bufHitCntAry,
    u32 bufStart,
    u32 bufEnd)
{
  if(bufHitCntAry != NULL && bufStart > 0 && bufEnd > 0) {
    assert(bufEnd > bufStart);
    u32 bufSz = bufEnd - bufStart;
    u32 byteIdx = 0;
    for(; byteIdx < bufSz; byteIdx++) {
      printf("buf hit cnt: byteIdx:%u hitCnt:%u\n", byteIdx, bufHitCntAry[byteIdx]);
    }
  }
}

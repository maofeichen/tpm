#include "hitmappropagate.h"
#include <assert.h>

/* HitMap node propagate */
/* HitMap Transition hash table operation */
static void
add2HitTransitionHT(HitTransitionHashTable **hitTransitionht, HitTransition *toTrans);

static HitTransitionHashTable*
findInHitTransitionHT(HitTransitionHashTable *hitTransitionht, HitTransition *hitTrans);

static void
delHitTransitionHT(HitTransitionHashTable **hitTransitionht);

static void
countHitTransitionHT(HitTransitionHashTable *hitTransitionht);

/* HitMap node hash */
static void
add2HitMapNodeHash(
    HitMapNodeHash **hitMapNodeHash,
    HitMapNode *hmNode);

static HitMapNodeHash *
findInHitMapNodeHash(
    HitMapNodeHash *hitMapNodeHash,
    HitMapNode *hmNode);

static void
delHitMapNodeHash(HitMapNodeHash **hitMapNodeHash);

static void
countHitMapNodeHash(HitMapNodeHash *hitMapNodeHash);

/* HitMap Transition stack */
static void
stackHitTransPush(
    HitTransition *trans,
    StackHitTransitionItem **stackTransTop,
    u32 *stackTransCnt);

static HitTransition *
stackHitTransPop(
    StackHitTransitionItem **stackTransTop,
    u32 *stackTransCnt);

static void
stackHitTransDisplay(
    StackHitTransitionItem *stackTransTop,
    u32 stackTransCnt);

static void
stackHitTransPopAll(
    StackHitTransitionItem **stackTransTop,
    u32 *stackTransCnt);

static bool
isStackHitTransEmpty(StackHitTransitionItem *stackTransTop);

static void
printHitTransitionNode(StackHitTransitionItem *transNode);

/* HitMap node stack */
static void
stackHitMapNodePush(HitMapNode *hmNode, StackHitMapNode **stackHMNodeTop, u32 *stackHMNodeCnt);

static HitMapNode *
stackHitMapNodePop(StackHitMapNode **stackHMNodeTop, u32 *stackHMNodeCnt);

static void
stackHitMapNodeDisplay(StackHitMapNode *stackHMNodeTop, u32 stackHMNodeCnt);

static void
stackHitMapNodePopAll(StackHitMapNode **stackHMNodeTop, u32 *stackHMNodeCnt);

static bool
isStackHitMapNodeEmpty(StackHitMapNode *stackHMNodeTop);

static int
dfsHitMapNodePropagate(
    HitMapNode *srcnode,
    HitMapContext *hitMap,
    HitMapAddr2NodeItem *hmAddr2NodeItem,
    u32 dstAddrStart,
    u32 dstAddrEnd,
    int dstMinSeqN,
    int dstMaxSeqN);

static void
storeAllUnvisitHitTransChildren(
    HitTransitionHashTable **hitTransitionht,
    HitTransition *firstChild,
    int maxseq,
    StackHitTransitionItem **stackHitTransTop,
    u32 *stackHitTransCnt);

static bool
isHitTransitionVisited(
    HitTransitionHashTable *hitTransitionht,
    HitTransition *hitTransition);

static void
markVisitHitTransition(
    HitTransitionHashTable **hitTransitionht,
    HitTransition *hitTransition);

/* dfs 2nd version */
static int
dfs2_HitMapNodePropagate(
    HitMapNode *srcnode,
    HitMapContext *hitMap,
    HitMapAddr2NodeItem *hmAddr2NodeItem,
    u32 dstAddrStart,
    u32 dstAddrEnd,
    int dstMinSeqN,
    int dstMaxSeqN);

static void
storeUnvisitHitTransChildren(
    HitMapNodeHash **hitMapNodeHash,
    HitTransition *firstChild,
    int maxseq,
    StackHitTransitionItem **stackHitTransTop,
    u32 *stackHitTransCnt);

static bool
isHitMapNodeVisited(
    HitMapNodeHash *hitMapNodeHash,
    HitMapNode *hmNode);

static void
markVisitHitMapNode(
    HitMapNodeHash **hitMapNodeHash,
    HitMapNode *hmNode);

/* dfs 3rd version */
static int
dfs3_HitMapNodePropagate(
    HitMapNode *srcnode,
    HitMapContext *hitMap,
    HitMapAddr2NodeItem *hmAddr2NodeItem,
    u32 dstAddrStart,
    u32 dstAddrEnd,
    int dstMinSeqN,
    int dstMaxSeqN);

static void
storeUnvisitHitMapNodeChildren(
    HitMapNodeHash *hitMapNodeHash,
    HitMapNode *farther,
    u32 currSeqN,
    int maxSeq,
    StackHitMapNode **stackHMNodeTop,
    u32 *stackHMNodeCnt);

/* dfs search reverse */
static int
dfs_HitMapNodePropgtReverse(
    HitMapNode *srcnode,
    HitMapContext *hitMap,
    HitMapAddr2NodeItem **hitMapAddr2NodeAry,
    u32 srcAddrStart,
    u32 srcAddrEnd,
    int srcMinSeqN,
    int srcMaxSeqN);

static u32
getMaxHitTransSeqN(HitMapNode *srcNode);

static void
storeUnvisitHMNodeChildrenReverse(
    HitMapNodeHash *hitMapNodeHash,
    HitMapNode *farther,
    u32 currSeqN,
    int minSeqN,
    StackHitMapNode **stackHMNodeTop,
    u32 *stackHMNodeCnt);

/* dfs search HitMap to build buffer hit count array*/
static int
dfsHitMapNodePropgtOfBuildBufHitCntAry(
    // #ifdef ENV64
    //         u64 *bufHitCntAry,
    // #else
    //         u32 *bufHitCntAry,
    // #endif
    u8 *bufHitCntAry,
    u32 numOfBuf,
    HitMapNode *srcNode);

static void
storeHitTransChildren(
    HitTransitionHashTable *visitHitTransHash,
    HitMapNode *farther,
    u32 currSeqN,
    StackHitTransitionItem **stackHitTransTop,
    u32 *stackHitTransCnt);

static void
updateBufHitCntArray(
    u8 *bufHitCntAry,
    u32 numOfBuf,
    StackHitMapNode *stackHMNodeTop);

int
hitMapNodePropagate(
    HitMapNode *srcnode,
    HitMapContext *hitMap,
    HitMapAddr2NodeItem *hmAddr2NodeItem,
    u32 dstAddrStart,
    u32 dstAddrEnd,
    int dstMinSeqN,
    int dstMaxSeqN)
// Returns:
//  >= 0: num of hitmap nodes that the srcnode can propagate to
//  <0: error
{
  // return dfsHitMapNodePropagate(srcnode, hitMap, hmAddr2NodeItem, dstAddrStart, dstAddrEnd, dstMinSeqN, dstMaxSeqN);
  // return dfs2_HitMapNodePropagate(srcnode, hitMap, hmAddr2NodeItem, dstAddrStart, dstAddrEnd, dstMinSeqN, dstMaxSeqN);
  return dfs3_HitMapNodePropagate(srcnode, hitMap, hmAddr2NodeItem, dstAddrStart, dstAddrEnd, dstMinSeqN, dstMaxSeqN);
}

int
hitMapNodePropagateReverse(
    HitMapNode *srcnode,
    HitMapContext *hitMap,
    HitMapAddr2NodeItem **hitMapAddr2NodeAry,
    u32 srcAddrStart,
    u32 srcAddrEnd,
    int srcMinSeqN,
    int srcMaxSeqN)
{
  return dfs_HitMapNodePropgtReverse(srcnode, hitMap, hitMapAddr2NodeAry,
      srcAddrStart, srcAddrEnd, srcMinSeqN, srcMaxSeqN);
}

int
hitMapNodePropgtOfBuildBufHitCntAry(
    // #ifdef ENV64
    //         u64 *bufHitCntAry,
    // #else
    //         u32 *bufHitCntAry,
    // #endif
    u8 *bufHitCntAry,
    u32 numOfBuf,
    HitMapNode *addrHead)
{
  // printf("hitMapNodePropgtOfBuildBufHitCntAry: bufHitCntAry:%p\n", bufHitCntAry);
  return dfsHitMapNodePropgtOfBuildBufHitCntAry(bufHitCntAry, numOfBuf, addrHead);
}


int
cmpHitMapAddr2NodeItem(HitMapAddr2NodeItem *l, HitMapAddr2NodeItem *r)
{
  if(l->addr < r->addr) { return -1; }
  else if(l->addr == r->addr) {
    if(l->node->version < r->node->version) { return -1; }
    // else if(l->node->version > r->node->version) { return 1; }
    else { return 1; }
  }
  else { return 1; }
}

static void
add2HitTransitionHT(HitTransitionHashTable **hitTransitionht, HitTransition *toTrans)
{
  HitTransitionHashTable *t = NULL;
  t = findInHitTransitionHT(*hitTransitionht, toTrans);
  if(t == NULL) {
    t = calloc(1, sizeof(HitTransitionHashTable) );
    assert(t != NULL);

    t->toTrans = toTrans;
    HASH_ADD(hh_hitTrans, *hitTransitionht, toTrans, 4, t);
  }
}

static HitTransitionHashTable*
findInHitTransitionHT(HitTransitionHashTable *hitTransitionht, HitTransition *hitTrans)
{
  HitTransitionHashTable *s = NULL;
  HASH_FIND(hh_hitTrans, hitTransitionht, &hitTrans, 4, s);
  return s;
}

static void
delHitTransitionHT(HitTransitionHashTable **hitTransitionht)
{
  HitTransitionHashTable *curr, *tmp;
  HASH_ITER(hh_hitTrans, *hitTransitionht, curr, tmp) {
    HASH_DELETE(hh_hitTrans, *hitTransitionht, curr);
    free(curr);
  }
}

static void
countHitTransitionHT(HitTransitionHashTable *hitTransitionht)
{
  u32 numOfHitTrans = 0;
  numOfHitTrans = HASH_CNT(hh_hitTrans, hitTransitionht);
  printf("num of hit trans:%u\n", numOfHitTrans);
}

static void
add2HitMapNodeHash(
    HitMapNodeHash **hitMapNodeHash,
    HitMapNode *hmNode)
{
  HitMapNodeHash *hmHash;
  hmHash = findInHitMapNodeHash(*hitMapNodeHash, hmNode);
  if(hmHash == NULL) {
    hmHash = calloc(1, sizeof(HitMapNodeHash) );
    assert(hmHash != NULL);
    hmHash->toHitMapNode = hmNode;
    HASH_ADD(hh_hitMapNode, *hitMapNodeHash, toHitMapNode, 4, hmHash);
  }
}

static HitMapNodeHash *
findInHitMapNodeHash(
    HitMapNodeHash *hitMapNodeHash,
    HitMapNode *hmNode)
{
  HitMapNodeHash *hmHash = NULL;
  HASH_FIND(hh_hitMapNode, hitMapNodeHash, &hmNode, 4, hmHash);
  return hmHash;
}

static void
delHitMapNodeHash(HitMapNodeHash **hitMapNodeHash)
{
  HitMapNodeHash *curr, *tmp;
  HASH_ITER(hh_hitMapNode, *hitMapNodeHash, curr, tmp) {
    HASH_DELETE(hh_hitMapNode, *hitMapNodeHash, curr);
    free(curr);
  }
}

static void
countHitMapNodeHash(HitMapNodeHash *hitMapNodeHash) {}

static void
stackHitTransPush(
    HitTransition *hitTrans,
    StackHitTransitionItem **stackHitTransTop,
    u32 *stackHitTransCnt)
{
  StackHitTransitionItem *i = calloc(1, sizeof(StackHitTransitionItem));
  i->transition = hitTrans;
  i->currSeqN = 0;

  i->next = *stackHitTransTop;
  *stackHitTransTop = i;
  (*stackHitTransCnt)++;
}

static HitTransition *
stackHitTransPop(
    StackHitTransitionItem **stackHitTransTop,
    u32 *stackHitTransCnt)
{
  StackHitTransitionItem *toDel;
  HitTransition *hitTrans = NULL;

  if(*stackHitTransTop != NULL) {
    toDel = *stackHitTransTop;
    *stackHitTransTop = toDel->next;

    hitTrans = toDel->transition;
    free(toDel);
    (*stackHitTransCnt)--;
  }
  return hitTrans;
}

static void
stackHitTransDisplay(
    StackHitTransitionItem *stackHitTransTop,
    u32 stackHitTransCnt)
{
  if(stackHitTransCnt > 0)
    printf("--------------------\ntotal transitions in stack:%u\n", stackHitTransCnt);

  while(stackHitTransTop != NULL) {
    printHitMapNode(stackHitTransTop->transition->child);
    stackHitTransTop = stackHitTransTop->next;
  }
}

static void
stackHitTransPopAll(
    StackHitTransitionItem **stackHitTransTop,
    u32 *stackHitTransCnt)
{
  while(*stackHitTransTop != NULL) {
    stackHitTransPop(stackHitTransTop, stackHitTransCnt);
  }
}

static bool
isStackHitTransEmpty(StackHitTransitionItem *stackHitTransTop)
{
  if(stackHitTransTop != NULL)
    return false;
  else
    return true;
}

static void
printHitTransitionNode(StackHitTransitionItem *transNode)
{

}

static void
stackHitMapNodePush(HitMapNode *hmNode, StackHitMapNode **stackHMNodeTop, u32 *stackHMNodeCnt)
{
  StackHitMapNode *s = calloc(1, sizeof(StackHitMapNode) );
  assert(s != NULL);

  s->hmNode = hmNode;
  s->taintBy = NULL;
  s->next = *stackHMNodeTop;
  *stackHMNodeTop = s;
  (*stackHMNodeCnt)++;
}

static HitMapNode *
stackHitMapNodePop(StackHitMapNode **stackHMNodeTop, u32 *stackHMNodeCnt)
{
  StackHitMapNode *toDel;
  HitMapNode *hmNode = NULL;

  if(*stackHMNodeTop != NULL) {
    toDel = *stackHMNodeTop;
    *stackHMNodeTop = toDel->next;
    hmNode = toDel->hmNode;
    free(toDel);
    (*stackHMNodeCnt)--;
  }
  return hmNode;
}

static void
stackHitMapNodeDisplay(StackHitMapNode *stackHMNodeTop, u32 stackHMNodeCnt)
{
  if(stackHMNodeCnt > 0)
    printf("--------------------\ntotal hit map node in stack:%u\n", stackHMNodeCnt);

  while(stackHMNodeTop != NULL) {
    printHitMapNodeLit(stackHMNodeTop->hmNode);
    stackHMNodeTop = stackHMNodeTop->next;
  }
}

static void
stackHitMapNodePopAll(StackHitMapNode **stackHMNodeTop, u32 *stackHMNodeCnt)
{
  while(*stackHMNodeTop != NULL) {
    stackHitMapNodePop(stackHMNodeTop, stackHMNodeCnt);
  }
}

static bool
isStackHitMapNodeEmpty(StackHitMapNode *stackHMNodeTop)
{
  if(stackHMNodeTop == NULL)  { return true; }
  else { return false; }
}


/* HitMap node propagate */

static int
dfsHitMapNodePropagate(
    HitMapNode *srcnode,
    HitMapContext *hitMap,
    HitMapAddr2NodeItem *hmAddr2NodeItem,
    u32 dstAddrStart,
    u32 dstAddrEnd,
    int dstMinSeqN,
    int dstMaxSeqN)
{
  if(srcnode == NULL) {
    fprintf(stderr, "dfsHitMapNodePropagate: hit map srcnode:%p\n", srcnode);
    return -1;
  }

  // printf("---------------\nsource:");
  // printHitMapNode(srcnode);
  // printf("dst max seqN:%u\n", dstMaxSeqN);

  HitTransitionHashTable *markVisitHitTransHT = NULL;

  StackHitTransitionItem *stackHitTransTop = NULL;
  u32 stackHitTransCnt = 0;

  HitTransition *sourceHitTrans = srcnode->firstChild;
  if(sourceHitTrans == NULL) {
    // printf("given source node is a leaf\n");
    // printHitMapNode(srcnode);
    return 0;
  }

  storeAllUnvisitHitTransChildren(&markVisitHitTransHT, sourceHitTrans, dstMaxSeqN,
      &stackHitTransTop, &stackHitTransCnt);
  // stackHitTransDisplay(stackHitTransTop, stackHitTransCnt);

  while(!isStackHitTransEmpty(stackHitTransTop) ) {
    HitTransition *popTrans = stackHitTransPop(&stackHitTransTop, &stackHitTransCnt);
    HitMapNode *popDstHitMapNode = popTrans->child;

    if(popDstHitMapNode->bufId > 0) {
      // printHitMapNodeLit(popDstHitMapNode);
    }

    if(popDstHitMapNode->bufId > 0
        && popDstHitMapNode->addr >= dstAddrStart && popDstHitMapNode->addr <= dstAddrEnd
        && popDstHitMapNode->lastUpdateTS >= dstMinSeqN && popDstHitMapNode->lastUpdateTS <= dstMaxSeqN) {
      // printHitMapNodeLit(popDstHitMapNode);

      HitMapAddr2NodeItem *find;
      HASH_FIND(hh_hmAddr2NodeItem, hmAddr2NodeItem->subHash, &popDstHitMapNode, 4, find);
      if(find == NULL) {
        HitMapAddr2NodeItem *toHitMapNodeItem = createHitMapAddr2NodeItem(popDstHitMapNode->addr, popDstHitMapNode, NULL, NULL);
        HASH_ADD(hh_hmAddr2NodeItem, hmAddr2NodeItem->subHash, node, 4, toHitMapNodeItem);
      }
    }

    storeAllUnvisitHitTransChildren(&markVisitHitTransHT, popDstHitMapNode->firstChild, dstMaxSeqN,
        &stackHitTransTop, &stackHitTransCnt);
    // stackHitTransDisplay(stackHitTransTop, stackHitTransCnt);

  }
  delHitTransitionHT(&markVisitHitTransHT);
  stackHitTransPopAll(&stackHitTransTop, &stackHitTransCnt);

  HASH_SRT(hh_hmAddr2NodeItem, hmAddr2NodeItem->subHash, cmpHitMapAddr2NodeItem);
  return 0;
}

static void
storeAllUnvisitHitTransChildren(
    HitTransitionHashTable **hitTransitionht,
    HitTransition *firstChild,
    int maxseq,
    StackHitTransitionItem **stackHitTransTop,
    u32 *stackHitTransCnt)
{

  while(firstChild != NULL) {
    if(!isHitTransitionVisited(*hitTransitionht, firstChild)
        && firstChild->maxSeqNo <= maxseq) {
      stackHitTransPush(firstChild, stackHitTransTop, stackHitTransCnt);
      markVisitHitTransition(hitTransitionht, firstChild);
    }
    firstChild = firstChild->next;
  }
}

static bool
isHitTransitionVisited(
    HitTransitionHashTable *hitTransitionht,
    HitTransition *hitTransition)
{
  if(hitTransition == NULL)
    return false;

  HitTransitionHashTable *found = NULL;

  found = findInHitTransitionHT(hitTransitionht, hitTransition);
  if(found != NULL)
    return true;
  else
    return false;
}

static void
markVisitHitTransition(
    HitTransitionHashTable **hitTransitionht,
    HitTransition *hitTransition)
{
  if (hitTransitionht == NULL || hitTransition == NULL)
    return;

  add2HitTransitionHT(hitTransitionht, hitTransition);
}

static int
dfs2_HitMapNodePropagate(
    HitMapNode *srcnode,
    HitMapContext *hitMap,
    HitMapAddr2NodeItem *hmAddr2NodeItem,
    u32 dstAddrStart,
    u32 dstAddrEnd,
    int dstMinSeqN,
    int dstMaxSeqN)
// uses HitMap Node hash instead of Hit Transition hash as dfs
{
  if(srcnode == NULL) {
    fprintf(stderr, "dfsHitMapNodePropagate: hit map srcnode:%p\n", srcnode);
    return -1;
  }

  // printf("---------------\nsource:");
  // printHitMapNode(srcnode);
  // printf("dst max seqN:%u\n", dstMaxSeqN);

  HitMapNodeHash *visitNodeHash = NULL;

  StackHitTransitionItem *stackHitTransTop = NULL;
  u32 stackHitTransCnt = 0;

  HitTransition *sourceHitTrans = srcnode->firstChild;
  if(sourceHitTrans == NULL) {
    // printf("given source node is a leaf\n");
    // printHitMapNode(srcnode);
    return 0;
  }

  storeUnvisitHitTransChildren(&visitNodeHash, sourceHitTrans, dstMaxSeqN, &stackHitTransTop, &stackHitTransCnt);
  // stackHitTransDisplay(stackHitTransTop, stackHitTransCnt);

  while(!isStackHitTransEmpty(stackHitTransTop) ) {
    HitTransition *popTrans = stackHitTransPop(&stackHitTransTop, &stackHitTransCnt);
    HitMapNode *popDstHitMapNode = popTrans->child;

    if(popDstHitMapNode->bufId > 0) {
      // printHitMapNodeLit(popDstHitMapNode);
    }

    if(popDstHitMapNode->bufId > 0
        && popDstHitMapNode->addr >= dstAddrStart && popDstHitMapNode->addr <= dstAddrEnd
        && popDstHitMapNode->lastUpdateTS >= dstMinSeqN && popDstHitMapNode->lastUpdateTS <= dstMaxSeqN) {
      // printHitMapNodeLit(popDstHitMapNode);

      HitMapAddr2NodeItem *find;
      HASH_FIND(hh_hmAddr2NodeItem, hmAddr2NodeItem->subHash, &popDstHitMapNode, 4, find);
      if(find == NULL) {
        HitMapAddr2NodeItem *toHitMapNodeItem = createHitMapAddr2NodeItem(popDstHitMapNode->addr, popDstHitMapNode, NULL, NULL);
        HASH_ADD(hh_hmAddr2NodeItem, hmAddr2NodeItem->subHash, node, 4, toHitMapNodeItem);
      }
    }

    storeUnvisitHitTransChildren(&visitNodeHash, popDstHitMapNode->firstChild, dstMaxSeqN, &stackHitTransTop, &stackHitTransCnt);
    // stackHitTransDisplay(stackHitTransTop, stackHitTransCnt);
  }

  delHitMapNodeHash(&visitNodeHash);
  stackHitTransPopAll(&stackHitTransTop, &stackHitTransCnt);

  HASH_SRT(hh_hmAddr2NodeItem, hmAddr2NodeItem->subHash, cmpHitMapAddr2NodeItem);
  return 0;
}

static void
storeUnvisitHitTransChildren(
    HitMapNodeHash **hitMapNodeHash,
    HitTransition *firstChild,
    int maxSeq,
    StackHitTransitionItem **stackHitTransTop,
    u32 *stackHitTransCnt)
{
  while(firstChild != NULL) {
    HitMapNode *hmNode = firstChild->child;
    if(!isHitMapNodeVisited(*hitMapNodeHash, hmNode) && firstChild->maxSeqNo <= maxSeq) {
      stackHitTransPush(firstChild, stackHitTransTop, stackHitTransCnt);
      markVisitHitMapNode(hitMapNodeHash, hmNode);
    }
    else{
      // printf("hitMapNode had been visited %p addr:%x ver:%u\n", hmNode, hmNode->addr, hmNode->version);
    }
    firstChild = firstChild->next;
  }
}

static bool
isHitMapNodeVisited(
    HitMapNodeHash *hitMapNodeHash,
    HitMapNode *hmNode)
{
  if(hmNode == NULL)
    return false;

  HitMapNodeHash *found = NULL;
  found = findInHitMapNodeHash(hitMapNodeHash, hmNode);
  if(found != NULL) { return true; }
  else { return false; }
}

static void
markVisitHitMapNode(
    HitMapNodeHash **hitMapNodeHash,
    HitMapNode *hmNode)
{
  if(/* *hitMapNodeHash == NULL || */ hmNode == NULL)
    return;

  add2HitMapNodeHash(hitMapNodeHash, hmNode);
}


static int
dfs3_HitMapNodePropagate(
    HitMapNode *srcnode,
    HitMapContext *hitMap,
    HitMapAddr2NodeItem *hmAddr2NodeItem,
    u32 dstAddrStart,
    u32 dstAddrEnd,
    int dstMinSeqN,
    int dstMaxSeqN)
// uses hitMap node stack instead of Hit Transition Stack as dfs2
{
  if(srcnode == NULL) {
    fprintf(stderr, "dfsHitMapNodePropagate: hit map srcnode:%p\n", srcnode);
    return -1;
  }

  if(srcnode->firstChild == NULL) {
    // printf("given source node is a leaf\n");
    // printHitMapNode(srcnode);
    return 0;
  }
  // printf("---------------\nsource:");
  // printHitMapNode(srcnode);
  // printf("dst max seqN:%u\n", dstMaxSeqN);

  HitMapNodeHash *visitNodeHash = NULL;

  StackHitMapNode *stackHMNodeTop = NULL;
  u32 stackHMNodeCnt = 0;

  stackHitMapNodePush(srcnode, &stackHMNodeTop, &stackHMNodeCnt);
  stackHMNodeTop->currSeqN = 0;

  while(!isStackHitMapNodeEmpty(stackHMNodeTop) ) {
    u32 currSeqN = stackHMNodeTop->currSeqN;
    HitMapNode *popNode = stackHitMapNodePop(&stackHMNodeTop, &stackHMNodeCnt);
    markVisitHitMapNode(&visitNodeHash, popNode);

    if(popNode->bufId > 0) {
      // printHitMapNodeLit(popNode);
      // printf("curr seqN:%u\n", currSeqN);
    }

    if(popNode->bufId > 0
        && popNode->addr >= dstAddrStart && popNode->addr <= dstAddrEnd
        && popNode->lastUpdateTS >= dstMinSeqN && popNode->lastUpdateTS <= dstMaxSeqN) {
      // printHitMapNodeLit(popNode);

      srcnode->hitcntOut += popNode->bytesz;    // updates both src & dst nodes' hit count
      popNode->hitcntIn += srcnode->bytesz;

      HitMapAddr2NodeItem *find;
      HASH_FIND(hh_hmAddr2NodeItem, hmAddr2NodeItem->subHash, &popNode, 4, find);
      if(find == NULL) {
        HitMapAddr2NodeItem *toHitMapNodeItem = createHitMapAddr2NodeItem(popNode->addr, popNode, NULL, NULL);
        HASH_ADD(hh_hmAddr2NodeItem, hmAddr2NodeItem->subHash, node, 4, toHitMapNodeItem);
      }
    }

    storeUnvisitHitMapNodeChildren(visitNodeHash, popNode, currSeqN, dstMaxSeqN, &stackHMNodeTop, &stackHMNodeCnt);
  }
  delHitMapNodeHash(&visitNodeHash);

  HASH_SRT(hh_hmAddr2NodeItem, hmAddr2NodeItem->subHash, cmpHitMapAddr2NodeItem);
  return 0;
}

static void
storeUnvisitHitMapNodeChildren(
    HitMapNodeHash *hitMapNodeHash,
    HitMapNode *farther,
    u32 currSeqN,
    int maxSeq,
    StackHitMapNode **stackHMNodeTop,
    u32 *stackHMNodeCnt)
{
  HitTransition *firstChild = farther->firstChild;
  while(firstChild != NULL) {
    HitMapNode *childNode = firstChild->child;

    if(!isHitMapNodeVisited(hitMapNodeHash, childNode) &&
        currSeqN <= firstChild->minSeqNo && // enforce the increasing seqN policy
        firstChild->maxSeqNo <= maxSeq) {
      stackHitMapNodePush(childNode, stackHMNodeTop, stackHMNodeCnt);
      (*stackHMNodeTop)->currSeqN = firstChild->maxSeqNo; // should assign the maxSeqN of HitTransition
    }
    else{
      // printf("hitMapNode had been visited %p addr:%x ver:%u\n", childNode, childNode->addr, childNode->version);
    }
    firstChild = firstChild->next;
  }
}

static int
dfs_HitMapNodePropgtReverse(
    HitMapNode *srcnode,
    HitMapContext *hitMap,
    HitMapAddr2NodeItem **hitMapAddr2NodeAry,
    u32 srcAddrStart,
    u32 srcAddrEnd,
    int srcMinSeqN,
    int srcMaxSeqN)
{
  if(srcnode == NULL || hitMap == NULL || hitMapAddr2NodeAry == NULL) {
    fprintf(stderr, "dfs_HitMapNodePropgtReverse: invalid argument\n");
    return -1;
  }

  if(srcnode->taintedBy == NULL) { return 0; }

  // printf("---------------\nsource:");
  // printHitMapNode(srcnode);
  // printf("src min seqN:%d\n", srcMinSeqN);

  HitMapNodeHash *visitNodeHash = NULL;

  StackHitMapNode *stackHMNodeTop = NULL;
  u32 stackHMNodeCnt = 0;

  u32 traverseStep = 0;

  stackHitMapNodePush(srcnode, &stackHMNodeTop, &stackHMNodeCnt);
  stackHMNodeTop->currSeqN = getMaxHitTransSeqN(srcnode);

  while(!isStackHitMapNodeEmpty(stackHMNodeTop) ) {
    u32 currSeqN = stackHMNodeTop->currSeqN;
    HitMapNode *popNode = stackHitMapNodePop(&stackHMNodeTop, &stackHMNodeCnt);
    markVisitHitMapNode(&visitNodeHash, popNode);

    if(popNode->bufId > 0 &&
        popNode->addr >= srcAddrStart && popNode->addr <= srcAddrEnd &&
        popNode->lastUpdateTS >= srcMinSeqN && popNode->lastUpdateTS <= srcMaxSeqN) {
      u32 srcAddrIdx = getTPMBufAddrIdx(popNode->bufId, popNode->addr, hitMap->tpmBuf);
      // printf("src addr idx:%u\n", srcAddrIdx);
      // printHitMapNodeLit(popNode);

      HitMapAddr2NodeItem *findSrc, *findDst;
      HASH_FIND(hh_hmAddr2NodeItem, hitMapAddr2NodeAry[srcAddrIdx], &popNode, 4, findSrc);
      // assert(findSrc != NULL);
      if(findSrc != NULL) {
        HASH_FIND(hh_hmAddr2NodeItem, findSrc->subHash, &srcnode, 4, findDst);
        if(findDst == NULL) {
          HitMapAddr2NodeItem *toHitMapNodeItem = createHitMapAddr2NodeItem(srcnode->addr, srcnode, NULL, NULL);
          HASH_ADD(hh_hmAddr2NodeItem, findSrc->subHash, node, 4, toHitMapNodeItem);
        }
      }
    }

    storeUnvisitHMNodeChildrenReverse(visitNodeHash, popNode, currSeqN, srcMinSeqN, &stackHMNodeTop, &stackHMNodeCnt);
    traverseStep++;
  }

  delHitMapNodeHash(&visitNodeHash);
  // printf("traverse step:%u\n", traverseStep);
  return traverseStep;
}

static u32
getMaxHitTransSeqN(HitMapNode *srcNode)
// Returns
//  max seqN of all Hit Transitions of a given node
{
  u32 maxSeqN;
  HitTransition *child;

  assert(srcNode != NULL);
  child = srcNode->taintedBy;
  maxSeqN = child->maxSeqNo;
  while(child != NULL) {
    if(maxSeqN < child->maxSeqNo)
      maxSeqN = child->maxSeqNo;
    child = child->next;
  }
  return maxSeqN;
}

static void
storeUnvisitHMNodeChildrenReverse(
    HitMapNodeHash *hitMapNodeHash,
    HitMapNode *farther,
    u32 currSeqN,
    int minSeqN,
    StackHitMapNode **stackHMNodeTop,
    u32 *stackHMNodeCnt)
{
  HitTransition *firstChild = farther->taintedBy;
  while(firstChild != NULL) {
    HitMapNode *childNode = firstChild->child;
    // printHitMapNodeLit(childNode);
    // printHitMapTransition(firstChild);
    if(!isHitMapNodeVisited(hitMapNodeHash, childNode)
        && (int)(firstChild->minSeqNo) >= minSeqN
        && currSeqN >= firstChild->maxSeqNo ) {
      stackHitMapNodePush(childNode, stackHMNodeTop, stackHMNodeCnt);
      (*stackHMNodeTop)->currSeqN = firstChild->minSeqNo;
    }

    firstChild = firstChild->next;
  }
}

static int
dfsHitMapNodePropgtOfBuildBufHitCntAry(
    // #ifdef ENV64
    //         u64 *bufHitCntAry,
    // #else
    //         u32 *bufHitCntAry,
    // #endif
    u8 *bufHitCntAry,
    u32 numOfBuf,
    HitMapNode *srcNode)
{
  HitTransitionHashTable *visitHitTransHash = NULL;

  StackHitTransitionItem *stackHitTransTop = NULL;
  u32 stackHitTransCnt = 0;

  StackHitMapNode *stackHMNodeTop = NULL;
  u32 stackHMNodeCnt = 0;

  if(srcNode == NULL) {
    fprintf(stderr, "dfsHitMapNodePropgtOfBuildBufHitCntAry: src node:%p\n", srcNode);
    return -1;
  }
  if(srcNode->firstChild == NULL) { return 0; }

//  printf("-----dfsHitMapNodePropgtOfBuildBufHitCntAry\n");
//  printHitMapNodeLit(srcNode);
//  printf("dfsHitMapNodePropgtOfBuildBufHitCntAry: bufHitCntAry:%p\n", bufHitCntAry);

  stackHitMapNodePush(srcNode, &stackHMNodeTop, &stackHMNodeCnt);
  storeHitTransChildren(visitHitTransHash, srcNode, 0, &stackHitTransTop, &stackHitTransCnt);

  while(!isStackHitTransEmpty(stackHitTransTop) ) {
    HitTransition *topHitTrans = stackHitTransTop->transition;
    HitMapNode *topDstNode = topHitTrans->child;
    u32 currSeqN = stackHitTransTop->currSeqN;
    // printHitMapTransition(topHitTrans);

    if(isHitTransitionVisited(visitHitTransHash, topHitTrans) ) {
      assert(topDstNode == stackHMNodeTop->hmNode);
      stackHitMapNodePop(&stackHMNodeTop, &stackHMNodeCnt);

      topHitTrans->hasUpdateBufHitCnt = 1;
      stackHitTransPop(&stackHitTransTop, &stackHitTransCnt);
    }
    else { // new hit transition
      markVisitHitTransition(&visitHitTransHash, topHitTrans);

      stackHitMapNodePush(topDstNode, &stackHMNodeTop, &stackHMNodeCnt);
      stackHMNodeTop->taintBy = topHitTrans;
      // stackHitMapNodeDisplay(stackHMNodeTop, stackHMNodeCnt);
      // printf("hit map node stack sz:%u\n", stackHMNodeCnt);

      // stackHitMapNodeDisplay(stackHMNodeTop, stackHMNodeCnt);
      updateBufHitCntArray(bufHitCntAry, numOfBuf, stackHMNodeTop);
      // printHitMapNodeLit(topDstNode);

      if(topDstNode->firstChild == NULL) { // leaf node
        assert(topDstNode == stackHMNodeTop->hmNode);
        stackHitMapNodePop(&stackHMNodeTop, &stackHMNodeCnt);

        topHitTrans->hasUpdateBufHitCnt = 1;
        stackHitTransPop(&stackHitTransTop, &stackHitTransCnt);
      }
      else {
        storeHitTransChildren(visitHitTransHash, topDstNode, currSeqN, &stackHitTransTop, &stackHitTransCnt);
      }
    }
  }
  stackHitMapNodePopAll(&stackHMNodeTop, &stackHMNodeCnt);
  delHitTransitionHT(&visitHitTransHash);
  return 0;
}

static void
storeHitTransChildren(
    HitTransitionHashTable *visitHitTransHash,
    HitMapNode *farther,
    u32 currSeqN,
    StackHitTransitionItem **stackHitTransTop,
    u32 *stackHitTransCnt)
{
  if(farther == NULL)
    return;

  HitTransition *firstChild = farther->firstChild;
  while(firstChild != NULL) {
    if(!isHitTransitionVisited(visitHitTransHash, firstChild)
        && currSeqN <= firstChild->minSeqNo) { // enforces the increasing SeqN policy
      stackHitTransPush(firstChild, stackHitTransTop, stackHitTransCnt);
      (*stackHitTransTop)->currSeqN = firstChild->maxSeqNo;
    }
    firstChild = firstChild->next;
  }
}

static void
updateBufHitCntArray(
    u8 *bufHitCntAry,
    u32 numOfBuf,
    StackHitMapNode *stackHMNodeTop)
{
  u32 srcBufID, dstBufID;
  u32 oldBufID, newBufID;
  StackHitMapNode *secondTop;
  HitMapNode *dstNode;

  if(bufHitCntAry == NULL || stackHMNodeTop == NULL)
    return;

  // printf("updateBufHitCntArray: bufHitCntAry:%p\n", bufHitCntAry);
  secondTop = stackHMNodeTop->next;
  if(secondTop != NULL
      && stackHMNodeTop->hmNode->bufId == secondTop->hmNode->bufId) {
    return; // No need to update within same buffer
  }

  oldBufID = 0;
  dstNode = stackHMNodeTop->hmNode;
  dstBufID = stackHMNodeTop->hmNode->bufId;
  stackHMNodeTop = stackHMNodeTop->next;

  while(stackHMNodeTop != NULL) {
    srcBufID = stackHMNodeTop->hmNode->bufId;
    newBufID = srcBufID;
    if(srcBufID != dstBufID && srcBufID != oldBufID) {
      // handle root node exception, since root node does not has any tainted by
      if(stackHMNodeTop->hmNode->lastUpdateTS < 0 ||
          (stackHMNodeTop->taintBy != NULL &&
           stackHMNodeTop->taintBy->hasUpdateBufHitCnt == 0) ) {

        u32 srcBufIdx = srcBufID-1, dstBufIdx = dstBufID -1;
        // assert(srcBufIdx < numOfBuf);
        // assert(dstBufIdx < numOfBuf);
        if(srcBufIdx < numOfBuf && dstBufIdx < numOfBuf) {
//          printf("src buf ID:%u --> dst buf ID:%u size:%u\n", srcBufID, dstBufID, dstNode->bytesz);
          u8 currVal = bufHitCntAry[srcBufIdx*numOfBuf + dstBufIdx];
//          printf("before update: bufHitCntAry:%p plus offset:%p val:%d\n",
//                  bufHitCntAry, bufHitCntAry+(srcBufIdx*numOfBuf + dstBufIdx), currVal);

          /* updates src & dst node's hit cout, including direct and indirect. */
          stackHMNodeTop->hmNode->hitcntOut += dstNode->bytesz;
          dstNode->hitcntIn += stackHMNodeTop->hmNode->bytesz;
//          printHitMapNodeLit(stackHMNodeTop->hmNode);
//          printHitMapNodeLit(dstNode);

          /* Dbg: print out update hit count for a specific <src,dst> pair. 
           Disable temporarily. */
          // if(srcBufID == 6 && dstBufID == 7)
          //   printf("update 2D hit count array: src id:%-4u - dst id:%-4u - val:%u\n",
          //          srcBufID, dstBufID, dstNode->bytesz);

          if(currVal + dstNode->bytesz <= 255) {
            bufHitCntAry[srcBufIdx * numOfBuf + dstBufIdx] += dstNode->bytesz;
//            printf("after update: bufHitCntAry:%p plus offset:%p val:%d\n",
//                    bufHitCntAry, bufHitCntAry+(srcBufIdx*numOfBuf + dstBufIdx),
//                    bufHitCntAry[srcBufIdx * numOfBuf + dstBufIdx]);
//            printf("update 2D array: bufHitCntAry[ %u ][ %u ] += byte size: %u\n",
//                    srcBufIdx, dstBufIdx, dstNode->bytesz);
//            printf("current 2D array: bufHitCntAry[ %u ][ %u ]: %d\n",
//                srcBufIdx, dstBufIdx, bufHitCntAry[srcBufIdx*numOfBuf + dstBufIdx]);
          }
        }
      }
      // printf("src buf ID:%u --> dst buf ID:%u size:%u\n", srcBufID, dstBufID, dstNode->bytesz);
    }
    oldBufID = newBufID;
    stackHMNodeTop = stackHMNodeTop->next;
  }
}

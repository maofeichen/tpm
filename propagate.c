#include "propagate.h"
#include <stdbool.h>
#include <stdint.h>
#include "utlist.h"

/* Transition hash table operation */
static void 
add2TransitionHT(TransitionHashTable **transitionht, u32 seqNo, Transition *toTrans);

static TransitionHashTable *
findInTransitionHT(TransitionHashTable *transitionht, u32 seqNo);

static void
delTransitionHT(TransitionHashTable **transitionht);

static void 
countTransitionHT(TransitionHashTable *transitionht);

/* TPMNode hash operation */
static void
add2TPMNodeHash(TPMNodeHash **tpmnodeHash, TPMNode *tpmnode);

static TPMNodeHash *
findInTPMNodeHash(TPMNodeHash *tpmnodeHash, TPMNode *tpmnode);

static void
delTPMNodeHash(TPMNodeHash **tpmnodeHash);

static void
countTPMNodeHash(TPMNodeHash *tpmnodeHash);

static void
printTPMNodeHash(TPMNodeHash *tpmnodeHash);

/* Stack of Transition node operation */
StackTransitionNode *stackTransTop = NULL;
u32 stackCount = 0;

static void 
transStackPush(Transition *transition);

static Transition * 
transStackPop();

static void 
transStackDisplay();

static void 
transStackPopAll();

static bool 
isTransStackEmpty();

/* Similar as above, additionally uses local pointers and add level information */
static void
stackTransPush(
    Transition *trans,
    u32 level,
    StackTransitionNode **stackTransTop,
    u32 *stackTransCnt);

static Transition *
stackTransPop(
    u32 *transLevel,
    StackTransitionNode **stackTransTop,
    u32 *stackTransCnt);

static void
stackTransDisplay(StackTransitionNode *stackTransTop, u32 stackTransCnt);

static void
stackTransPopAll(StackTransitionNode **stackTransTop, u32 *stackTransCnt);

static bool
isStackTransEmpty(StackTransitionNode *stackTransTop);

static void
printTransitionNode(StackTransitionNode *transNode);

/* stack of memory nodes during dfsfast */
static void
stckMemnodePush(TPMNode2 *memnode, u32 level, StckMemnode **stckMemnodeTop, u32 *stckMemnodeCnt);

static TPMNode2 *
stckMemnodePop(u32 *level, StckMemnode **stckMemnodeTop, u32 *stckMemnodeCnt);

static void
stckMemnodeDisplay(StckMemnode *stckMemnodeTop, u32 stckMemnodeCnt);

static void
stckMemnodePopAll(StckMemnode **stckMemnodeTop, u32 *stckMemnodeCnt);

static bool
isStckMemnodeEmpty(StckMemnode *stckMemnodeTop);

/* TPMNode stack operation */
static void
stackTPMNodePush(
    TPMNode *tpmnode,
    TPMNode *farther,
    Transition *dirctTrans,
    StackTPMNode **stackTPMNodeTop,
    u32 *stackTPMNodeCnt);

static TPMNode *
stackTPMNodePop(
    StackTPMNode **stackTPMNodeTop,
    u32 *stackTPMNodeCnt);

static void
stackTPMNodeDisplay(
    StackTPMNode *stackTPMNodeTop,
    u32 stackTPMNodeCnt);

static void
stackTPMNodePopAll(
    StackTPMNode **stackTPMNodeTop,
    u32 *stackTPMNodeCnt);

static bool
isStackTPMNodeEmpty(StackTPMNode *stackTPMNodeTop);

/* mem node propagate implement */
static int 
dfs(TPMContext *tpm,
    TPMNode2 *s,
    TaintedBuf **dstMemNodes,
    Addr2NodeItem *addr2NodeHT,
    u32 dstAddrStart,
    u32 dstAddrEnd,
    int dstMinSeq,
    int dstMaxseq,
    u32 *stepCount);

// static int 
// dfsfast(TPMContext *tpm,
//     TPMPropgtSearchCtxt *tpmPSCtxt,
//     AddrPropgtToNode **addrPropgtToNode,
//     TPMNode2 *srcnode);

static int
dfsPrintResult(TPMContext *tpm, TPMNode2 *s);

/* dfs operation */
static void 
markVisitTransition(TransitionHashTable **transitionht, Transition *transition);

static bool 
isTransitionVisited(TransitionHashTable *transitionht, Transition *transition);

static void 
storeAllUnvisitChildren(
    TransitionHashTable **transitionht,
    Transition *firstChild,
    int maxseq);

// static void 
// storeAllUnvisitChildrenFast(
//     TransitionHashTable **transitionht,
//     Transition *firstChild,
//     int maxseq,
//     StackTransitionNode **stackTransTop,
//     u32 *stackTransCnt,
//     u32 dfsLevel);

static void
storeUnvisitChildren(
    TransitionHashTable **transitionht,
    Transition *firstChild,
    int maxseq,
    StackTransitionNode **stackTransTop,
    u32 *stackTransCnt,
    u32 dfsLevel);

static void
storeUnvisitChildren_Intermediate(
    TransitionHashTable **transitionht,
    Transition *firstChild,
    int maxseq,
    StackTransitionNode **stackTransTop,
    u32 *stackTransCnt,
    u32 dfsLevel);

static void
storePropagateDstMemNode(TPMNode2 *memNode, TaintedBuf **dstMemNodes);

/* dfs implementation: buf node propagates to hitmap nodes */
static int
dfs2HitMapNode(
    TPMContext *tpm,
    TPMNode2 *srcnode,
    HitMapContext *hitMapCtxt);

static bool
isValidBufNode(TPMNode2 *node);

static void
storeDFSBufNodeVisitPath(
    TPMNode2 *node,
    u32 lvl,
    StckMemnode **stackBufNodePathTop,
    u32 *stackBufNodePathCnt);

static int
dfs2HitMapNode_NodeStack(
    TPMContext *tpm,
    TPMNode2 *srcnode,
    HitMapContext *hitMapCtxt);

static void
add2HitMap(
    TPMNode *topNode,
    StckMemnode *stackBufNodePathTop,
    u32 stackBufNodePathCnt,
    StackTPMNode *stackTPMNodeTop,
    HitMapContext *hitMapCtxt);

static void
markVisitTPMNode(TPMNodeHash **tpmNodeHash, TPMNode *tpmnode);

static bool
isTPMNodeVisited(TPMNodeHash *tpmNodeHash, TPMNode *tpmnode);

static void
storeUnvisitTPMNodeChildren(
    TPMNodeHash **tpmnodeHash,
    TPMNode *father,
    int maxSeqN,
    StackTPMNode **stackTPMNodeTop,
    u32 *stackTPMNodeCnt);

static int
dfs2HitMapNode_NodeStack_dupl(
    TPMContext *tpm,
    TPMNode2 *srcnode,
    HitMapContext *hitMapCtxt,
    u32 *nodeVisitIdx);

static void
storeUnvisitTPMNodeChildren_dupl(
    u32 *nodeVisitIdx,
    TPMNode *farther,
    int maxSeqN,
    StackTPMNode **stackTPMNodeTop,
    u32 *stackTPMNodeCnt);

static int
dfs_build_hitmap(
    TPMContext *tpm,
    TPMNode2 *srcnode,
    HitMapContext *hitMapCtxt);

static void
storeTPMNodeChildren(
    TPMNode2 *srcnode,
    u32 maxSeqN,
    StackTPMNode **stackTpmNodeTop,
    u32 *stackTpmNodeCnt);

static int
dfs2HitMapNode_PopAtEnd(
    TPMContext *tpm,
    TPMNode2 *srcnode,
    HitMapContext *hitMapCtxt);

static int
dfs2BuildHitMap_DBG(
    TPMContext *tpm,
    TPMNode2 *srcnode,
    HitMapContext *hitMapCtxt);

static void
popBufNode(
    TPMNode *dstNode,
    StckMemnode **stackBufNodePathTop,
    u32 *stackBufNodePathCnt);

/* dfs search to build HitMap with intermediate node */
static int
dfsBuildHitMap_intermediateNode(
    TPMContext *tpm,
    TPMNode2 *srcnode,
    HitMapContext *hitMapCtxt);

static bool
isLeafTransition(Transition *trans);

static void
processIntermediateTrans(
    TPMNode *child,
    StackTPMNode *stackTPMNodePathTop,
    u32 stackTPMNodePathCnt,
    HitMapContext *hitMapCtxt,
    u32 transSeqN);

static void
processLeafTrans(
    TPMNode *leafChild,
    StackTPMNode *stackTPMNodePathTop,
    u32 stackTPMNodePathCnt,
    HitMapContext *hitMapCtxt,
    u32 transSeqN);

static void
processHasVisitTrans(
    TPMNode *child,
    StackTPMNode *stackTPMNodePathTop,
    u32 stackTPMNodePathCnt,
    HitMapContext *hitMapCtxt,
    u32 transSeqN);

/* TPM node stack operation
 *  used as in building HitMap with intermediate nodes, the tpm nodes can be
 *  either memory or reg/temp node
 */
static void
tpmNodePush(
    TPMNode *node,
    StackTPMNode **stackTPMNodeTop,
    u32 *stackTPMNodeCnt);

static TPMNode *
tpmNodePop(StackTPMNode **stackTPMNodeTop, u32 *stackTPMNodeCnt);

static void
printTPMNodeStack(StackTPMNode *stackTPMNodeTop, u32 stackTPMNodeCnt);

static void
tpmNodePopAll(StackTPMNode **stackTPMNodeTop, u32 *stackTPMNodeCnt);

static bool
isTPMNodeStackEmpty(StackTPMNode *stackTPMNodeTop);

static int
dfs_disp_reverse_propgt(TPMContext *tpm, TPMNode2 *src);

static void
push_unvisitnode_children_reverse(
    TPMNodeHash **visit_nodehash,
    TPMNode *child,
    StackTPMNode **stack_nodetop,
    u32 *stack_nodecnt);

/* non static functions */

int 
cmpAddr2NodeItem(Addr2NodeItem *l, Addr2NodeItem *r)
{
  if(l->addr < r->addr) { return -1; }
  else if(l->addr == r->addr) {
    if(l->node->version < r->node->version) { return -1; }
    else if(l->node->version < r->node->version) { return 0; }
    else { return 1; }
  }
  else { return 1; }
}

int
memNodePropagate(
    TPMContext *tpm,
    TPMNode2 *s,
    TaintedBuf **dstMemNodes,   // IGNORE
    Addr2NodeItem *addr2NodeHT,
    u32 dstAddrStart,
    u32 dstAddrEnd,
    int dstMinSeq,
    int dstMaxSeq,
    u32 *stepCount)
{
  // printMemNode(s);
  // printf("dststart:%-8x dstend:%-8x dstminseq:%d dstmaxseq:%d\n",
  // 	dstAddrStart, dstAddrEnd, dstMinSeq, dstMaxSeq);
  return dfs(tpm, s, dstMemNodes, addr2NodeHT, dstAddrStart, dstAddrEnd, dstMinSeq, dstMaxSeq, stepCount);
}

// int 
// memnodePropgtFast(
//     TPMContext *tpm,
//     TPMPropgtSearchCtxt *tpmPSCtxt,
//     AddrPropgtToNode **addrPropgtToNode,
//     TPMNode2 *srcnode)
// {
//   return dfsfast(tpm, tpmPSCtxt, addrPropgtToNode, srcnode);
// }

int
bufnodePropgt2HitMapNode(
    TPMContext *tpm,
    TPMNode2 *srcnode,
    HitMapContext *hitMapCtxt,
    u32 *nodeVisitIdx)
{
  // return dfs2HitMapNode(tpm, srcnode, hitMapCtxt);
  // return dfs2HitMapNode_NodeStack(tpm, srcnode, hitMapCtxt); // last used
  return dfs2HitMapNode_NodeStack_dupl(tpm, srcnode, hitMapCtxt, nodeVisitIdx);
  // return dfs_build_hitmap(tpm, srcnode, hitMapCtxt); // Non hash table

  // return dfs2HitMapNode_PopAtEnd(tpm, srcnode, hitMapCtxt);
  // return dfs2BuildHitMap_DBG(tpm, srcnode, hitMapCtxt);
  // return dfsBuildHitMap_intermediateNode(tpm, srcnode, hitMapCtxt);
}

//int
//hitMapNodePropagate(HitMapNode *srcnode, HitMapContext *hitMap, TPMContext *tpm)
// Returns:
//  >= 0: num of hitmap nodes that the srcnode can propagate to
//  <0: error
//{
//    return dfsHitMapNodePropagate(srcnode, hitMap, tpm);
//}


int
printMemNodePropagate(TPMContext *tpm, TPMNode2 *s)
{
  return dfsPrintResult(tpm, s);
}

#if TPM_RE_TRANSITON
int
disp_reverse_propgt(TPMContext *tpm, TPMNode2 *s)
{
  return dfs_disp_reverse_propgt(tpm, s);
}
#endif

static int
dfs(TPMContext *tpm,
    TPMNode2 *s,
    TaintedBuf **dstMemNodes,   // IGNORE
    Addr2NodeItem *addr2NodeHT,
    u32 dstAddrStart,
    u32 dstAddrEnd,
    int dstMinSeq,
    int dstMaxSeq,
    u32 *stepCount)
// Returns:
//  >=0: dst mem nodes hit count
//  <0: error
//	Depth First Search the propagated buffer given tpm and source 
{
  if(tpm == NULL || s == NULL) {
    fprintf(stderr, "error: dfs: tpm:%p s:%p\n", tpm, s);
    return -1;
  }
#ifdef DEBUG
  printf("--------------------\n");
  printf("dfs: source addr:%x val:%x ts:%u version%u\n", s->addr, s->val, s->lastUpdateTS, s->version);
#endif

  TransitionHashTable *markVisitTransHT = NULL;
  Transition *source_trans = s->firstChild;
  int srcHitDstByte = 0;
  int srcbyte = s->bytesz;

  if(source_trans != NULL) {
    storeAllUnvisitChildren(&markVisitTransHT, source_trans, dstMaxSeq);
    while(!isTransStackEmpty() ) {
      Transition *pop = transStackPop();
      TPMNode *dst = getTransitionDst(pop);

      if(dst->tpmnode1.type == TPM_Type_Memory) {
        // printf("propagate to addr:%x val:%x sz:%u\n", dst->tpmnode2.addr, dst->tpmnode2.val, dst->tpmnode2.bytesz);
        if(dst->tpmnode2.addr >= dstAddrStart
            && dst->tpmnode2.addr <= dstAddrEnd
            && dst->tpmnode2.lastUpdateTS >= dstMinSeq
            && dst->tpmnode2.lastUpdateTS <= dstMaxSeq) {    // Only stores hit mem nodes in dst addr and seq range
          dst->tpmnode2.hitcnt += srcbyte;        // updates dst node hitcnt
          srcHitDstByte += dst->tpmnode2.bytesz;  // updates src node hitcnt
          // storePropagateDstMemNode(&(dst->tpmnode2), dstMemNodes); // IGNORE: old

          // adds the dst node to 2nd level of the addr2NodeItem hash
          Addr2NodeItem *addr2NodeItem = createAddr2NodeItem(dst->tpmnode2.addr, &(dst->tpmnode2), NULL, NULL);
          HASH_ADD(hh_addr2NodeItem, addr2NodeHT->subHash, node, 4, addr2NodeItem);
        }
      }
      else {
        // printf("propagate to temp/reg:%x val:%x first_child:%p\n", dst->tpmnode1.addr, dst->tpmnode1.val, dst->tpmnode1.firstChild);
      }
      (*stepCount)++;
      storeAllUnvisitChildren(&markVisitTransHT, dst->tpmnode1.firstChild, dstMaxSeq);
      // TODO: if search node seqNo larger than dst max seqNo, no need to search further
    }
  }
  else {
#ifdef DEBUG
    printf("dfs: given source is a leaf\n");
    printMemNode(s);
#endif	 
  }

#ifdef DEBUG
  printf("total:%u traverse steps\n", *stepCount);
#endif
  delTransitionHT(&markVisitTransHT);
  transStackPopAll();
  HASH_SRT(hh_addr2NodeItem, addr2NodeHT->subHash, cmpAddr2NodeItem);

  return srcHitDstByte;
}

// static int 
// dfsfast(TPMContext *tpm,
//     TPMPropgtSearchCtxt *tpmPSCtxt,
//     AddrPropgtToNode **addrPropgtToNode,
//     TPMNode2 *srcnode)
// {
//   if(tpm == NULL || srcnode == NULL || tpmPSCtxt == NULL) {
//     fprintf(stderr, "error: dfs: tpm:%p srcnode:%p tpmPSCtxt:%p\n", tpm, srcnode, tpmPSCtxt);
//     return -1;
//   }
//   // printMemNode(srcnode);

//   TransitionHashTable *markVisitTransHT = NULL;
//   Transition *sourceTrans = srcnode->firstChild;

//   StackTransitionNode *stackTransTop = NULL;
//   u32 stackTransCnt = 0;
//   u32 dfsLevel = 0;

//   StackTransitionNode *stackMemTransTop = NULL;
//   u32 stackMemTransCnt = 0;

//   int stepCount = 0;

//   if(sourceTrans != NULL) {
//     dfsLevel++;
//     storeAllUnvisitChildrenFast(&markVisitTransHT, sourceTrans, tpmPSCtxt->maxSeqN, &stackTransTop, &stackTransCnt, dfsLevel);
//     // stackTransDisplay(stackTransTop, stackTransCnt);

//     while(!isStackTransEmpty(stackTransTop) ) {
//       u32 transLvl;
//       Transition *popTrans = stackTransPop(&transLvl, &stackTransTop, &stackTransCnt);
//       TPMNode *dstnode = getTransitionDst(popTrans);

//       if(dstnode->tpmnode1.type == TPM_Type_Memory) {
//         // printMemNode((TPMNode2 *)dstnode);
//       }

//       stepCount++;
//       storeAllUnvisitChildrenFast(&markVisitTransHT, dstnode->tpmnode1.firstChild, tpmPSCtxt->maxSeqN, &stackTransTop, &stackTransCnt, dfsLevel);
//       // stackTransDisplay(stackTransTop, stackTransCnt);
//       dfsLevel++;
//     }
//   }
//   else {
//     printf("dfsfast: given source node is a leaf\n");
//     printMemNode(srcnode);
//   }
//   delTransitionHT(&markVisitTransHT);
//   stackTransPopAll(&stackTransTop, &stackTransCnt);

//   return stepCount;
// }

static int
dfsPrintResult(TPMContext *tpm, TPMNode2 *s)
// Returns
//	0: success
//	<0: error
//	Depth First Search the propagated buffer given tpm and source 
{
  if(tpm == NULL || s == NULL) {
    fprintf(stderr, "error: dfs: tpm:%p s:%p\n", tpm, s);
    return -1;
  }

  // #ifdef DEBUG
  printf("--------------------\n");
  printf("dfs: source addr:%x val:%x ts:%u version%u\n", s->addr, s->val, s->lastUpdateTS, s->version);
  // #endif

  TransitionHashTable *markVisitTransHT = NULL;
  Transition *source_trans = s->firstChild;
  int stepCount = 0;

  if(source_trans != NULL) {
    storeAllUnvisitChildren(&markVisitTransHT, source_trans, INT32_MAX);
    while(!isTransStackEmpty() ) {
      Transition *pop = transStackPop();
      TPMNode *dst = getTransitionDst(pop);
      // #ifdef DEBUG
      if(dst->tpmnode1.type == TPM_Type_Memory) {
        // printf("propagate to addr:%x val:%x\n", dst->tpmnode2.addr, dst->tpmnode2.val);
        printMemNodeLit((TPMNode2 *)dst);
      }
      // #endif
      stepCount++;

      storeAllUnvisitChildren(&markVisitTransHT, dst->tpmnode1.firstChild, INT32_MAX);
    }
  }
  else {
#ifdef DEBUG
    printf("dfs: given source is a leaf\n");
    print_mem_node(s);
#endif	 
  }

#ifdef DEBUG
  printf("total:%u traverse steps\n", stepCount);
#endif
  delTransitionHT(&markVisitTransHT);
  transStackPopAll();

  return stepCount;
}

static void 
add2TransitionHT(TransitionHashTable **transitionht, u32 seqNo, Transition *toTrans)
{
  TransitionHashTable *t;
  t = findInTransitionHT(*transitionht, seqNo);
  if(t == NULL ) {
    t = malloc(sizeof(TransitionHashTable) );
    t->seqNo = seqNo;
    HASH_ADD(hh_trans, *transitionht, seqNo, 4, t);
    t->toTrans = toTrans;
  }
  else {}	// Not update
}

static TransitionHashTable *
findInTransitionHT(TransitionHashTable *transitionht, u32 seqNo)
{
  TransitionHashTable *s = NULL;
  HASH_FIND(hh_trans, transitionht, &seqNo, 4, s);
  return s;
}

static void
delTransitionHT(TransitionHashTable **transitionht)
{
  TransitionHashTable *curr, *tmp;
  HASH_ITER(hh_trans, *transitionht, curr, tmp) {
    HASH_DELETE(hh_trans, *transitionht, curr);
    free(curr);
  }
  // printf("del transition hash table\n");
}

static void 
countTransitionHT(TransitionHashTable *transitionht)
{
  u32 num;
  num = HASH_CNT(hh_trans, transitionht);
  printf("total:%u transitions in hash table\n", num);
}

static void
add2TPMNodeHash(TPMNodeHash **tpmnodeHash, TPMNode *tpmnode)
{
  TPMNodeHash *tpmHash;
  tpmHash = findInTPMNodeHash(*tpmnodeHash, tpmnode);
  if(tpmHash == NULL) {
    tpmHash = calloc(1, sizeof(TPMNodeHash) );
    assert(tpmHash != NULL);
    tpmHash->toTPMNode = tpmnode;
    HASH_ADD(hh_tpmnode, *tpmnodeHash, toTPMNode, 4, tpmHash);
  }
}

static TPMNodeHash *
findInTPMNodeHash(TPMNodeHash *tpmnodeHash, TPMNode *tpmnode)
{
  TPMNodeHash *tpmHash = NULL;
  HASH_FIND(hh_tpmnode, tpmnodeHash, &tpmnode, 4, tpmHash);
  return tpmHash;
}

static void
delTPMNodeHash(TPMNodeHash **tpmnodeHash)
{
  TPMNodeHash *cur, *tmp;
  HASH_ITER(hh_tpmnode, *tpmnodeHash, cur, tmp) {
    HASH_DELETE(hh_tpmnode, *tpmnodeHash, cur);
    free(cur);
  }
}

static void
countTPMNodeHash(TPMNodeHash *tpmnodeHash) {}

static void 
printTPMNodeHash(TPMNodeHash *tpmnodeHash)
{
  TPMNodeHash *cur, *tmp;
  HASH_ITER(hh_tpmnode, tpmnodeHash, cur, tmp) {
    TPMNode *node = cur->toTPMNode;
    if(node->tpmnode1.type == TPM_Type_Memory) {
      printMemNodeLit((TPMNode2 *)node);
    }
    else {
      printNonmemNode((TPMNode1 *)node);
    }
  }
}


static void
transStackPush(Transition *transition)
{
  StackTransitionNode *n = malloc(sizeof(StackTransitionNode) );
  n->transition = transition;
  n->next = stackTransTop;
  stackTransTop = n;
  stackCount++;
}

static Transition *
transStackPop()
{
  StackTransitionNode *toDel;
  Transition *trans = NULL;

  if(stackTransTop != NULL) {
    toDel = stackTransTop;
    stackTransTop = toDel->next;
    trans = toDel->transition;
    free(toDel);
    stackCount--;
  }
  return trans;
}

static void 
transStackDisplay()
{
  StackTransitionNode *n = stackTransTop;
  while(n != NULL) {
    printf("Transition:%p seqNo:%u\n", n->transition, n->transition->seqNo);
    n = n->next;
  }
}

static void 
transStackPopAll()
{
  while(stackTransTop != NULL) {
    transStackPop();
  }
}

static bool 
isTransStackEmpty()
{
  if(stackTransTop == NULL)
    return true;
  else
    return false;
}

static void
stackTransPush(
    Transition *trans,
    u32 level,
    StackTransitionNode **stackTransTop,
    u32 *stackTransCnt)
{
  StackTransitionNode *n = calloc(1, sizeof(StackTransitionNode));
  n->transition = trans;
  n->level = level;
  n->next = *stackTransTop;
  *stackTransTop = n;
  (*stackTransCnt)++;
}

static Transition *
stackTransPop(
    u32 *transLevel,
    StackTransitionNode **stackTransTop,
    u32 *stackTransCnt)
{
  StackTransitionNode *toDel;
  Transition *trans = NULL;

  if(*stackTransTop != NULL) {
    toDel = *stackTransTop;
    *stackTransTop = toDel->next;

    trans = toDel->transition;
    *transLevel = toDel->level;

    free(toDel);
    (*stackTransCnt)--;
  }
  return trans;
}

static void
stackTransDisplay(StackTransitionNode *stackTransTop, u32 stackTransCnt)
{
  if(stackTransCnt > 0)
    printf("--------------------\ntotal transitions in stack:%u\n", stackTransCnt);

  while(stackTransTop != NULL) {
    printf("Transition level:%u\n", stackTransTop->level);
    printTrans1stChild(stackTransTop->transition->child);
    stackTransTop = stackTransTop->next;
  }
}

static void
stackTransPopAll(StackTransitionNode **stackTransTop, u32 *stackTransCnt)
{
  while(*stackTransTop != NULL) {
    u32 transLvl;
    stackTransPop(&transLvl, stackTransTop, stackTransCnt);
  }
}

static bool
isStackTransEmpty(StackTransitionNode *stackTransTop)
{
  if(stackTransTop != NULL)
    return false;
  else
    return true;
}

static void
printTransitionNode(StackTransitionNode *transNode)
{
  if(transNode == NULL)
    return;

  printf("Transition node: level:%u first child:\n", transNode->level);
  if(transNode->transition->child->tpmnode1.type == TPM_Type_Memory) {
    printMemNode((TPMNode2 *)&(transNode->transition->child->tpmnode2) );
  }
  else {
    printNonmemNode((TPMNode1 *)&(transNode->transition->child->tpmnode1) );
  }
}


static void
stckMemnodePush(TPMNode2 *memnode, u32 level, StckMemnode **stckMemnodeTop, u32 *stckMemnodeCnt)
{
  StckMemnode *n = calloc(1, sizeof(StckMemnode) );
  assert(n != NULL);
  n->level = level;
  n->memnode = memnode;
  n->next = *stckMemnodeTop;
  *stckMemnodeTop = n;
  (*stckMemnodeCnt)++;
}

static TPMNode2 *
stckMemnodePop(u32 *level, StckMemnode **stckMemnodeTop, u32 *stckMemnodeCnt)
{
  StckMemnode *toDel;
  TPMNode2 *memnode = NULL;

  if(*stckMemnodeTop != NULL) {
    toDel = *stckMemnodeTop;
    *stckMemnodeTop = toDel->next;
    memnode = toDel->memnode;
    *level = toDel->level;
    free(toDel);
    (*stckMemnodeCnt)--;
  }
  return memnode;
}

static void
stckMemnodeDisplay(StckMemnode *stckMemnodeTop, u32 stckMemnodeCnt)
{
  if(stckMemnodeCnt > 0)
    printf("--------------------\ntotal memnode in stack:%u\n", stckMemnodeCnt);

  while(stckMemnodeTop != NULL) {
    printf("node levle:%u minSeqN:%u\n", stckMemnodeTop->level, stckMemnodeTop->minSeqN);
    // printMemNode(stckMemnodeTop->memnode);
    printMemNodeLit(stckMemnodeTop->memnode);
    stckMemnodeTop = stckMemnodeTop->next;
  }
}

static void
stckMemnodePopAll(StckMemnode **stckMemnodeTop, u32 *stckMemnodeCnt)
{
  while(*stckMemnodeTop != NULL){
    u32 lvl;
    stckMemnodePop(&lvl, stckMemnodeTop, stckMemnodeCnt);
  }
}

static bool
isStckMemnodeEmpty(StckMemnode *stckMemnodeTop)
{
  if(stckMemnodeTop != NULL)
    return false;
  else
    return true;
}

static void
stackTPMNodePush(
    TPMNode *tpmnode,
    TPMNode *farther,
    Transition *dirctTrans,
    StackTPMNode **stackTPMNodeTop,
    u32 *stackTPMNodeCnt)
{
  StackTPMNode *s = calloc(1, sizeof(StackTPMNode) );
  assert(s != NULL);
  s->node = tpmnode;
  s->farther = farther;
  s->dirctTrans = dirctTrans;
  s->next = *stackTPMNodeTop;
  s->isVisit = 0;
  *stackTPMNodeTop = s;
  (*stackTPMNodeCnt)++;
}

static TPMNode *
stackTPMNodePop(
    StackTPMNode **stackTPMNodeTop,
    u32 *stackTPMNodeCnt)
{
  StackTPMNode *toPop;
  TPMNode *tpmnode = NULL;

  if(*stackTPMNodeTop != NULL) {
    toPop = *stackTPMNodeTop;
    *stackTPMNodeTop = toPop->next;
    tpmnode = toPop->node;

    free(toPop);
    (*stackTPMNodeCnt)--;
  }

  return tpmnode;
}

static void
stackTPMNodeDisplay(
    StackTPMNode *stackTPMNodeTop,
    u32 stackTPMNodeCnt)
{
  if (stackTPMNodeCnt > 0)
    printf("-----\nnum of TPMNodes in stack:%u\n", stackTPMNodeCnt);

  while (stackTPMNodeTop != NULL) {
    TPMNode *farther = stackTPMNodeTop->farther;
    printf("farther: ");
    printNode(farther);

    TPMNode *node = stackTPMNodeTop->node;
    printf("node: ");
    printNode(node);

    print1Trans(stackTPMNodeTop->dirctTrans);
    //        if (node->tpmnode1.type == TPM_Type_Memory)
    //            printMemNodeLit((TPMNode2 *) node);
    //        else
    //            printNonmemNode((TPMNode1 *) node);
    stackTPMNodeTop = stackTPMNodeTop->next;
  }
}

static void
stackTPMNodePopAll(
    StackTPMNode **stackTPMNodeTop,
    u32 *stackTPMNodeCnt)
{
  while(*stackTPMNodeTop != NULL) {
    stackTPMNodePop(stackTPMNodeTop, stackTPMNodeCnt);
  }
}

static bool
isStackTPMNodeEmpty(StackTPMNode *stackTPMNodeTop)
{
  if(stackTPMNodeTop != NULL) { return false; }
  else { return true; }
}

static void 
markVisitTransition(TransitionHashTable **transitionht, Transition *transition)
{
  if (transitionht == NULL || transition == NULL)
    return;

  add2TransitionHT(transitionht, transition->seqNo, transition);
}

static bool 
isTransitionVisited(TransitionHashTable *transitionht, Transition *transition)
{
  if(transition == NULL)
    return false;

  TransitionHashTable *found = NULL;
  u32 seqNo;

  seqNo = transition->seqNo;
  found = findInTransitionHT(transitionht, seqNo);
  if(found != NULL)
    return true;
  else
    return false;
}

static void 
storeAllUnvisitChildren(
    TransitionHashTable **transitionht,
    Transition *firstChild,
    int maxseq)
// Not use!
{
  while(firstChild != NULL){
    if(!isTransitionVisited(*transitionht, firstChild)
        && firstChild->seqNo <= maxseq) {    // only search within the dst max range
      transStackPush(firstChild);
      markVisitTransition(transitionht, firstChild);
    }
    firstChild = firstChild->next;
  }
}

// static void 
// storeAllUnvisitChildrenFast(
//     TransitionHashTable **transitionht,
//     Transition *firstChild,
//     int maxseq,
//     StackTransitionNode **stackTransTop,
//     u32 *stackTransCnt,
//     u32 dfsLevel)
// // Same as storeAllUnvisitChildren, additionally add level info
// // Not use!
// {

//   while(firstChild != NULL) {
//     if(!isTransitionVisited(*transitionht, firstChild)
//         && firstChild->seqNo <= maxseq) {
//       // transStackPush(firstChild);
//       stackTransPush(firstChild, dfsLevel, stackTransTop, stackTransCnt);
//       markVisitTransition(transitionht, firstChild);
//     }
//     firstChild = firstChild->next;
//   }
// }

static void
storeUnvisitChildren(
    TransitionHashTable **transitionht,
    Transition *firstChild,
    int maxseq,
    StackTransitionNode **stackTransTop,
    u32 *stackTransCnt,
    u32 dfsLevel)
// Push all the transition children into the transition stack, but don't mark them as visited yet
{
  // printf("maxSeqN:%d\n", maxseq);
  // printTransAllChildren(firstChild);
  while(firstChild != NULL) {
    if(!isTransitionVisited(*transitionht, firstChild)  // only push non visit node (dfs routine)
        && firstChild->seqNo <= maxseq
    /* && firstChild->child->tpmnode1.hasVisit == 0 */  ) { // A bug in propagate
      stackTransPush(firstChild, dfsLevel, stackTransTop, stackTransCnt);
    }
    firstChild = firstChild->next;
  }
}

static void
storeUnvisitChildren_Intermediate(
    TransitionHashTable **transitionht,
    Transition *firstChild,
    int maxseq,
    StackTransitionNode **stackTransTop,
    u32 *stackTransCnt,
    u32 dfsLevel)
{
  while(firstChild != NULL) {
    if(!isTransitionVisited(*transitionht, firstChild)  // only push non visit node (dfs routine)
        && firstChild->seqNo <= maxseq ) {
      stackTransPush(firstChild, dfsLevel, stackTransTop, stackTransCnt);
    }
    firstChild = firstChild->next;
  }
}

static void
storePropagateDstMemNode(TPMNode2 *memNode, TaintedBuf **dstMemNodes)
{
  TaintedBuf *node = createTaintedBuf(memNode);
  LL_APPEND(*dstMemNodes, node);
}

static int
dfs2HitMapNode(
    TPMContext *tpm,
    TPMNode2 *srcnode,
    HitMapContext *hitMapCtxt)
{
  if(tpm == NULL || srcnode == NULL || hitMapCtxt == NULL) {
    fprintf(stderr, "dfs2HitMapNode: tpm:%p srcnode:%p hitMap:%p\n", tpm, srcnode, hitMapCtxt);
    return -1;
  }

  if(isHitMapNodeExist(srcnode, hitMapCtxt) ) {
    // printf("srcnode %p had been build HitMap\n", srcnode);
    return 0;
  }

  TransitionHashTable *markVisitTransHT = NULL;

  StackTransitionNode *stackTransTop = NULL;
  u32 stackTransCnt = 0;

  StckMemnode *stackBufNodePathTop = NULL;
  u32 stackBufNodePathCnt = 0;

  u32 dfsLevel = 0;   // Not used
  int stepCount = 0;

  u32 minHitTransSeqN, maxHitTransSeqN;

  // printf("----------\ndfs2HitMapNode_PopWhenNoChildren source:%p\n", srcnode);
  // printMemNode(srcnode);
  // printTransAllChildren(sourceTrans);

  Transition *sourceTrans = srcnode->firstChild;
  if(sourceTrans == NULL) {
    // printf("dfs2HitMapNode: given source node is a leaf\n");
    // printMemNode(srcnode);
    return 0;
  }
  minHitTransSeqN = sourceTrans->seqNo;
  maxHitTransSeqN = sourceTrans->seqNo;

  stckMemnodePush(srcnode, dfsLevel, &stackBufNodePathTop, &stackBufNodePathCnt);
  // stckMemnodeDisplay(stackBufNodePathTop, stackBufNodePathCnt);
  // printf("--------------------\ndfs depth level:%u\n", dfsLevel);
  // printMemNodeLit(srcnode);

  storeUnvisitChildren(&markVisitTransHT, sourceTrans, hitMapCtxt->maxBufSeqN,
      &stackTransTop, &stackTransCnt, dfsLevel);
  // storeAllUnvisitChildrenFast(&markVisitTransHT, sourceTrans,
  //         hitMapCtxt->maxBufSeqN, &stackTransTop, &stackTransCnt, dfsLevel);
  // stackTransDisplay(stackTransTop, stackTransCnt);

  while(!isStackTransEmpty(stackTransTop) ) {
    Transition *topTrans = stackTransTop->transition;
    TPMNode *dstNode = getTransitionDst(topTrans);
    u32 transLvl;   // Not used

    if(isTransitionVisited(markVisitTransHT, topTrans) ) {  // if the transition had been visited
      if(dstNode->tpmnode1.type == TPM_Type_Memory && dstNode->tpmnode2.bufid > 0) {
        // printMemNodeLit((TPMNode2 *)dstNode);
        assert((TPMNode2 *)dstNode == stackBufNodePathTop->memnode);
        if(stackBufNodePathCnt > 1)
          createHitMapRecord(stackBufNodePathTop->next->memnode, 0,
              (TPMNode2 *)dstNode, topTrans->seqNo, hitMapCtxt);

        stckMemnodePop(&transLvl, &stackBufNodePathTop, &stackBufNodePathCnt);
      }

      stackTransPop(&transLvl, &stackTransTop, &stackTransCnt);
      // stackTransDisplay(stackTransTop, stackTransCnt);
      // popBufNode(dstNode, &stackBufNodePathTop, &stackBufNodePathCnt);
    }
    else { // new transition
      markVisitTransition(&markVisitTransHT, topTrans);   // mark it as visit
      if(dstNode->tpmnode1.type == TPM_Type_Memory && dstNode->tpmnode2.bufid > 0) {
        stckMemnodePush((TPMNode2 *)dstNode, transLvl, &stackBufNodePathTop, &stackBufNodePathCnt);
      }


      if(dstNode->tpmnode1.firstChild == NULL) { // leaf nodes
        if(dstNode->tpmnode1.type == TPM_Type_Memory && dstNode->tpmnode2.bufid > 0) {
          // printMemNodeLit((TPMNode2 *)dstNode);
          assert((TPMNode2 *)dstNode == stackBufNodePathTop->memnode);
          if(stackBufNodePathCnt > 1)
            createHitMapRecord(stackBufNodePathTop->next->memnode, 0,
                (TPMNode2 *)dstNode, topTrans->seqNo, hitMapCtxt);
          stckMemnodePop(&transLvl, &stackBufNodePathTop, &stackBufNodePathCnt);
        }

        stackTransPop(&transLvl, &stackTransTop, &stackTransCnt);
        // stackTransDisplay(stackTransTop, stackTransCnt);
        // popBufNode(dstNode, &stackBufNodePathTop, &stackBufNodePathCnt);
      }
      else {
        storeUnvisitChildren(&markVisitTransHT, dstNode->tpmnode1.firstChild,
            hitMapCtxt->maxBufSeqN, &stackTransTop, &stackTransCnt, dfsLevel);
        // stackTransDisplay(stackTransTop, stackTransCnt);
      }
    }
  }

  delTransitionHT(&markVisitTransHT);
  stackTransPopAll(&stackTransTop, &stackTransCnt);
  stckMemnodePopAll(&stackBufNodePathTop, &stackBufNodePathCnt);

  return stepCount;
}

static bool
isValidBufNode(TPMNode2 *node)
{
  if(node->bufid > 0)
    return true;
  else
    return false;
}

static void
storeDFSBufNodeVisitPath(
    TPMNode2 *node,
    u32 lvl,
    StckMemnode **stackBufNodePathTop,
    u32 *stackBufNodePathCnt)
// 1. stores buf nodes that dfs visits, that is, each node's level in the stack should
//  > than its previous
// 2. creates HitMap records
{
  if(*stackBufNodePathTop != NULL) {
    u32 nodeLvl = (*stackBufNodePathTop)->level;
    if(nodeLvl < lvl) {
      // printf("----------src hitmap node:\n");
      // printMemNodeLit((*stackBufNodePathTop)->memnode);
      // printf("dst hitmap node:\n");
      // printMemNodeLit(node);

      // createHitMapRecord((*stackBufNodePathTop)->memnode, (*stackBufNodePathTop)->level, node, lvl);
      stckMemnodePush(node, lvl, stackBufNodePathTop, stackBufNodePathCnt);
    }
    else {
      while(*stackBufNodePathTop != NULL && (*stackBufNodePathTop)->level >= lvl) {
        stckMemnodePop(&nodeLvl, stackBufNodePathTop, stackBufNodePathCnt);
      }

      // printf("----------src hitmap node:\n");
      // printMemNodeLit((*stackBufNodePathTop)->memnode);
      // printf("dst hitmap node:\n");
      // printMemNodeLit(node);

      // createHitMapRecord((*stackBufNodePathTop)->memnode, (*stackBufNodePathTop)->level, node, lvl);
      stckMemnodePush(node, lvl, stackBufNodePathTop, stackBufNodePathCnt);
    }
  }
  else {
    stckMemnodePush(node, lvl, stackBufNodePathTop, stackBufNodePathCnt);
  }
}

static int
dfs2HitMapNode_NodeStack(
    TPMContext *tpm,
    TPMNode2 *srcnode,
    HitMapContext *hitMapCtxt)
// Uses node stack instead of transition stack
// Enforces the monotonic increasing seqN policy: only search further if child's transition's
// seqN larger than curr seqN
{
  TPMNodeHash *visitTPMNodeHash = NULL;

  StackTPMNode *stackTPMNodeTop = NULL;
  u32 stackTPMNodeCnt = 0;

  StckMemnode *stackBufNodePathTop = NULL;
  u32 stackBufNodePathCnt = 0;

  u32 dfsLevel = 0; // Not used
  u32 currSeqN = 0; // Init source seqN to 0

  if(tpm == NULL || srcnode == NULL || hitMapCtxt == NULL) {
    fprintf(stderr, "dfs2HitMapNode_NodeStack: tpm:%p srcnode:%p hitMap:%p\n", tpm, srcnode, hitMapCtxt);
    return -1;
  }

  if(isHitMapNodeExist(srcnode, hitMapCtxt) ) {
    // printf("srcnode %p had been build HitMap\n", srcnode);
    return 0;
  }

//  printf("---------------\ndfs2HitMapNode_NodeStack source:%p\n", srcnode);
//  printMemNode(srcnode);

  stackTPMNodePush((TPMNode *)srcnode, NULL, NULL, &stackTPMNodeTop, &stackTPMNodeCnt);
  stackTPMNodeTop->currSeqN = currSeqN;

  while(!isStackTPMNodeEmpty(stackTPMNodeTop) ) {
    TPMNode *topNode = stackTPMNodeTop->node;
    u32 transLvl = 0;

    if(isTPMNodeVisited(visitTPMNodeHash, topNode) ) {
      if(topNode->tpmnode1.type == TPM_Type_Memory &&
          topNode->tpmnode2.bufid > 0) {

        add2HitMap(topNode, stackBufNodePathTop, stackBufNodePathCnt, stackTPMNodeTop, hitMapCtxt);
        stckMemnodePop(&transLvl, &stackBufNodePathTop, &stackBufNodePathCnt);
      }
      stackTPMNodePop(&stackTPMNodeTop, &stackTPMNodeCnt);
      // stackTPMNodeDisplay(stackTPMNodeTop, stackTPMNodeCnt);
    }
    else {  // new TPMNode
      markVisitTPMNode(&visitTPMNodeHash, topNode);

      if(topNode->tpmnode1.type == TPM_Type_Memory &&
          topNode->tpmnode2.bufid > 0) {
        stckMemnodePush((TPMNode2 *)topNode, transLvl, &stackBufNodePathTop, &stackBufNodePathCnt);
        // stckMemnodeDisplay(stackBufNodePathTop, stackBufNodePathCnt);
      }
      else { // it's not a valid buffer node, might need to update the minSeqN of
        // source buffer node (top of the path buf stack
        if(stackTPMNodeTop->farther->tpmnode1.type == TPM_Type_Memory &&
            (TPMNode2 *)stackTPMNodeTop->farther == stackBufNodePathTop->memnode) {
          // printf("-----update minSeqN\n");
          // set the minSeqN (should be direct transition of the source)
          stackBufNodePathTop->minSeqN = stackTPMNodeTop->dirctTrans->seqNo;
          // stckMemnodeDisplay(stackBufNodePathTop, stackBufNodePathCnt);
        }
      }

      if(topNode->tpmnode1.firstChild == NULL) { // leaf
        if(topNode->tpmnode1.type == TPM_Type_Memory &&
            topNode->tpmnode2.bufid > 0) {

          add2HitMap(topNode, stackBufNodePathTop, stackBufNodePathCnt, stackTPMNodeTop, hitMapCtxt);
          stckMemnodePop(&transLvl, &stackBufNodePathTop, &stackBufNodePathCnt);
        }
        stackTPMNodePop(&stackTPMNodeTop, &stackTPMNodeCnt);
        // stackTPMNodeDisplay(stackTPMNodeTop, stackTPMNodeCnt);
      }
      else {
        storeUnvisitTPMNodeChildren(&visitTPMNodeHash, topNode, hitMapCtxt->maxBufSeqN, &stackTPMNodeTop, &stackTPMNodeCnt);
        // stackTPMNodeDisplay(stackTPMNodeTop, stackTPMNodeCnt);
      }
    } // end else new TPMNode
  }

  delTPMNodeHash(&visitTPMNodeHash);
  stckMemnodePopAll(&stackBufNodePathTop, &stackBufNodePathCnt);

  return 0;
}

static void
add2HitMap(
    TPMNode *topNode,
    StckMemnode *stackBufNodePathTop,
    u32 stackBufNodePathCnt,
    StackTPMNode *stackTPMNodeTop,
    HitMapContext *hitMapCtxt)
{
  assert((TPMNode2 *)topNode == stackBufNodePathTop->memnode);
  if(stackBufNodePathCnt > 1) {
    TPMNode2 *src = stackBufNodePathTop->next->memnode;
    TPMNode2 *dst = (TPMNode2 *)topNode;
    u32 minHitTransSeqN = stackBufNodePathTop->next->minSeqN;
    u32 maxHitTransSeqN = stackTPMNodeTop->dirctTrans->seqNo;
    assert(minHitTransSeqN <= maxHitTransSeqN);
//    printf("-----\nCreates HitTransition between: minSeqN:%u maxSeqN:%u\n", minHitTransSeqN, maxHitTransSeqN);
//    printMemNodeLit(src);
//    printMemNodeLit(dst);

    createHitMapRecord(stackBufNodePathTop->next->memnode, minHitTransSeqN, (TPMNode2 *)topNode, maxHitTransSeqN, hitMapCtxt);
    // createHitMapRecordReverse(stackBufNodePathTop->next->memnode, minHitTransSeqN, (TPMNode2 *)topNode, maxHitTransSeqN, hitMapCtxt);
  }
}

static void
markVisitTPMNode(TPMNodeHash **tpmNodeHash, TPMNode *tpmnode)
{
  if(tpmNodeHash == NULL || tpmnode == NULL)
    return;
  add2TPMNodeHash(tpmNodeHash, tpmnode);
}

static bool
isTPMNodeVisited(TPMNodeHash *tpmNodeHash, TPMNode *tpmnode)
{
  if(tpmnode == NULL)
    return false;

  TPMNodeHash *found = NULL;
  found = findInTPMNodeHash(tpmNodeHash, tpmnode);
  if(found != NULL) { return true; }
  else { return false; }
}

static void
storeUnvisitTPMNodeChildren(
    TPMNodeHash **tpmnodeHash,
    TPMNode *farther,
    int maxSeqN,
    StackTPMNode **stackTPMNodeTop,
    u32 *stackTPMNodeCnt)
{
  Transition *firstChild = farther->tpmnode1.firstChild;
  while(firstChild != NULL) {
    TPMNode *childNode = firstChild->child;

    if(!isTPMNodeVisited(*tpmnodeHash, childNode) &&
        // firstChild->hasVisit == 0 && // The transition had not been visited before
        (*stackTPMNodeTop)->currSeqN <= firstChild->seqNo && // enforces the increasing seqN policy
        firstChild->seqNo <= maxSeqN ) {
      stackTPMNodePush(childNode, farther, firstChild, stackTPMNodeTop, stackTPMNodeCnt);
      (*stackTPMNodeTop)->currSeqN = firstChild->seqNo;

      firstChild->hasVisit += 1;
      // print1Trans(firstChild);
    }
    else {
      // printf("-----skip: \n");
      // printNode(farther);
      // print1Trans(firstChild);
      // printNode(childNode);
    }
    firstChild = firstChild->next;
  }
}

/*
 * Duplicate function, only difference is using tpm node flag to mark visited nodes
 * instead of hash table.
 */
static int
dfs2HitMapNode_NodeStack_dupl(
    TPMContext *tpm,
    TPMNode2 *srcnode,
    HitMapContext *hitMapCtxt,
    u32 *nodeVisitIdx)
{
//  TPMNodeHash *visitTPMNodeHash = NULL;

  StackTPMNode *stackTPMNodeTop = NULL;
  u32 stackTPMNodeCnt = 0;

  StckMemnode *stackBufNodePathTop = NULL;
  u32 stackBufNodePathCnt = 0;

  u32 dfsLevel = 0; // Not used
  u32 currSeqN = 0; // Init source seqN to 0

  if(tpm == NULL || srcnode == NULL || hitMapCtxt == NULL) {
    fprintf(stderr, "dfs2HitMapNode_NodeStack: tpm:%p srcnode:%p hitMap:%p\n", tpm, srcnode, hitMapCtxt);
    return -1;
  }

  if(isHitMapNodeExist(srcnode, hitMapCtxt) ) {
    // printf("srcnode %p had been build HitMap\n", srcnode);
    return 0;
  }

//  printf("---------------\ndfs2HitMapNode_NodeStack source:%p\n", srcnode);
//  printMemNode(srcnode);

  stackTPMNodePush((TPMNode *)srcnode, NULL, NULL, &stackTPMNodeTop, &stackTPMNodeCnt);
  stackTPMNodeTop->currSeqN = currSeqN;

  while(!isStackTPMNodeEmpty(stackTPMNodeTop) ) {
    TPMNode *topNode = stackTPMNodeTop->node;
    u32 transLvl = 0;

    // if(isTPMNodeVisited(visitTPMNodeHash, topNode) ) {
    if(topNode->tpmnode1.visitNodeIdx == *nodeVisitIdx) {
      if(topNode->tpmnode1.type == TPM_Type_Memory &&
          topNode->tpmnode2.bufid > 0) {

        add2HitMap(topNode, stackBufNodePathTop, stackBufNodePathCnt, stackTPMNodeTop, hitMapCtxt);
        stckMemnodePop(&transLvl, &stackBufNodePathTop, &stackBufNodePathCnt);
      }
      stackTPMNodePop(&stackTPMNodeTop, &stackTPMNodeCnt);
      // stackTPMNodeDisplay(stackTPMNodeTop, stackTPMNodeCnt);
    }
    else {  // new TPMNode
      // markVisitTPMNode(&visitTPMNodeHash, topNode);
      topNode->tpmnode1.visitNodeIdx = *nodeVisitIdx;

      if(topNode->tpmnode1.type == TPM_Type_Memory &&
          topNode->tpmnode2.bufid > 0) {
        stckMemnodePush((TPMNode2 *)topNode, transLvl, &stackBufNodePathTop, &stackBufNodePathCnt);
        // stckMemnodeDisplay(stackBufNodePathTop, stackBufNodePathCnt);
      }
      else { // it's not a valid buffer node, might need to update the minSeqN of
        // source buffer node (top of the path buf stack
        if(stackTPMNodeTop->farther->tpmnode1.type == TPM_Type_Memory &&
            (TPMNode2 *)stackTPMNodeTop->farther == stackBufNodePathTop->memnode) {
          // printf("-----update minSeqN\n");
          // set the minSeqN (should be direct transition of the source)
          stackBufNodePathTop->minSeqN = stackTPMNodeTop->dirctTrans->seqNo;
          // stckMemnodeDisplay(stackBufNodePathTop, stackBufNodePathCnt);
        }
      }

      if(topNode->tpmnode1.firstChild == NULL) { // leaf
        if(topNode->tpmnode1.type == TPM_Type_Memory &&
            topNode->tpmnode2.bufid > 0) {

          add2HitMap(topNode, stackBufNodePathTop, stackBufNodePathCnt, stackTPMNodeTop, hitMapCtxt);
          stckMemnodePop(&transLvl, &stackBufNodePathTop, &stackBufNodePathCnt);
        }
        stackTPMNodePop(&stackTPMNodeTop, &stackTPMNodeCnt);
        // stackTPMNodeDisplay(stackTPMNodeTop, stackTPMNodeCnt);
      }
      else {
        storeUnvisitTPMNodeChildren_dupl(nodeVisitIdx, topNode, hitMapCtxt->maxBufSeqN, &stackTPMNodeTop, &stackTPMNodeCnt);
        // stackTPMNodeDisplay(stackTPMNodeTop, stackTPMNodeCnt);
      }
    } // end else new TPMNode
  }

  // delTPMNodeHash(&visitTPMNodeHash);
  stckMemnodePopAll(&stackBufNodePathTop, &stackBufNodePathCnt);

  return 0;
}

static void
storeUnvisitTPMNodeChildren_dupl(
    u32 *nodeVisitIdx,
    TPMNode *farther,
    int maxSeqN,
    StackTPMNode **stackTPMNodeTop,
    u32 *stackTPMNodeCnt)
{
  Transition *firstChild = farther->tpmnode1.firstChild;
  while(firstChild != NULL) {
    TPMNode *childNode = firstChild->child;

    if(// !isTPMNodeVisited(*tpmnodeHash, childNode) &&
        // firstChild->hasVisit == 0 && // The transition had not been visited before
        childNode->tpmnode1.visitNodeIdx != *nodeVisitIdx &&
        (*stackTPMNodeTop)->currSeqN <= firstChild->seqNo && // enforces the increasing seqN policy
        firstChild->seqNo <= maxSeqN ) {
      stackTPMNodePush(childNode, farther, firstChild, stackTPMNodeTop, stackTPMNodeCnt);
      (*stackTPMNodeTop)->currSeqN = firstChild->seqNo;

      firstChild->hasVisit += 1;
      // print1Trans(firstChild);
    }
    else {
      // printf("-----skip: \n");
      // printNode(farther);
      // print1Trans(firstChild);
      // printNode(childNode);
    }
    firstChild = firstChild->next;
  }

}

/*
static int
dfs_build_hitmap(
    TPMContext *tpm,
    TPMNode2 *srcnode,
    HitMapContext *hitMapCtxt)
{
  StackTPMNode *stackTpmNodeTop = NULL;
  u32           stackTpmNodeCnt = 0;

  StckMemnode *stackBufNodePathTop = NULL;
  u32          stackBufNodePathCnt = 0;

  if(tpm == NULL || srcnode == NULL || hitMapCtxt == NULL) {
    fprintf(stderr, "dfs_build_hitmap: error: tpm:%p srcnode:%p HitMapCtxt:%p\n",
        tpm, srcnode, hitMapCtxt);
    return -1;
  }

  if(isHitMapNodeExist(srcnode, hitMapCtxt) )
    return 0;

//  printf("---------------\ndfs build HitMap, source:%p\n", srcnode);
//  printMemNode(srcnode);

  stackTPMNodePush((TPMNode *)srcnode, NULL, NULL, &stackTpmNodeTop, &stackTpmNodeCnt);
  stackTpmNodeTop->currSeqN = 0;    // init

  while(!isStackTPMNodeEmpty(stackTpmNodeTop) ) {
    TPMNode *top = stackTpmNodeTop->node;
    u32 lvl = 0;

//    if(stackTpmNodeTop->isVisit) {
    if(top->tpmnode1.src_ptr == srcnode) { // had been visited
      if(top->tpmnode1.type == TPM_Type_Memory && top->tpmnode2.bufid > 0) {
        add2HitMap(top, stackBufNodePathTop, stackBufNodePathCnt, stackTpmNodeTop, hitMapCtxt);
        stckMemnodePop(&lvl, &stackBufNodePathTop, &stackBufNodePathCnt);
      }

      stackTPMNodePop(&stackTpmNodeTop, &stackTpmNodeCnt);
    }
    else{ // unvisited node
//      stackTpmNodeTop->isVisit = 1; // mark visit in tpmnode stack
      top->tpmnode1.src_ptr = srcnode; // mark visit in tpmnode itself

      if(top->tpmnode1.type == TPM_Type_Memory && top->tpmnode2.bufid > 0) {
        stckMemnodePush((TPMNode2 *)top, lvl, &stackBufNodePathTop, &stackBufNodePathCnt);
      }
      else {
        if(stackTpmNodeTop->farther->tpmnode1.type == TPM_Type_Memory &&
            (TPMNode2 *)stackTpmNodeTop->farther == stackBufNodePathTop->memnode){
          stackBufNodePathTop->minSeqN = stackTpmNodeTop->dirctTrans->seqNo;
        }
      }

      if(top->tpmnode1.firstChild == NULL) { // leaf node
        if(top->tpmnode1.type == TPM_Type_Memory && top->tpmnode2.bufid > 0) {
          add2HitMap(top, stackBufNodePathTop, stackBufNodePathCnt, stackTpmNodeTop, hitMapCtxt);
          stckMemnodePop(&lvl, &stackBufNodePathTop, &stackBufNodePathCnt);
        }
        stackTPMNodePop(&stackTpmNodeTop, &stackTpmNodeCnt);
      }
      else {
        storeTPMNodeChildren(srcnode, hitMapCtxt->maxBufSeqN, &stackTpmNodeTop, &stackTpmNodeCnt);
//        printf("num of nodes in stack:%u\n", stackTpmNodeCnt);
      }
    }
  }

  stckMemnodePopAll(&stackBufNodePathTop, &stackBufNodePathCnt);
  return 0;
}

static void
storeTPMNodeChildren(
    TPMNode2 *srcnode,
    u32 maxSeqN,
    StackTPMNode **stackTpmNodeTop,
    u32 *stackTpmNodeCnt)
{
  TPMNode *farther = (*stackTpmNodeTop)->node;
  u32 far_trans = (*stackTpmNodeTop)->currSeqN;
//  printf("----- -----\nfarther's transition:%u\n", far_trans);
  Transition *firstChild = farther->tpmnode1.firstChild;

  while(firstChild != NULL) {
//    printf("transition seqNo:%u\n", firstChild->seqNo);
    TPMNode *child = firstChild->child;
    if(far_trans < firstChild->seqNo && // guarantee the dfs monotonic transition seqNo
        child->tpmnode1.src_ptr != srcnode && // replace hash table, if the node had been visit, not visit again
        firstChild->seqNo <= maxSeqN) {
      stackTPMNodePush(child, farther, firstChild, stackTpmNodeTop, stackTpmNodeCnt);
      (*stackTpmNodeTop)->currSeqN = firstChild->seqNo;   // stores the transition's seqNo,
      // farther's transition number
//      printNode(child);
    }
    else {
//      printf("dbg\n");
    }
    firstChild = firstChild->next;
  }
}

*/


static int
dfs2HitMapNode_PopAtEnd(
    TPMContext *tpm,
    TPMNode2 *srcnode,
    HitMapContext *hitMapCtxt)
{
  if(tpm == NULL || srcnode == NULL || hitMapCtxt == NULL) {
    fprintf(stderr, "dfs2HitMapNode_PopWhenNoChildren: tpm:%p srcnode:%p hitMap:%p\n", tpm, srcnode, hitMapCtxt);
    return -1;
  }

  if(isHitMapNodeExist(srcnode, hitMapCtxt) )
    return 0;

  TransitionHashTable *markVisitTransHT = NULL;
  Transition *sourceTrans = srcnode->firstChild;

  StackTransitionNode *stackTransTop = NULL;
  u32 stackTransCnt = 0;

  StckMemnode *stackBufNodePathTop = NULL;
  u32 stackBufNodePathCnt = 0;

  u32 dfsLevel = 0;   // Not used
  int stepCount = 0;

  if(sourceTrans == NULL) {
    // printf("dfs2HitMapNode: given source node is a leaf\n");
    // printMemNode(srcnode);
    return 0;
  }

  // printf("----------\ndfs2HitMapNode_PopWhenNoChildren source:%p\n", srcnode);
  // printMemNode(srcnode);
  // printTransAllChildren(sourceTrans);

  stckMemnodePush(srcnode, dfsLevel, &stackBufNodePathTop, &stackBufNodePathCnt);
  // stckMemnodeDisplay(stackBufNodePathTop, stackBufNodePathCnt);

  storeUnvisitChildren(&markVisitTransHT, sourceTrans,
      hitMapCtxt->maxBufSeqN, &stackTransTop, &stackTransCnt, dfsLevel);
  // stackTransDisplay(stackTransTop, stackTransCnt);

  while(!isStackTransEmpty(stackTransTop) ) {
    Transition *topTrans = stackTransTop->transition;
    TPMNode *dstNode = getTransitionDst(topTrans);
    u32 transLvl;   // Not used

    if(isTransitionVisited(markVisitTransHT, topTrans) ) {  // if the transition had been visited
      stackTransPop(&transLvl, &stackTransTop, &stackTransCnt);
      // stackTransDisplay(stackTransTop, stackTransCnt);
      popBufNode(dstNode, &stackBufNodePathTop, &stackBufNodePathCnt);
    }
    else {
      if(dstNode->tpmnode1.type == TPM_Type_Memory && isValidBufNode((TPMNode2 *)dstNode) ) {
        if(dstNode->tpmnode2.hasVisit != 0) { // the buf node had been visited by other source buffer node
          createHitMapRecord(stackBufNodePathTop->memnode, 0, (TPMNode2 *)dstNode, topTrans->seqNo, hitMapCtxt); // creates a transition to the visited buf node
          stackTransPop(&transLvl, &stackTransTop, &stackTransCnt);
          continue;
        }
        else {
          dstNode->tpmnode2.hasVisit = 1;
        }

        // printf("----------src hitmap node:\n");
        // printMemNodeLit(stackBufNodePathTop->memnode);
        // printf("dst hitmap node:\n");
        // printMemNodeLit((TPMNode2 *)dstNode);
        createHitMapRecord(stackBufNodePathTop->memnode, 0, (TPMNode2 *)dstNode, 0, hitMapCtxt);
        stckMemnodePush((TPMNode2 *)dstNode, dfsLevel, &stackBufNodePathTop, &stackBufNodePathCnt);
      }

      markVisitTransition(&markVisitTransHT, topTrans);

      if(dstNode->tpmnode1.firstChild == NULL) { // leaf nodes
        stackTransPop(&transLvl, &stackTransTop, &stackTransCnt);
        // stackTransDisplay(stackTransTop, stackTransCnt);
        popBufNode(dstNode, &stackBufNodePathTop, &stackBufNodePathCnt);
      }
      else {
        storeUnvisitChildren(&markVisitTransHT, dstNode->tpmnode1.firstChild,
            hitMapCtxt->maxBufSeqN, &stackTransTop, &stackTransCnt, dfsLevel);
        // stackTransDisplay(stackTransTop, stackTransCnt);
      }
    }
  }

  delTransitionHT(&markVisitTransHT);
  stackTransPopAll(&stackTransTop, &stackTransCnt);
  stckMemnodePopAll(&stackBufNodePathTop, &stackBufNodePathCnt);

  return stepCount;
}

static int
dfs2BuildHitMap_DBG(
    TPMContext *tpm,
    TPMNode2 *srcnode,
    HitMapContext *hitMapCtxt)
// Debug dfs build HitMap without intermediate node
{
  if(tpm == NULL || srcnode == NULL || hitMapCtxt == NULL) {
    fprintf(stderr, "dfs2HitMapNode_PopWhenNoChildren: tpm:%p srcnode:%p hitMap:%p\n", tpm, srcnode, hitMapCtxt);
    return -1;
  }

  if(isHitMapNodeExist(srcnode, hitMapCtxt) )
    return 0;

  TransitionHashTable *markVisitTransHT = NULL;
  Transition *sourceTrans = srcnode->firstChild;

  StackTransitionNode *stackTransTop = NULL;
  u32 stackTransCnt = 0;

  StckMemnode *stackBufNodePathTop = NULL;
  u32 stackBufNodePathCnt = 0;

  u32 dfsLevel = 0;   // Not used
  int stepCount = 0;

  if(sourceTrans == NULL) {
    // printf("dfs2HitMapNode: given source node is a leaf\n");
    // printMemNode(srcnode);
    return 0;

  }

  // printf("----------\ndfs2HitMapNode_PopWhenNoChildren source:%p\n", srcnode);
  // printMemNode(srcnode);
  // printTransAllChildren(sourceTrans);

  stckMemnodePush(srcnode, dfsLevel, &stackBufNodePathTop, &stackBufNodePathCnt);
  // stckMemnodeDisplay(stackBufNodePathTop, stackBufNodePathCnt);

  storeUnvisitChildren(&markVisitTransHT, sourceTrans,
      hitMapCtxt->maxBufSeqN, &stackTransTop, &stackTransCnt, dfsLevel);
  // stackTransDisplay(stackTransTop, stackTransCnt);

  while(!isStackTransEmpty(stackTransTop) ) {
    Transition *topTrans = stackTransTop->transition;
    TPMNode *dstNode = getTransitionDst(topTrans);
    u32 transLvl;   // Not used

    if(isTransitionVisited(markVisitTransHT, topTrans) ) {  // if the transition had been visited
      stackTransPop(&transLvl, &stackTransTop, &stackTransCnt);
      // stackTransDisplay(stackTransTop, stackTransCnt);
      popBufNode(dstNode, &stackBufNodePathTop, &stackBufNodePathCnt);
    }
    else {
      if(dstNode->tpmnode1.type == TPM_Type_Memory && isValidBufNode((TPMNode2 *)dstNode) ) {
        if(dstNode->tpmnode2.hasVisit != 0) { // the buf node had been visited by other source buffer node
          // createHitMapRecord(stackBufNodePathTop->memnode, 0, (TPMNode2 *)dstNode, 0, hitMapCtxt); // creates a transition to the visited buf node
          // stackTransPop(&transLvl, &stackTransTop, &stackTransCnt);
          // continue;
        }
        else {
          dstNode->tpmnode2.hasVisit = 1;
        }

        // printf("----------src hitmap node:\n");
        // printMemNodeLit(stackBufNodePathTop->memnode);
        // printf("dst hitmap node:\n");
        // printMemNodeLit((TPMNode2 *)dstNode);
        createHitMapRecord(stackBufNodePathTop->memnode, 0, (TPMNode2 *)dstNode, topTrans->seqNo, hitMapCtxt);
        stckMemnodePush((TPMNode2 *)dstNode, dfsLevel, &stackBufNodePathTop, &stackBufNodePathCnt);
      }

      markVisitTransition(&markVisitTransHT, topTrans);

      if(dstNode->tpmnode1.firstChild == NULL) { // leaf nodes
        stackTransPop(&transLvl, &stackTransTop, &stackTransCnt);
        // stackTransDisplay(stackTransTop, stackTransCnt);
        popBufNode(dstNode, &stackBufNodePathTop, &stackBufNodePathCnt);
      }
      else {
        storeUnvisitChildren(&markVisitTransHT, dstNode->tpmnode1.firstChild,
            hitMapCtxt->maxBufSeqN, &stackTransTop, &stackTransCnt, dfsLevel);
        // stackTransDisplay(stackTransTop, stackTransCnt);
      }
    }
  }

  delTransitionHT(&markVisitTransHT);
  stackTransPopAll(&stackTransTop, &stackTransCnt);
  stckMemnodePopAll(&stackBufNodePathTop, &stackBufNodePathCnt);

  return stepCount;
}


static void
popBufNode(
    TPMNode *dstNode,
    StckMemnode **stackBufNodePathTop,
    u32 *stackBufNodePathCnt)
{
  u32 transLvl;
  if(dstNode->tpmnode1.type == TPM_Type_Memory) {
    if((TPMNode2 *)dstNode == (*stackBufNodePathTop)->memnode) {
      stckMemnodePop(&transLvl, stackBufNodePathTop, stackBufNodePathCnt);
    }
  }
}

static int
dfsBuildHitMap_intermediateNode(
    TPMContext *tpm,
    TPMNode2 *srcnode,
    HitMapContext *hitMapCtxt)
{
  if(tpm == NULL || srcnode == NULL || hitMapCtxt == NULL) {
    fprintf(stderr, "dfsBuildHitMap_intermediateNode: tpm:%p srcnode:%p hitMap:%p\n", tpm, srcnode, hitMapCtxt);
    return -1;
  }

  if(isHitMapNodeExist(srcnode, hitMapCtxt) ) // if the srcnode had already been searched
    return 0;                               // no need to search again

  int maxSeqN, minSeqN;

  TransitionHashTable *HT_visitedTrans = NULL; // used to mark nodes had been visited during dfs (dfs routine)

  StackTransitionNode *stackTransTop = NULL;   // used to store transitions during dfs (routine)
  u32 stackTransCnt = 0;

  StackTPMNode *stackTPMNodePathTop = NULL;    // used to store path node during dfs (for building HitMap)
  u32 stackTPMNodePathCnt = 0;

  Transition *srcTrans = srcnode->firstChild;
  if(srcTrans == NULL) {
    // printf("dfs2HitMapNode: given source node is a leaf\n");
    // printMemNode(srcnode);
    return 0;
  }
  // printf("---------------\ndfsBuildHitMap_intermediateNode source:%p\n", srcnode);
  // printMemNode(srcnode);
  // printf("maxseqN:%u\n", hitMapCtxt->maxBufSeqN);

  tpmNodePush((TPMNode *)srcnode, &stackTPMNodePathTop, &stackTPMNodePathCnt);
  // printTPMNodeStack(stackTPMNodePathTop, stackTPMNodePathCnt);

  storeUnvisitChildren_Intermediate(&HT_visitedTrans, srcTrans, hitMapCtxt->maxBufSeqN, &stackTransTop, &stackTransCnt, 0);
  // stackTransDisplay(stackTransTop, stackTransCnt);

  while(!isStackTransEmpty(stackTransTop) ) {
    u32 transLvl;   // Not used, only for method interface
    Transition *topTrans = stackTransTop->transition;
    TPMNode *child = topTrans->child;

    if(child->tpmnode1.type == TPM_Type_Memory
        /* && child->tpmnode2.addr == 0xbffff240 */) {
      // printMemNodeLit((TPMNode2 *)child);
    }


    if(isTransitionVisited(HT_visitedTrans, topTrans) ) {  // if the transition had been examined and
      // has children been pushed to transtiion stack
      assert(child == stackTPMNodePathTop->node);
      processIntermediateTrans(child, stackTPMNodePathTop, stackTPMNodePathCnt, hitMapCtxt, topTrans->seqNo);

      tpmNodePop(&stackTPMNodePathTop, &stackTPMNodePathCnt); // pop the TPMNode stack accordingly
      // printTPMNodeStack(stackTPMNodePathTop, stackTPMNodePathCnt);
      stackTransPop(&transLvl, &stackTransTop, &stackTransCnt);
      // stackTransDisplay(stackTransTop, stackTransCnt);
    }
    else {  // if the transition hasn't been visited, examine the top of transiton stack
      // if(child->tpmnode1.type == TPM_Type_Memory)
      //     printMemNodeLit((TPMNode2 *)child);
      if(child->tpmnode1.hasVisit == 0){
        child->tpmnode1.hasVisit = 1;
      }
      else { // indicates the child had been visited by other source nodes, do not need to visit again
        processHasVisitTrans(child, stackTPMNodePathTop, stackTPMNodePathCnt, hitMapCtxt, topTrans->seqNo);

        stackTransPop(&transLvl, &stackTransTop, &stackTransCnt);
        // stackTransDisplay(stackTransTop, stackTransCnt);
        continue;
      }

      markVisitTransition(&HT_visitedTrans, topTrans); // mark the transtition as visited
      // even it could be a leaf

      tpmNodePush(child, &stackTPMNodePathTop, &stackTPMNodePathCnt); // push the TPMNode to stack, as path
      // printTPMNodeStack(stackTPMNodePathTop, stackTPMNodePathCnt);

      if(isLeafTransition(topTrans) ) {
        assert(child == stackTPMNodePathTop->node); // the top of TPMNode stack and the top of transtion
        // stack point to the same node
        processLeafTrans(child, stackTPMNodePathTop, stackTPMNodePathCnt, hitMapCtxt, topTrans->seqNo);

        tpmNodePop(&stackTPMNodePathTop, &stackTPMNodePathCnt); // pop the TPMNode stack accordingly
        // printTPMNodeStack(stackTPMNodePathTop, stackTPMNodePathCnt);
        stackTransPop(&transLvl, &stackTransTop, &stackTransCnt);
        // stackTransDisplay(stackTransTop, stackTransCnt);
      }
      else {
        storeUnvisitChildren_Intermediate(&HT_visitedTrans, child->tpmnode1.firstChild,
            hitMapCtxt->maxBufSeqN, &stackTransTop, &stackTransCnt, 0);
      }
    }
  }
  delTransitionHT(&HT_visitedTrans);
  stackTransPopAll(&stackTransTop, &stackTransCnt);
  tpmNodePopAll(&stackTPMNodePathTop, &stackTPMNodePathCnt);

  return 0;
}

static bool
isLeafTransition(Transition *trans)
{
  TPMNode *child = trans->child;
  if(child->tpmnode1.firstChild == NULL)
    return true;
  else
    return false;
}

static void
processIntermediateTrans(
    TPMNode *child,
    StackTPMNode *stackTPMNodePathTop,
    u32 stackTPMNodePathCnt,
    HitMapContext *hitMapCtxt,
    u32 transSeqN)
{
  if((child->tpmnode1.type == TPM_Type_Memory
      && child->tpmnode2.bufid > 0)
      || stackTPMNodePathTop->flagCreateHM == 1) { // if it's a memory node child or it belongs to path to a memory node
    stackTPMNodePathTop->flagCreateHM = 1;
    if(stackTPMNodePathCnt > 1)
    {
      stackTPMNodePathTop->next->flagCreateHM = 1;

      TPMNode *src = stackTPMNodePathTop->next->node;
      TPMNode *dst = stackTPMNodePathTop->node;
      createHitMapRecord_IntrmdtNode(src, dst, hitMapCtxt, transSeqN);
    }
  }
}

static void
processLeafTrans(
    TPMNode *leafChild,
    StackTPMNode *stackTPMNodePathTop,
    u32 stackTPMNodePathCnt,
    HitMapContext *hitMapCtxt,
    u32 transSeqN)
{
  if(leafChild->tpmnode1.type == TPM_Type_Memory
      && leafChild->tpmnode2.bufid > 0) { // if the leaf transition child is a memory node,
    // need to create HitMap nodes
    stackTPMNodePathTop->flagCreateHM = 1;

    if(stackTPMNodePathCnt > 1) {
      stackTPMNodePathTop->next->flagCreateHM = 1; // set last second item in TPMNode stack as true
      TPMNode *dst = stackTPMNodePathTop->node;
      TPMNode *src = stackTPMNodePathTop->next->node;
      createHitMapRecord_IntrmdtNode(src, dst, hitMapCtxt, transSeqN);
    }
  }
}

static void
processHasVisitTrans(
    TPMNode *child,
    StackTPMNode *stackTPMNodePathTop,
    u32 stackTPMNodePathCnt,
    HitMapContext *hitMapCtxt,
    u32 transSeqN)
// Nodes had been visited via other sources:
// 1. Memory nodes
//  should be in the hitmap, creates a transition to it
// 2. Non_memory node
//  if it's in the hitmap, creates a transition to it
//  otherwise, do nothing
{
  bool isMemNodeExist;
  if(child->tpmnode1.type == TPM_Type_Memory) {
    isMemNodeExist = isHitMapNodeExist((TPMNode2 *)child, hitMapCtxt);
    assert(isMemNodeExist == true);

    if(stackTPMNodePathCnt > 0) {
      TPMNode *src = stackTPMNodePathTop->node;
      TPMNode *dst = child;
      createHitMapRecord_IntrmdtNode(src, dst, hitMapCtxt, transSeqN);
    }
  }
  else {
    if(isIntermediateNodeExist((TPMNode1 *)child, hitMapCtxt) ) {
      if(stackTPMNodePathCnt > 0) {
        TPMNode *src = stackTPMNodePathTop->node;
        TPMNode *dst = child;
        createHitMapRecord_IntrmdtNode(src, dst, hitMapCtxt, transSeqN);
      }
    }
  }
}

/* TPMNode stack operations */
static void
tpmNodePush(
    TPMNode *node,
    StackTPMNode **stackTPMNodeTop,
    u32 *stackTPMNodeCnt)
{
  StackTPMNode *n = calloc(1, sizeof(StackTPMNode) );
  assert(n != NULL);

  n->node = node;
  n->next = *stackTPMNodeTop;
  n->flagCreateHM = 0;
  *stackTPMNodeTop = n;
  (*stackTPMNodeCnt)++;
}

static TPMNode *
tpmNodePop(StackTPMNode **stackTPMNodeTop, u32 *stackTPMNodeCnt)
{
  StackTPMNode *toDel;
  TPMNode *node = NULL;

  if(*stackTPMNodeTop != NULL) {
    toDel = *stackTPMNodeTop;
    *stackTPMNodeTop = toDel->next;
    node = toDel->node;

    free(toDel);
    (*stackTPMNodeCnt)++;
  }
  return node;
}

static void
printTPMNodeStack(StackTPMNode *stackTPMNodeTop, u32 stackTPMNodeCnt)
{
  if(stackTPMNodeCnt > 0)
    printf("---------------\ntotal TPM stack nodes:%u\n", stackTPMNodeCnt);

  while(stackTPMNodeTop != NULL) {
    TPMNode *node = stackTPMNodeTop->node;
    if(node->tpmnode1.type == TPM_Type_Memory)
      printMemNodeLit((TPMNode2 *)node);
    else
      printNonmemNode((TPMNode1 *)node);

    stackTPMNodeTop = stackTPMNodeTop->next;
  }
}

static void
tpmNodePopAll(StackTPMNode **stackTPMNodeTop, u32 *stackTPMNodeCnt)
{
  while(*stackTPMNodeTop != NULL) {
    tpmNodePop(stackTPMNodeTop, stackTPMNodeCnt);
  }
}

static bool
isTPMNodeStackEmpty(StackTPMNode *stackTPMNodeTop)
{
  if(stackTPMNodeTop != NULL)
    return false;
  else
    return true;
}

#if TPM_RE_TRANSITON
/*
 * dfs search propagate reversely.
 * Returns:
 *  0: success
 *  <0: error
 */
static int
dfs_disp_reverse_propgt(TPMContext *tpm, TPMNode2 *src)
{
  TPMNodeHash *visit_nodehash = NULL;

  StackTPMNode *stack_nodetop = NULL;
  u32 stack_nodecnt = 0;

  if(tpm != NULL && src != NULL)
  {
    printf("--------------------\ndfs source: ");
    printMemNodeLit(src);

    stackTPMNodePush((TPMNode *)src, NULL, NULL, &stack_nodetop, &stack_nodecnt);
    while(!isStackTPMNodeEmpty(stack_nodetop) ) {
      TPMNode *topnode = stackTPMNodePop(&stack_nodetop, &stack_nodecnt);
      markVisitTPMNode(&visit_nodehash, topnode);

      if(topnode->tpmnode1.type == TPM_Type_Memory &&
         topnode->tpmnode2.lastUpdateTS < 0)
      {
        printMemNodeLit((TPMNode2 *)topnode);
      }
      push_unvisitnode_children_reverse(&visit_nodehash, topnode,
                                        &stack_nodetop, &stack_nodecnt);
    }
  }
  else
  {
    fprintf(stderr, "error: dfs: tpm:%p src:%p\n", tpm, src);
    return -1;
  }

  delTPMNodeHash(&visit_nodehash);
  return 0;
}

static void
push_unvisitnode_children_reverse(
    TPMNodeHash **visit_nodehash,
    TPMNode *child,
    StackTPMNode **stack_nodetop,
    u32 *stack_nodecnt)
{
  Transition *first_farther = child->tpmnode1.first_farther;
  while(first_farther != NULL) {
    TPMNode *farther_node = first_farther->child;
    if(!isTPMNodeVisited(*visit_nodehash, farther_node) )
    {
      stackTPMNodePush(farther_node, child, first_farther, stack_nodetop, stack_nodecnt);
    }
    first_farther = first_farther->next;
  }
}
#endif

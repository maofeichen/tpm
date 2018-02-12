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

static int 
dfsfast(TPMContext *tpm,
        TPMPropgtSearchCtxt *tpmPSCtxt,
        AddrPropgtToNode **addrPropgtToNode,
        TPMNode2 *srcnode);

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

static void 
storeAllUnvisitChildrenFast(
        TransitionHashTable **transitionht,
        Transition *firstChild,
        int maxseq,
        StackTransitionNode **stackTransTop,
        u32 *stackTransCnt,
        u32 dfsLevel);

static void
storeAllUnvisitChildren_NoMark(
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
dfs2HitMapNode_PopWhenNoChildren(
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
        TPMNode *leafChild,
        StackTPMNode *stackTPMNodePathTop,
        u32 stackTPMNodePathCnt,
        HitMapContext *hitMapCtxt);

static void
processLeafTrans(
        TPMNode *leafChild,
        StackTPMNode *stackTPMNodePathTop,
        u32 stackTPMNodePathCnt,
        HitMapContext *hitMapCtxt);

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

/* HitMap node propagate */
static int
dfsHitMapNodePropagate(HitMapNode *srcnode);

/* HitMap Transition hash table operation */
static void
add2HitTransitionHT(HitTransitionHashTable **hitTransitionht, HitTransition *toTrans);

static HitTransitionHashTable*
findInHitTransitionHT(HitTransitionHashTable *hitTransitionht, HitTransition *hitTrans);

static void
delHitTransitionHT(HitTransitionHashTable **hitTransitionht);

static void
countHitTransitionHT(HitTransitionHashTable *hitTransitionht);

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

/* functions */

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

int 
memnodePropgtFast(
        TPMContext *tpm,
        TPMPropgtSearchCtxt *tpmPSCtxt,
        AddrPropgtToNode **addrPropgtToNode,
        TPMNode2 *srcnode)
{
    return dfsfast(tpm, tpmPSCtxt, addrPropgtToNode, srcnode);
}

int
bufnodePropgt2HitMapNode(
        TPMContext *tpm,
        TPMNode2 *srcnode,
        HitMapContext *hitMapCtxt)
{
    // return dfs2HitMapNode(tpm, srcnode, hitMapCtxt);
    // return dfs2HitMapNode_PopWhenNoChildren(tpm, srcnode, hitMapCtxt);
    return dfsBuildHitMap_intermediateNode(tpm, srcnode, hitMapCtxt);
}

int
hitMapNodePropagate(HitMapNode *srcnode)
// Returns:
//  >= 0: num of hitmap nodes that the srcnode can propagate to
//  <0: error
{
    return dfsHitMapNodePropagate(srcnode);
}


int
printMemNodePropagate(TPMContext *tpm, TPMNode2 *s)
{
	return dfsPrintResult(tpm, s);
}

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
				// printf("propagate to addr:%x val:%x\n", dst->tpmnode2.addr, dst->tpmnode2.val);
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

static int 
dfsfast(TPMContext *tpm,
        TPMPropgtSearchCtxt *tpmPSCtxt,
        AddrPropgtToNode **addrPropgtToNode,
        TPMNode2 *srcnode)
{
	if(tpm == NULL || srcnode == NULL || tpmPSCtxt == NULL) {
		fprintf(stderr, "error: dfs: tpm:%p srcnode:%p tpmPSCtxt:%p\n", tpm, srcnode, tpmPSCtxt);
		return -1;
	}
	// printMemNode(srcnode);

	TransitionHashTable *markVisitTransHT = NULL;
	Transition *sourceTrans = srcnode->firstChild;

	StackTransitionNode *stackTransTop = NULL;
	u32 stackTransCnt = 0;
	u32 dfsLevel = 0;

	StackTransitionNode *stackMemTransTop = NULL;
	u32 stackMemTransCnt = 0;

	int stepCount = 0;

	if(sourceTrans != NULL) {
	    dfsLevel++;
	    storeAllUnvisitChildrenFast(&markVisitTransHT, sourceTrans, tpmPSCtxt->maxSeqN, &stackTransTop, &stackTransCnt, dfsLevel);
	    // stackTransDisplay(stackTransTop, stackTransCnt);

	    while(!isStackTransEmpty(stackTransTop) ) {
	        u32 transLvl;
	        Transition *popTrans = stackTransPop(&transLvl, &stackTransTop, &stackTransCnt);
			TPMNode *dstnode = getTransitionDst(popTrans);

			if(dstnode->tpmnode1.type == TPM_Type_Memory) {
			    // printMemNode((TPMNode2 *)dstnode);
			}

			stepCount++;
			storeAllUnvisitChildrenFast(&markVisitTransHT, dstnode->tpmnode1.firstChild, tpmPSCtxt->maxSeqN, &stackTransTop, &stackTransCnt, dfsLevel);
			// stackTransDisplay(stackTransTop, stackTransCnt);
			dfsLevel++;
	    }
	}
	else {
	    printf("dfsfast: given source node is a leaf\n");
	    printMemNode(srcnode);
	}
	delTransitionHT(&markVisitTransHT);
	stackTransPopAll(&stackTransTop, &stackTransCnt);

	return stepCount;
}

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
			if(dst->tpmnode1.type == TPM_Type_Memory)
				printf("propagate to addr:%x val:%x\n", dst->tpmnode2.addr, dst->tpmnode2.val);
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
        printf("node levle:%u\n", stckMemnodeTop->level);
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

static void 
storeAllUnvisitChildrenFast(
        TransitionHashTable **transitionht,
        Transition *firstChild,
        int maxseq,
        StackTransitionNode **stackTransTop,
        u32 *stackTransCnt,
        u32 dfsLevel)
// Same as storeAllUnvisitChildren, additionally add level info
{

    while(firstChild != NULL) {
        if(!isTransitionVisited(*transitionht, firstChild)
           && firstChild->seqNo <= maxseq) {
            // transStackPush(firstChild);
            stackTransPush(firstChild, dfsLevel, stackTransTop, stackTransCnt);
            markVisitTransition(transitionht, firstChild);
        }
        firstChild = firstChild->next;
    }
}

static void
storeAllUnvisitChildren_NoMark(
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
           && firstChild->child->tpmnode1.hasVisit == 0 ) { // A bug in propagate
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
    TransitionHashTable *markVisitTransHT = NULL;
    Transition *sourceTrans = srcnode->firstChild;

    StackTransitionNode *stackTransTop = NULL;
    u32 stackTransCnt = 0;

    StckMemnode *stackBufNodePathTop = NULL;
    u32 stackBufNodePathCnt = 0;

    u32 dfsLevel = 0;
    int stepCount = 0;

    if(sourceTrans == NULL) {
        printf("dfs2HitMapNode: given source node is a leaf\n");
        printMemNode(srcnode);
        return 0;

    }

    stckMemnodePush(srcnode, dfsLevel, &stackBufNodePathTop, &stackBufNodePathCnt);
    // stckMemnodeDisplay(stackBufNodePathTop, stackBufNodePathCnt);
    printf("--------------------\ndfs depth level:%u\n", dfsLevel);
    printMemNodeLit(srcnode);

    storeAllUnvisitChildrenFast(&markVisitTransHT, sourceTrans,
            hitMapCtxt->maxBufSeqN, &stackTransTop, &stackTransCnt, dfsLevel);
    // stackTransDisplay(stackTransTop, stackTransCnt);

    while(!isStackTransEmpty(stackTransTop) ) {
        u32 transLvl;

        // printTransitionNode(stackTransTop);
        Transition *popTrans = stackTransPop(&transLvl, &stackTransTop, &stackTransCnt);
        dfsLevel = transLvl + 1;

        TPMNode *dstnode = getTransitionDst(popTrans);
        if(dstnode->tpmnode1.type == TPM_Type_Memory && isValidBufNode((TPMNode2 *)dstnode) ) {
            // printf("--------------------\ndfs depth level:%u\n", transLvl);
            printMemNodeLit((TPMNode2 *)dstnode);
            // printMemNode((TPMNode2 *)dstnode);

            storeDFSBufNodeVisitPath((TPMNode2 *)dstnode, transLvl, &stackBufNodePathTop, &stackBufNodePathCnt);
            // stckMemnodeDisplay(stackBufNodePathTop, stackBufNodePathCnt);

        }
        else {
            // printf("--------------------\nTransition level:%u\n", transLvl);
            // printNonmemNode((TPMNode1 *)dstnode);
        }

        stepCount++;
        storeAllUnvisitChildrenFast(&markVisitTransHT, dstnode->tpmnode1.firstChild,
                hitMapCtxt->maxBufSeqN, &stackTransTop, &stackTransCnt, dfsLevel);
        // stackTransDisplay(stackTransTop, stackTransCnt);
        // dfsLevel++;
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
dfs2HitMapNode_PopWhenNoChildren(
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

    storeAllUnvisitChildren_NoMark(&markVisitTransHT, sourceTrans,
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
            markVisitTransition(&markVisitTransHT, topTrans);
            if(dstNode->tpmnode1.hasVisit == 0)
                dstNode->tpmnode1.hasVisit = 1;

            if(dstNode->tpmnode1.type == TPM_Type_Memory && isValidBufNode((TPMNode2 *)dstNode) ) {
                // printf("----------src hitmap node:\n");
                // printMemNodeLit(stackBufNodePathTop->memnode);
                // printf("dst hitmap node:\n");
                // printMemNodeLit((TPMNode2 *)dstNode);
                createHitMapRecord(stackBufNodePathTop->memnode, 0, (TPMNode2 *)dstNode, 0, hitMapCtxt);
                stckMemnodePush((TPMNode2 *)dstNode, dfsLevel, &stackBufNodePathTop, &stackBufNodePathCnt);
            }
            else {}

            if(dstNode->tpmnode1.firstChild == NULL) { // leaf nodes
                stackTransPop(&transLvl, &stackTransTop, &stackTransCnt);
                // stackTransDisplay(stackTransTop, stackTransCnt);

                popBufNode(dstNode, &stackBufNodePathTop, &stackBufNodePathCnt);
            }
            else {
              storeAllUnvisitChildren_NoMark(&markVisitTransHT, dstNode->tpmnode1.firstChild,
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

    TransitionHashTable *HT_visitedTrans = NULL; // used to mark nodes had been visited during dfs (dfs routine)

    StackTransitionNode *stackTransTop = NULL;  // used to store transitions during dfs (routine)
    u32 stackTransCnt = 0;

    StackTPMNode *stackTPMNodePathTop = NULL;    // used to store path node during dfs (for building HitMap)
    u32 stackTPMNodePathCnt = 0;

    Transition *srcTrans = srcnode->firstChild;
    if(srcTrans == NULL) {
        printf("dfs2HitMapNode: given source node is a leaf\n");
        printMemNode(srcnode);
        return 0;
    }
    printf("---------------\ndfsBuildHitMap_intermediateNode source:%p\n", srcnode);
    printMemNode(srcnode);

    tpmNodePush((TPMNode *)srcnode, &stackTPMNodePathTop, &stackTPMNodePathCnt);
    printTPMNodeStack(stackTPMNodePathTop, stackTPMNodePathCnt);

    storeAllUnvisitChildren_NoMark(&HT_visitedTrans, srcTrans, hitMapCtxt->maxBufSeqN, &stackTransTop, &stackTransCnt, 0);
    // stackTransDisplay(stackTransTop, stackTransCnt);

    while(!isStackTransEmpty(stackTransTop) ) {
        u32 transLvl;   // Not used, only for method interface
        Transition *topTrans = stackTransTop->transition;
        TPMNode *child = topTrans->child;

        if(isTransitionVisited(HT_visitedTrans, topTrans) ) {  // if the transition had been examined and
                                                               // has children been pushed to transtiion stack
            assert(child == stackTPMNodePathTop->node);
            processIntermediateTrans(child, stackTPMNodePathTop, stackTPMNodePathCnt, hitMapCtxt);

            tpmNodePop(&stackTPMNodePathTop, &stackTPMNodePathCnt); // pop the TPMNode stack accordingly
            // printTPMNodeStack(stackTPMNodePathTop, stackTPMNodePathCnt);
            stackTransPop(&transLvl, &stackTransTop, &stackTransCnt);
            // stackTransDisplay(stackTransTop, stackTransCnt);
        }
        else {  // if the transition hasn't been visited, examine the top of transiton stack
            // if(child->tpmnode1.type == TPM_Type_Memory)
            //     printMemNodeLit((TPMNode2 *)child);
            markVisitTransition(&HT_visitedTrans, topTrans); // mark the transtition as visited
                                                             // even it could be a leaf
            tpmNodePush(child, &stackTPMNodePathTop, &stackTPMNodePathCnt); // push the TPMNode to stack, as path
            // printTPMNodeStack(stackTPMNodePathTop, stackTPMNodePathCnt);

            if(isLeafTransition(topTrans) ) {
                assert(child == stackTPMNodePathTop->node); // the top of TPMNode stack and the top of transtion
                                                            // stack point to the same node
                processLeafTrans(child, stackTPMNodePathTop, stackTPMNodePathCnt, hitMapCtxt);

                tpmNodePop(&stackTPMNodePathTop, &stackTPMNodePathCnt); // pop the TPMNode stack accordingly
                // printTPMNodeStack(stackTPMNodePathTop, stackTPMNodePathCnt);
                stackTransPop(&transLvl, &stackTransTop, &stackTransCnt);
                // stackTransDisplay(stackTransTop, stackTransCnt);
            }
            else {
                storeAllUnvisitChildren_NoMark(&HT_visitedTrans, child->tpmnode1.firstChild,
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
        TPMNode *leafChild,
        StackTPMNode *stackTPMNodePathTop,
        u32 stackTPMNodePathCnt,
        HitMapContext *hitMapCtxt)
{
    if((leafChild->tpmnode1.type == TPM_Type_Memory
        && leafChild->tpmnode2.bufid > 0)
       || stackTPMNodePathTop->flagCreateHM == 1) { // if it's a memory node child or it belongs to path to a memory node
        stackTPMNodePathTop->flagCreateHM = 1;
        if(stackTPMNodePathCnt > 1)
        {
            stackTPMNodePathTop->next->flagCreateHM = 1;

            TPMNode *src = stackTPMNodePathTop->next->node;
            TPMNode *dst = stackTPMNodePathTop->node;
            createHitMapRecord_IntrmdtNode(src, dst, hitMapCtxt);
        }
    }
}

static void
processLeafTrans(
        TPMNode *leafChild,
        StackTPMNode *stackTPMNodePathTop,
        u32 stackTPMNodePathCnt,
        HitMapContext *hitMapCtxt)
{
    if(leafChild->tpmnode1.type == TPM_Type_Memory
       && leafChild->tpmnode2.bufid > 0) { // if the leaf transition child is a memory node,
                                           // need to create HitMap nodes
        stackTPMNodePathTop->flagCreateHM = 1;

        if(stackTPMNodePathCnt > 1) {
            stackTPMNodePathTop->next->flagCreateHM = 1; // set last second item in TPMNode stack as true
            TPMNode *dst = stackTPMNodePathTop->node;
            TPMNode *src = stackTPMNodePathTop->next->node;
            createHitMapRecord_IntrmdtNode(src, dst, hitMapCtxt);
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


/* HitMap node propagate */
static int
dfsHitMapNodePropagate(HitMapNode *srcnode)
{
    if(srcnode == NULL) {
        fprintf(stderr, "dfsHitMapNodePropagate: hit map srcnode:%p\n", srcnode);
        return -1;
    }

    HitTransitionHashTable *markVisitHitTransHT = NULL;
    HitTransition *sourceHitTrans = srcnode->firstChild;

    StackHitTransitionItem *stackHitTransTop = NULL;
    u32 stackHitTransCnt = 0;

    if(sourceHitTrans == NULL) {
        printf("given source node is a leaf\n");
        printHitMapNode(srcnode);
        return 0;
    }

    storeAllUnvisitHitTransChildren(&markVisitHitTransHT, sourceHitTrans, 0,
            &stackHitTransTop, &stackHitTransCnt);
    // stackHitTransDisplay(stackHitTransTop, stackHitTransCnt);

    while(!isStackHitTransEmpty(stackHitTransTop) ) {
        HitTransition *popTrans = stackHitTransPop(&stackHitTransTop, &stackHitTransCnt);
        HitMapNode *popDstHitMapNode = popTrans->child;
        printHitMapNode(popDstHitMapNode);

        storeAllUnvisitHitTransChildren(&markVisitHitTransHT, popDstHitMapNode->firstChild, 0,
                &stackHitTransTop, &stackHitTransCnt);
        // stackHitTransDisplay(stackHitTransTop, stackHitTransCnt);

    }
    delHitTransitionHT(&markVisitHitTransHT);
    stackHitTransPopAll(&stackHitTransTop, &stackHitTransCnt);

    return 0;
}

static void
add2HitTransitionHT(HitTransitionHashTable **hitTransitionht, HitTransition *toTrans)
{
    HitTransitionHashTable *t;
    t = findInHitTransitionHT(*hitTransitionht, toTrans);
    if(t == NULL) {
        t = calloc(1, sizeof(HitTransitionHashTable));
        t->toTrans = toTrans;
        HASH_ADD(hh_hitTrans, *hitTransitionht, toTrans, 4, t);
    }
    else {}
}

static HitTransitionHashTable*
findInHitTransitionHT(HitTransitionHashTable *hitTransitionht, HitTransition *hitTrans)
{
    HitTransitionHashTable *s = NULL;
    HASH_FIND(hh_hitTrans, hitTransitionht, hitTrans, 4, s);
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
    // TODO
}

static void
stackHitTransPush(
        HitTransition *hitTrans,
        StackHitTransitionItem **stackHitTransTop,
        u32 *stackHitTransCnt)
{
    StackHitTransitionItem *i = calloc(1, sizeof(StackHitTransitionItem));
    i->transition = hitTrans;

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
storeAllUnvisitHitTransChildren(
        HitTransitionHashTable **hitTransitionht,
        HitTransition *firstChild,
        int maxseq,
        StackHitTransitionItem **stackHitTransTop,
        u32 *stackHitTransCnt)
{

    while(firstChild != NULL) {
        if(!isHitTransitionVisited(*hitTransitionht, firstChild)
           /* && firstChild->seqNo <= maxseq */) {
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

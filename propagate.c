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

/* IGNORE! stack of memory nodes during dfsfast */
static void
stckMemnodePush(TPMNode2 *memnode, StckMemnode **stckMemnodeTop, u32 *stckMemnodeCnt);

static TPMNode2 *
stckMemnodePop(StckMemnode **stckMemnodeTop, u32 *stckMemnodeCnt);

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
storePropagateDstMemNode(TPMNode2 *memNode, TaintedBuf **dstMemNodes);

/* dfs implementation: buf node propagates to hitmap nodes */
static int
dfs2HitMapNode(
        TPMContext *tpm,
        TPMNode2 *srcnode,
        HitMapContext *hitMapCtxt);

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
    return dfs2HitMapNode(tpm, srcnode, hitMapCtxt);
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
stckMemnodePush(TPMNode2 *memnode, StckMemnode **stckMemnodeTop, u32 *stckMemnodeCnt)
{
    StckMemnode *n = calloc(1, sizeof(StckMemnode) );
    assert(n != NULL);
    n->memnode = memnode;
    n->next = *stckMemnodeTop;
    *stckMemnodeTop = n;
    (*stckMemnodeCnt)++;
}

static TPMNode2 *
stckMemnodePop(StckMemnode **stckMemnodeTop, u32 *stckMemnodeCnt)
{
    StckMemnode *toDel;
    TPMNode2 *memnode = NULL;

    if(*stckMemnodeTop != NULL) {
        toDel = *stckMemnodeTop;
        *stckMemnodeTop = toDel->next;
        memnode = toDel->memnode;
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
        printMemNode(stckMemnodeTop->memnode);
        stckMemnodeTop = stckMemnodeTop->next;
    }
}

static void
stckMemnodePopAll(StckMemnode **stckMemnodeTop, u32 *stckMemnodeCnt)
{
    while(*stckMemnodeTop != NULL){
        stckMemnodePop(stckMemnodeTop, stckMemnodeCnt);
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
    return 0;
}

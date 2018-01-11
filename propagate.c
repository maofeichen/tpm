#include "propagate.h"
#include <stdbool.h>
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
dfsPrintResult(TPMContext *tpm, TPMNode2 *s);

/* dfs operation */
static void 
markVisitTransition(TransitionHashTable **transitionht, Transition *transition);

static bool 
isTransitionVisited(TransitionHashTable *transitionht, Transition *transition);

static void 
storeAllUnvisitChildren(TransitionHashTable **transitionht, Transition *firstChild);

static void 
storePropagateDstMemNode(TPMNode2 *memNode, TaintedBuf **dstMemNodes);

/* functions */

//Addr2NodeItem *
//createAddr2NodeItem(u32 addr, TPMNode2 *memNode, Addr2NodeItem *subHash, TaintedBuf *toMemNode)
//{
//	Addr2NodeItem *i = NULL;
//	i = malloc(sizeof(Addr2NodeItem) );
//	i->addr = addr;
//	i->node = memNode;
//	i->subHash 	 = subHash;
//	i->toMemNode = toMemNode;
//	return i;
//}

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
		storeAllUnvisitChildren(&markVisitTransHT, source_trans);
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
			storeAllUnvisitChildren(&markVisitTransHT, dst->tpmnode1.firstChild);
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
		storeAllUnvisitChildren(&markVisitTransHT, source_trans);
		while(!isTransStackEmpty() ) {
			Transition *pop = transStackPop();
			TPMNode *dst = getTransitionDst(pop);
// #ifdef DEBUG
			if(dst->tpmnode1.type == TPM_Type_Memory)
				printf("propagate to addr:%x val:%x\n", dst->tpmnode2.addr, dst->tpmnode2.val);
// #endif
			stepCount++;

			storeAllUnvisitChildren(&markVisitTransHT, dst->tpmnode1.firstChild);
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
storeAllUnvisitChildren(TransitionHashTable **transitionht, Transition *firstChild)
{
	while(firstChild != NULL){
		if(!isTransitionVisited(*transitionht, firstChild) ) {
			transStackPush(firstChild);
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

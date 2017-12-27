#include <stdbool.h>
#include "utlist.h"
#include "propagate.h"

/* TransitionHashTable operation */
static void 
add_trans_ht(TransitionHashTable **transitionht, u32 seqNo, Transition *toTrans);

static TransitionHashTable *
find_trans_ht(TransitionHashTable *transitionht, u32 seqNo);

static void
del_trans_ht(TransitionHashTable **transitionht);

static void 
count_trans_ht(TransitionHashTable *transitionht);

/* Stack of Transition node operation */
StackTransitionNode *stackTransTop = NULL;
u32 stackCount = 0;

static void 
stackTransPush(Transition *transition);

static Transition * 
stackTransPop();

static void 
stackTransDisplay();

static void 
stackTransPopAll();

static bool 
isStackTransEmpty();

/* get propagate implement */
static int 
dfs(TPMContext *tpm, TPMNode2 *s, TaintedBuf **dstBuf);

static int 
dfs_print(TPMContext *tpm, TPMNode2 *s);

/* dfs operation */
static void 
markVisitTransition(TransitionHashTable **transitionht, Transition *transition);

static bool 
isTransitionVisited(TransitionHashTable *transitionht, Transition *transition);

static void 
storeAllUnvisitChildren(TransitionHashTable **transitionht, Transition *firstChild);

static TPMNode *
getDestination(Transition *transition);

static u32 
getChildrenNum(Transition *firstChild);

static void 
storeReachMemNode(TPMNode2 *memNode, TaintedBuf **dstBuf);

int 
memNodeReachBuf(TPMContext *tpm, TPMNode2 *s, TaintedBuf **dstBuf)
{
	return dfs(tpm, s, dstBuf);
}

int 
print_propagation(TPMContext *tpm, TPMNode2 *s)
{
	return dfs_print(tpm, s);
}

static int
dfs(TPMContext *tpm, TPMNode2 *s, TaintedBuf **dstBuf)
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
		while(!isStackTransEmpty() ) {
			Transition *pop = stackTransPop();
			TPMNode *dst = getDestination(pop);
// #ifdef DEBUG
			if(dst->tpmnode1.type == TPM_Type_Memory) {
				// printf("propagate to addr:%x val:%x\n", dst->tpmnode2.addr, dst->tpmnode2.val);
				storeReachMemNode(&(dst->tpmnode2), dstBuf);
			}
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
	del_trans_ht(&markVisitTransHT);
	stackTransPopAll();

	return stepCount;	
}

static int 
dfs_print(TPMContext *tpm, TPMNode2 *s)
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
		while(!isStackTransEmpty() ) {
			Transition *pop = stackTransPop();
			TPMNode *dst = getDestination(pop);
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
	del_trans_ht(&markVisitTransHT);
	stackTransPopAll();

	return stepCount;	
}

static void 
add_trans_ht(TransitionHashTable **transitionht, u32 seqNo, Transition *toTrans)
{
	TransitionHashTable *t;
	t = find_trans_ht(*transitionht, seqNo);
	if(t == NULL ) {
		t = malloc(sizeof(TransitionHashTable) );
		t->seqNo = seqNo;
		HASH_ADD(hh_trans, *transitionht, seqNo, 4, t);
		t->toTrans = toTrans;
	}
	else {}	// Not update
}

static TransitionHashTable *
find_trans_ht(TransitionHashTable *transitionht, u32 seqNo)
{
	TransitionHashTable *s = NULL;
	HASH_FIND(hh_trans, transitionht, &seqNo, 4, s);
	return s;
}

static void
del_trans_ht(TransitionHashTable **transitionht)
{
	TransitionHashTable *curr, *tmp;
	HASH_ITER(hh_trans, *transitionht, curr, tmp) {
		HASH_DELETE(hh_trans, *transitionht, curr);
		free(curr);
	}
	// printf("del transition hash table\n");
}

static void 
count_trans_ht(TransitionHashTable *transitionht)
{
	u32 num;
	num = HASH_CNT(hh_trans, transitionht);
	printf("total:%u transitions in hash table\n", num);
}

static void 
stackTransPush(Transition *transition)
{
	StackTransitionNode *n = malloc(sizeof(StackTransitionNode) );
	n->transition = transition;
	n->next = stackTransTop;
	stackTransTop = n;
	stackCount++;
}

static Transition *
stackTransPop()
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
stackTransDisplay()
{
	StackTransitionNode *n = stackTransTop;
	while(n != NULL) {
		printf("Transition:%p seqNo:%u\n", n->transition, n->transition->seqNo);
		n = n->next;
	}
}

static void 
stackTransPopAll()
{
	while(stackTransTop != NULL) {
		stackTransPop();
	}
}

static bool 
isStackTransEmpty()
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

	add_trans_ht(transitionht, transition->seqNo, transition);
}

static bool 
isTransitionVisited(TransitionHashTable *transitionht, Transition *transition)
{
	if(transition == NULL)
		return false;

	TransitionHashTable *found = NULL;
	u32 seqNo;

	seqNo = transition->seqNo;
	found = find_trans_ht(transitionht, seqNo);
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
			stackTransPush(firstChild);
			markVisitTransition(transitionht, firstChild);
		}
		firstChild = firstChild->next;
	}
}

static TPMNode *
getDestination(Transition *transition)
{
	if(transition != NULL)
		return transition->child;
	else 
		return NULL;
}

static u32 
getChildrenNum(Transition *firstChild)
{
	u32 num = 0;
	while(firstChild != NULL) {
		num++;
		firstChild = firstChild->next;
	}
	return num;
}

static void 
storeReachMemNode(TPMNode2 *memNode, TaintedBuf **dstBuf)
{
	TaintedBuf *node = createTaintedBuf(memNode);
	LL_APPEND(*dstBuf, node);
}
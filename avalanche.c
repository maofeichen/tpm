#include "avalanche.h"

/* TransitionHashTable operation */
static void 
add_trans_ht(TransitionHashTable **transitionht, u32 seqNo, Transition *toTrans);

static TransitionHashTable *
find_trans_ht(TransitionHashTable *transitionht, u32 seqNo);

static void
del_trans_ht(TransitionHashTable *transitionht);

static void 
count_trans_ht(TransitionHashTable *transitionht);

/* Stack of Transition node operation */
StackTransitionNode *stackTransTop = NULL;

static void 
stackTransPush(Transition *transition);

static void 
stackTransPop();

int 
dfs(TPMContext *tpm, TPMNode2 *s)
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
	printf("dfs: tpm:%p\nsource ", tpm);
	print_mem_node(s);
	printf("--------------------\n");
// #endif

	TransitionHashTable *transitionht = NULL;

	return 0;	
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
	else {}
}

static TransitionHashTable *
find_trans_ht(TransitionHashTable *transitionht, u32 seqNo)
{

}
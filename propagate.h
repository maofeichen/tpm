#ifndef PROPAGATE_H
#define PROPAGATE_H 

#include "uthash.h"

#include "tpmnode.h"
#include "tpm.h"
#include "type.h"

// Transition hash table
//	uses in dfs to mark transitions that had been visited
typedef struct TransitionHashTable
{
	u32 seqNo;
	Transition *toTrans;
	UT_hash_handle hh_trans;
} TransitionHashTable;

typedef struct StackTransitionNode 
{
	Transition *transition;
	struct StackTransitionNode *next;
} StackTransitionNode;

int 
memNodeReachBuf(TPMContext *tpm, TPMNode2 *s, TaintedBuf **dstBuf);

int 
print_propagation(TPMContext *tpm, TPMNode2 *s);

#endif
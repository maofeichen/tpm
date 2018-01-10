#ifndef PROPAGATE_H
#define PROPAGATE_H 

#include "uthash.h"
#include "avalanchetype.h"
#include "tpmnode.h"
#include "tpm.h"
#include "type.h"

typedef struct TransitionHashTable
// Transition hash table
//	uses in dfs to mark transitions that had been visited
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

//struct addr2NodeItem
//{
//    u32 addr;				/* 32-bit address: src addr in 1st level hash; dst addr in 2nd level hash */
//    struct TPMNode2 *node;	/* used as key to hash: src node in 1st level hash; dst node in 2nd level hash */
//    struct addr2NodeItem *subHash;	  /* next level hash */
//    TaintedBuf *toMemNode; 			  // the mem node that the source node can propagate
//    UT_hash_handle hh_addr2NodeItem;  /* makes this structure hashable */
//};
//typedef struct addr2NodeItem Addr2NodeItem;

Addr2NodeItem *
createAddr2NodeItem(u32 addr, TPMNode2 *memNode, Addr2NodeItem *subHash, TaintedBuf *toMemNode);

int
cmpAddr2NodeItem(Addr2NodeItem *l, Addr2NodeItem *r);

int 
memNodePropagate(TPMContext *tpm, TPMNode2 *s, TaintedBuf **dstMemNodes, Addr2NodeItem *addr2NodeHT,
    u32 dstAddrStart, u32 dstAddrEnd, int dstMinSeq, int dstMaxseq, u32 *stepCount);
// Returns:
//  >=0: dst mem nodes hit byte count
//  <0: error
// searches mem node propagation given tpm, source node. Stores results
// (destination mem nodes) in dstBuf

int 
printMemNodePropagate(TPMContext *tpm, TPMNode2 *s);

#endif

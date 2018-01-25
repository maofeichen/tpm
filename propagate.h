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
	u32 level;
	struct StackTransitionNode *next;
} StackTransitionNode;

typedef struct StckMemnode
{
    TPMNode2 *memnode;
    struct StckMemnode *next;
} StckMemnode;

int
cmpAddr2NodeItem(Addr2NodeItem *l, Addr2NodeItem *r);

int 
memNodePropagate(
        TPMContext *tpm,
        TPMNode2 *s,
        TaintedBuf **dstMemNodes,   // IGNORE
        Addr2NodeItem *addr2NodeHT,
        u32 dstAddrStart,
        u32 dstAddrEnd,
        int dstMinSeq,
        int dstMaxseq,
        u32 *stepCount);
// Returns:
//  >=0: dst mem nodes hit byte count
//  <0: error
// searches mem node propagation given tpm, source node. Stores results
// (destination mem nodes) in dstBuf

int 
memnodePropgtFast(
        TPMContext *tpm,
        TPMPropgtSearchCtxt *tpmPSCtxt,
        AddrPropgtToNode **addrPropgtToNode,
        TPMNode2 *srcnode);
// Returns:
//  >=0: step counts in the dfs search
//  <0: error
// searches mem node propagation given tpm, source node.

int
printMemNodePropagate(TPMContext *tpm, TPMNode2 *s);

#endif

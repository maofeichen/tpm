#ifndef PROPAGATE_H
#define PROPAGATE_H 

#include "uthash.h"
#include "avalanchetype.h"
#include "hitmapnode.h"
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
{   u32 level;
    TPMNode2 *memnode;
    struct StckMemnode *next;
} StckMemnode;

/* HitMap node */
typedef struct HitTransitionHashTable
// Transition hash table
//	uses in dfs to mark transitions that had been visited
{
	// u32 seqNo;
	HitTransition *toTrans; // the hitTrans ptr is key
	UT_hash_handle hh_hitTrans;
} HitTransitionHashTable;

typedef struct StackHitTransitionItem
{
	HitTransition *transition;
	// u32 level;
	struct StackHitTransitionItem *next;
} StackHitTransitionItem;

/* function prototype */

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
bufnodePropgt2HitMapNode(
        TPMContext *tpm,
        TPMNode2 *srcnode,
        HitMapContext *hitMapCtxt);
// Returns:
//  >=0: success
//  <0: error

int
hitMapNodePropagate(HitMapNode *srcnode);
// Returns:
//  >= 0: num of hitmap nodes that the srcnode can propagate to
//  <0: error

int
printMemNodePropagate(TPMContext *tpm, TPMNode2 *s);

#endif

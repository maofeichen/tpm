#ifndef PROPAGATE_H
#define PROPAGATE_H 

#include "uthash.h"
#include "avalanchetype.h"
#include "env.h"
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

typedef struct TPMNodeHash
{
  TPMNode *toTPMNode;
  UT_hash_handle hh_tpmnode;
} TPMNodeHash;

typedef struct StackTransitionNode 
{
  Transition *transition;
  u32 level;
  struct StackTransitionNode *next;
} StackTransitionNode;

typedef struct StckMemnode
{
  u32 level;
  TPMNode2 *memnode;
  u32 minSeqN; // records min seqN during traversing between buffer nodes
  // u32 maxSeqN;
  struct StckMemnode *next;
} StckMemnode;  // stores buf nodes during dfs search of building HitMap

typedef struct StackTPMNode
{
  TPMNode *node;        // Can be either memory or reg/temp node
  char flagCreateHM;    // indicates if the TPMNode should create a hitmap node
  TPMNode *farther;
  Transition *dirctTrans; // The transition between farther and itself
  u32 currSeqN;
  struct StackTPMNode *next;
  char isVisit;
} StackTPMNode;

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

// int 
// memnodePropgtFast(
//     TPMContext *tpm,
//     TPMPropgtSearchCtxt *tpmPSCtxt,
//     AddrPropgtToNode **addrPropgtToNode,
//     TPMNode2 *srcnode);
// Returns:
//  >=0: step counts in the dfs search
//  <0: error
// searches mem node propagation given tpm, source node.

int
bufnodePropgt2HitMapNode(
    TPMContext *tpm,
    TPMNode2 *srcnode,
    HitMapContext *hitMapCtxt,
    u32 *nodeVisitIdx);
// Returns:
//  >=0: success
//  <0: error

//int
//hitMapNodePropagate(HitMapNode *srcnode, HitMapContext *hitMap, TPMContext *tpm);
// Returns:
//  >= 0: num of hitmap nodes that the srcnode can propagate to
//  <0: error

int
printMemNodePropagate(TPMContext *tpm, TPMNode2 *s);

int
disp_reverse_propgt(TPMContext *tpm, TPMNode2 *s);
#endif

#ifndef HITMAPPROPAGATE_H
#define HITMAPPROPAGATE_H

#include "uthash.h"
#include "hitmapnode.h"
#include "hitmapavaltype.h"
#include "env.h"
#include "type.h"

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
  u32 currSeqN;
  struct StackHitTransitionItem *next;
} StackHitTransitionItem;

typedef struct HitMapNodeHash
// used in dfs to mark nodes had been visited
{
  HitMapNode *toHitMapNode;
  UT_hash_handle hh_hitMapNode;
} HitMapNodeHash;

typedef struct StackHitMapNode
{
  HitMapNode *hmNode;
  u32 currSeqN;
  HitTransition *taintBy;
  struct StackHitMapNode *next;
} StackHitMapNode;

int
hitMapNodePropagate(
    HitMapNode *srcnode,
    HitMapContext *hitMap,
    HitMapAddr2NodeItem *hmAddr2NodeItem,
    u32 dstAddrStart,
    u32 dstAddrEnd,
    int dstMinSeqN,
    int dstMaxSeqN);
// Returns:
//  >= 0: num of hitmap nodes that the srcnode can propagate to
//  <0: error

int
hitMapNodePropagateReverse(
    HitMapNode *srcnode,
    HitMapContext *hitMap,
    HitMapAddr2NodeItem **hitMapAddr2NodeAry,
    u32 srcAddrStart,
    u32 srcAddrEnd,
    int srcMinSeqN,
    int srcMaxSeqN);

int
hitMapNodePropgtOfBuildBufHitCntAry(
    // #ifdef ENV64
    //         u64 *bufHitCntAry,
    // #else
    //         u32 *bufHitCntAry,
    // #endif
    u8 *bufHitCntAry,
    u32 numOfBuf,
    HitMapNode *addrHead);

int
cmpHitMapAddr2NodeItem(HitMapAddr2NodeItem *l, HitMapAddr2NodeItem *r);

#endif

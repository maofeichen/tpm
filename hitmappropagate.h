#ifndef HITMAPPROPAGATE_H
#define HITMAPPROPAGATE_H

#include "uthash.h"
#include "hitmapnode.h"
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
	// u32 level;
	struct StackHitTransitionItem *next;
} StackHitTransitionItem;

int
hitMapNodePropagate(HitMapNode *srcnode, HitMapContext *hitMap);
// Returns:
//  >= 0: num of hitmap nodes that the srcnode can propagate to
//  <0: error

#endif

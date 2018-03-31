#ifndef HITMAPAVALTYPE_H_
#define HITMAPAVALTYPE_H_

#include "hitmap.h"
#include "type.h"

typedef struct HitMapAddr2NodeItem
{
  u32 addr;				/* 32-bit address: src addr in 1st level hash; dst addr in 2nd level hash */
  HitMapNode *node;	    /* used as key to hash: src node in 1st level hash; dst node in 2nd level hash */
  struct HitMapAddr2NodeItem *subHash;    /* next level hash */
  HitMapNode *toHitMapNode; 			    // the mem node that the source node can propagate
  UT_hash_handle hh_hmAddr2NodeItem;      /* makes this structure hashable */
} HitMapAddr2NodeItem;

HitMapAddr2NodeItem *
createHitMapAddr2NodeItem(
    u32 addr,
    HitMapNode *node,
    HitMapAddr2NodeItem *subHash,
    HitMapNode *toHitMapNode);

void
freeHitMapAddr2NodeItem(HitMapAddr2NodeItem *hmAddr2NodeItem);

u32
getHitMap2LAddr2NodeItemTotal(HitMapAddr2NodeItem *hmAddr2NodeItem);

void
printHitMap2LAddr2NodeItem(HitMapAddr2NodeItem *hmAddr2NodeItem);

void
printHitMapAddr2NodeItemSubhash(HitMapAddr2NodeItem *hmAddr2NodeItem);

#endif /* HITMAPAVALTYPE_H_ */

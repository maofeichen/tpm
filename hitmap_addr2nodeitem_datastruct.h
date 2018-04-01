#ifndef HITMAP_ADDR2NODEITEM_DATASTRUCT_H
#define HITMAP_ADDR2NODEITEM_DATASTRUCT_H

#include "hitmapavaltype.h"
#include <stdbool.h>

typedef struct StackHitMapAddr2NodeItem
{
  HitMapAddr2NodeItem *hitMapAddr2NodeItem;
  struct StackHitMapAddr2NodeItem *next;
} StackHitMapAddr2NodeItem;
// stores HitMap Addr2nodeitem during avalanche search

/* Stack of HitMap Addr2NodeItem operation */
void
hitMapAddr2NodeItemPush(
    HitMapAddr2NodeItem *hitMapAddr2NodeItem,
    StackHitMapAddr2NodeItem **stackHitMapAddr2NodeItemTop,
    u32 *stackHitMapAddr2NodeItemCount);

HitMapAddr2NodeItem *
hitMapAddr2NodeItemPop(
    StackHitMapAddr2NodeItem **stackHitMapAddr2NodeItemTop,
    u32 *stackHitMapAddr2NodeItemCount);

void
hitMapAddr2NodeItemDisplay(
	StackHitMapAddr2NodeItem *stackHitMapAddr2NodeItemTop);

void
hitMapAddr2NodeItemDispRange(
    StackHitMapAddr2NodeItem *stackHitMapAddr2NodeItemTop,
    char *s);

void
hitMapAddr2NodeItemPopAll(
    StackHitMapAddr2NodeItem **stackHitMapAddr2NodeItemTop,
    u32 *stackHitMapAddr2NodeItemCount);

bool
isHitMapAddr2NodeItemStackEmpty(
	StackHitMapAddr2NodeItem *stackHitMapAddr2NodeItemTop,
	u32 stackHitMapAddr2NodeItemCount);

#endif /* HITMAP_ADDR2NODEITEM_DATASTRUCT_H */

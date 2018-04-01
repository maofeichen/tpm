#include "hitmap_addr2nodeitem_datastruct.h"
#include <assert.h>
#include <stdlib.h> // calloc

void
hitMapAddr2NodeItemPush(
    HitMapAddr2NodeItem *hitMapAddr2NodeItem,
    StackHitMapAddr2NodeItem **stackHitMapAddr2NodeItemTop,
    u32 *stackHitMapAddr2NodeItemCount)
{
  StackHitMapAddr2NodeItem *s = calloc(sizeof(StackHitMapAddr2NodeItem), 1);
  assert(s != NULL);
  s->hitMapAddr2NodeItem = hitMapAddr2NodeItem;
  s->next = *stackHitMapAddr2NodeItemTop;
  *stackHitMapAddr2NodeItemTop = s;
  (*stackHitMapAddr2NodeItemCount)++;
}

HitMapAddr2NodeItem *
hitMapAddr2NodeItemPop(
    StackHitMapAddr2NodeItem **stackHitMapAddr2NodeItemTop,
    u32 *stackHitMapAddr2NodeItemCount)
{
  StackHitMapAddr2NodeItem *toPop;
  HitMapAddr2NodeItem *hitMapAddr2NodeItem = NULL;

  if(*stackHitMapAddr2NodeItemTop != NULL) {
    toPop = *stackHitMapAddr2NodeItemTop;
    *stackHitMapAddr2NodeItemTop = toPop->next;
    hitMapAddr2NodeItem = toPop->hitMapAddr2NodeItem;
    free(toPop);
    (*stackHitMapAddr2NodeItemCount)--;
  }
  return hitMapAddr2NodeItem;
}

void
hitMapAddr2NodeItemDisplay(
	StackHitMapAddr2NodeItem *stackHitMapAddr2NodeItemTop)
{
  while(stackHitMapAddr2NodeItemTop != NULL) {
    HitMapNode *n = stackHitMapAddr2NodeItemTop->hitMapAddr2NodeItem->node;
    printHitMapNodeLit(n);
    stackHitMapAddr2NodeItemTop = stackHitMapAddr2NodeItemTop->next;
  }
}

void
hitMapAddr2NodeItemDispRange(
    StackHitMapAddr2NodeItem *stackHitMapAddr2NodeItemTop,
    char *s)
{
  StackHitMapAddr2NodeItem *t;
  u32 bufstart, bufend;
  HitMapNode *n;

  if(stackHitMapAddr2NodeItemTop != NULL) {
    t = stackHitMapAddr2NodeItemTop;
    n = t->hitMapAddr2NodeItem->node;
    bufend = n->addr + n->bytesz;

    while(t != NULL && t->next != NULL) { t = t->next; }
    n = t->hitMapAddr2NodeItem->node; // gets last node
    bufstart = n->addr;
    printf("%s\n\tbufstart:%x bufend:%x sz:%u\n", s, bufstart, bufend, bufend-bufstart);
  }
}

void
hitMapAddr2NodeItemPopAll(
    StackHitMapAddr2NodeItem **stackHitMapAddr2NodeItemTop,
    u32 *stackHitMapAddr2NodeItemCount)
{
  while(*stackHitMapAddr2NodeItemTop != NULL) {
    hitMapAddr2NodeItemPop(stackHitMapAddr2NodeItemTop, stackHitMapAddr2NodeItemCount);
  }
}

bool
isHitMapAddr2NodeItemStackEmpty(
	StackHitMapAddr2NodeItem *stackHitMapAddr2NodeItemTop,
	u32 stackHitMapAddr2NodeItemCount)
{
  if(stackHitMapAddr2NodeItemTop == NULL) {
    assert(stackHitMapAddr2NodeItemCount == 0);
    return true;
  }
  else return false;
}

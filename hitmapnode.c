#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include "hitmapnode.h"

HitMapNode *
createHitMapNode(
        u32 bufId,
        u32 addr,
        u32 version,
        u32 val,
        u32 bytesz,
        u32 lastUpdateTS)
{
    HitMapNode *h = calloc(1, sizeof(HitMapNode));
    assert(h != NULL);
    h->bufId = bufId;
    h->addr = addr;
    h->version = version;
    h->val = val;
    h->bytesz = bytesz;
    h->lastUpdateTS = lastUpdateTS;
    h->firstChild = NULL;
    h->leftNBR = NULL;
    h->rightNBR = NULL;
    h->nextVersion = NULL;
    h->hitcnt = 0;
    return h;
}

HitTransition *
createHitTransition(
        u32 minSeqN,
        u32 maxSeqN,
        HitMapNode *child)
{
    HitTransition *t;
    t = calloc(1, sizeof(HitTransition));
    t->minSeqNo = minSeqN;
    t->maxSeqNo = maxSeqN;
    t->child = child;
    t->next = NULL;
    return t;
}


HitMapBufNodePtr2NodeHashTable *
createHitMapBufNode2NodeHT(TPMNode2 *srcnode, HitMapNode *hitMapNode)
{
    HitMapBufNodePtr2NodeHashTable *h;
    h = calloc(1, sizeof(HitMapBufNodePtr2NodeHashTable));
    assert(h != NULL);

    h->srcnode = srcnode;
    h->toHitMapNode = hitMapNode;
    return h;
}

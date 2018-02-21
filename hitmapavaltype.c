#include "hitmapavaltype.h"
#include "assert.h"

HitMapAddr2NodeItem *
createHitMapAddr2NodeItem(
        u32 addr,
        HitMapNode *node,
        HitMapAddr2NodeItem *subHash,
        HitMapNode *toHitMapNode)
{
    HitMapAddr2NodeItem *h = calloc(1, sizeof(HitMapAddr2NodeItem) );
    assert(h != NULL);
    h->addr = addr;
    h->node = node;
    h->subHash = subHash;
    h->toHitMapNode = toHitMapNode;
    return h;
}

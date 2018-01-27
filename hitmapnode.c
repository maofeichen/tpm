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

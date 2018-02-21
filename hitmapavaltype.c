#include "hitmapavaltype.h"
#include "uthash.h"
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

void
freeHitMapAddr2NodeItem(HitMapAddr2NodeItem *hmAddr2NodeItem)
{
    HitMapAddr2NodeItem *item, *temp, *subItem, *subTemp;

    if(hmAddr2NodeItem == NULL) {
        // fprintf(stderr, "freeHitMapAddr2NodeItem error invalid:%p\n", hmAddr2NodeItem);
        return;
    }

    HASH_ITER(hh_hmAddr2NodeItem, hmAddr2NodeItem, item, temp) {
        HASH_ITER(hh_hmAddr2NodeItem, hmAddr2NodeItem->subHash, subItem, subTemp) {
            HASH_DELETE(hh_hmAddr2NodeItem, hmAddr2NodeItem->subHash, subItem);
            free(subItem);
        }
        HASH_DELETE(hh_hmAddr2NodeItem, hmAddr2NodeItem, item);
        free(item);
    }
}


void
printHitMap2LAddr2NodeItem(HitMapAddr2NodeItem *hmAddr2NodeItem)
{
    u32 totalSrc;

    totalSrc = HASH_CNT(hh_hmAddr2NodeItem, hmAddr2NodeItem);
    printf("total src HitMap nodes:%u\n", totalSrc);
    for(; hmAddr2NodeItem != NULL; hmAddr2NodeItem = hmAddr2NodeItem->hh_hmAddr2NodeItem.next) {
        printHitMapAddr2NodeItemSubhash(hmAddr2NodeItem);
    }
}


void
printHitMapAddr2NodeItemSubhash(HitMapAddr2NodeItem *hmAddr2NodeItem)
{
	HitMapAddr2NodeItem *subitem = NULL;
	u32 totalSubItem;

	if(hmAddr2NodeItem == NULL) {
	    return;
	}
	totalSubItem = HASH_CNT(hh_hmAddr2NodeItem, hmAddr2NodeItem->subHash);
	printf("----------\nsrc hitmap node:\n");
	printHitMapNodeLit(hmAddr2NodeItem->node);
	printf("total propagate dst hitmap node:%u\n", totalSubItem);
	for(subitem = hmAddr2NodeItem->subHash; subitem != NULL; subitem = subitem->hh_hmAddr2NodeItem.next) {
	    printHitMapNodeLit(subitem->node);
	}
}

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

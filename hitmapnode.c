#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "hitmapnode.h"

static HitMapNode *
createHitMapRecordNode(TPMNode2 *node, HitMapContext *hitMap);

static void
attachHitTransition(HitMapNode *srcHMN, HitTransition *t);

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

void
createHitMapRecord(
        TPMNode2 *src,
        u32 srclvl,
        TPMNode2 *dst,
        u32 dstLvl,
        HitMapContext *hitMapCtxt)
//  1. creates HitMap record source
//  2. creates HitMap record destination
//  3. creates transition node between src and destination
{
    // printf("---------------\nHitMapRecord src: Lvl:%u\n", srclvl);
    // printMemNodeLit(src);
    // printf("dst: Lvl:%u\n", dstLvl);
    // printMemNodeLit(dst);

    HitMapNode *HMNSrc, *HMNDst;
    HitTransition *t;

    HMNSrc = createHitMapRecordNode(src, hitMapCtxt);
    HMNDst = createHitMapRecordNode(dst, hitMapCtxt);
    t = createHitTransition(0, 0, HMNDst);
    attachHitTransition(HMNSrc, t);
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

static HitMapNode *
//  1  detects if node exists in HitMap
//      a) yes, return pointer
//      b) no, creates new hitMap node
//          1) updates the HitMap Context Hash Table
//          2) updates the HitMap Array
//          3) updates neighbors link
//          4) updates versions link
createHitMapRecordNode(TPMNode2 *node, HitMapContext *hitMap)
{
    HitMapNode *HMNode;
    HitMapBufNodePtr2NodeHashTable *find, *htItem;

    HASH_FIND(hh_hitMapBufNode2NodeHT, hitMap->hitMapNodeHT, &node, 4, find);
    if(find == NULL) {
        HMNode = createHitMapNode(node->bufid, node->addr, node->version, node->val, node->bytesz, node->lastUpdateTS);

        htItem = createHitMapBufNode2NodeHT(node, HMNode);
        HASH_ADD(hh_hitMapBufNode2NodeHT, hitMap->hitMapNodeHT, srcnode, 4, htItem);
        return HMNode;
    }
    else {
        return find->toHitMapNode;
    }
}

static void
attachHitTransition(HitMapNode *srcHMN, HitTransition *t)
{
    assert(srcHMN != NULL);
    assert(t != NULL);
    if(srcHMN->firstChild == NULL) {
        srcHMN->firstChild = t;
    }
    else {
        HitTransition *firstChild = srcHMN->firstChild;
        while(firstChild->next != NULL) {
            firstChild = firstChild->next;
        }
        firstChild->next = t;
    }
}

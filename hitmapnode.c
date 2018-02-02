#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "hitmapnode.h"

static HitMapNode *
createHitMapRecordNode(TPMNode2 *node, HitMapContext *hitMap);

static void
updateHitMapHashTable(
        TPMNode2 *node,
        HitMapNode *hmNode,
        HitMapContext *hitMap);

static void
updateHMNodeVersion(HitMapNode *hmNode, HitMapContext *hitMap);

static void
linkNextVersionHitMapNode(HitMapNode *front, HitMapNode *next);

static void
updateHitMapArray(HitMapNode *hmNode, HitMapContext *hitMap);

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
    h->nextVersion = h; // points to itsefl
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

//    printf("HitMap Node src:\n");
//    printHitMapNode(HMNSrc);
//    printf("HitMap Node dst:\n");
//    printHitMapNode(HMNDst);
//    printf("HitMap Transition:\n");
//    printHitMapTransition(t);
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

    if(node == NULL || hitMap == NULL) {
        fprintf(stderr, "createHitMapRecordNode:node:%p hitMap:%p\n", node, hitMap);
        return NULL;
    }

    // is in HitMap hash table?
    HASH_FIND(hh_hitMapBufNode2NodeHT, hitMap->hitMapNodeHT, &node, 4, find);
    if(find == NULL) {
        HMNode = createHitMapNode(node->bufid, node->addr, node->version, node->val, node->bytesz, node->lastUpdateTS);

        updateHitMapHashTable(node, HMNode, hitMap);
        updateHMNodeVersion(HMNode, hitMap);
        updateHitMapArray(HMNode, hitMap);

        return HMNode;
    }
    else {
        return find->toHitMapNode;
    }
}

static void
updateHitMapHashTable(
        TPMNode2 *node,
        HitMapNode *hmNode,
        HitMapContext *hitMap)
{
    if(node == NULL || hmNode == NULL || hitMap == NULL){
        fprintf(stderr, "update HitMap Hash Table: node:%p hmNode:%p HitMap:%p",
                node, hmNode, hitMap);
        return;
    }
    HitMapBufNodePtr2NodeHashTable *htItem;
    htItem = createHitMapBufNode2NodeHT(node, hmNode);
    HASH_ADD(hh_hitMapBufNode2NodeHT, hitMap->hitMapNodeHT, srcnode, 4, htItem);
}

static void
updateHMNodeVersion(HitMapNode *hmNode, HitMapContext *hitMap)
{
    int addrIdx;

    u32 bufID = hmNode->bufId;
    u32 addr = hmNode->addr;
    addrIdx = getTPMBufAddrIdx(bufID, addr, hitMap->tpmBuf);

    if(hitMap->bufArray[bufID]->addrArray[addrIdx] == NULL) {
        hitMap->bufArray[bufID]->addrArray[addrIdx] = hmNode;
    }
    else {
        linkNextVersionHitMapNode(hitMap->bufArray[bufID]->addrArray[addrIdx], hmNode);
    }
}

static void
linkNextVersionHitMapNode(HitMapNode *front, HitMapNode *next)
// the node versions are not in-order
{
    if(front == NULL || next == NULL) {
        fprintf(stderr, "linkNextVersionNode: front:%p next:%p\n", front, next);
        return;
    }
    next->nextVersion = front->nextVersion; // next points to head
    front->nextVersion = next;
}

static void
updateHitMapArray(HitMapNode *hmNode, HitMapContext *hitMap)
// hitMap array always points to the earliest version node
{
    HitMapNode *head, *earliest;
    u32 currVersion, bufID, addr, addrIdx;

    if( hmNode == NULL || hitMap == NULL) {
        fprintf(stderr, "updateHitMapArray: HitMap Node:%p hitMap:%p\n",
                hmNode, hitMap);
        return;
    }

    bufID = hmNode->bufId;
    addr = hmNode->addr;
    addrIdx = getTPMBufAddrIdx(bufID, addr, hitMap->tpmBuf);

    head = hitMap->bufArray[bufID]->addrArray[addrIdx];
    earliest = head;

    currVersion = head->version;
    do{
        if(head->version < earliest->version)
            earliest = head;

        head = head->nextVersion;
    }
    while(head->version != currVersion);

    hitMap->bufArray[bufID]->addrArray[addrIdx] = earliest;
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

void
printHitMapNode(HitMapNode *node)
{
    if(node == NULL)
        return;
    printf("bufID:%u addr:0x%-8x val:%-8x sz:%u lastUpdateTS:%-16u"
            " firstChild:%-8p leftNBR:%-10p rightNBR:%-10p nextVersion:%-8p"
            " version:%-9u hitcnt:%-8u\n",
            node->bufId, node->addr, node->val, node->bytesz, node->lastUpdateTS,
            node->firstChild, node->leftNBR, node->rightNBR, node->nextVersion,
            node->version, node->hitcnt);
}

void
printHitMapTransition(HitTransition *hTrans)
{
    if(hTrans == NULL)
        return;
    printf("HitMap Transition:%p minSeqN:%u maxSeqN:%u child:%p next:%p",
            hTrans, hTrans->minSeqNo, hTrans->maxSeqNo, hTrans->child, hTrans->next);
    if(hTrans->child != NULL) {
        printHitMapNode(hTrans->child);
    }
}

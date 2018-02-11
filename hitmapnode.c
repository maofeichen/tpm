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

static u32
getBufArrayIdx(u32 bufID);

static void
updateHitMapNeighbor(HitMapNode *hmNode, HitMapContext *hitMap);

static void
updateLeftNeighbor(
        u32 bufArrayIdx,
        int addrIdx,
        HitMapNode *hmNode,
        HitMapContext *hitMap);

static void
updateRightNeighbor(
        u32 bufArrayIdx,
        int addrIdx,
        HitMapNode *hmNode,
        HitMapContext *hitMap);

static void
getEarliestVersion(HitMapNode **hmNode);

static void
attachHitTransition(HitMapNode *srcHMN, HitTransition *t);

HitMapNode *
createHitMapNode(
        u32 bufId,
        u32 addr,
        u32 version,
        u32 val,
        u32 bytesz,
        int lastUpdateTS,
        u32 type)
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
    h->type = type;
    return h;
}

int
compareHitMapHTItem(HitMapBufNodePtr2NodeHashTable *l, HitMapBufNodePtr2NodeHashTable *r)
{
    if(l->toHitMapNode->addr < r->toHitMapNode->addr) { return -1;}
    else if(l->toHitMapNode->addr == r->toHitMapNode->addr ) { return 0; }
    else { return 1; }
}


bool
isHitMapNodeExist(TPMNode2 *node, HitMapContext *hitMap)
{
    HitMapBufNodePtr2NodeHashTable *find;
    HASH_FIND(hh_hitMapBufNode2NodeHT, hitMap->hitMapNodeHT, &node, 4, find);
    if(find == NULL)
        return false;
    else
        return true;
}

void
sortHitMapHashTable(HitMapBufNodePtr2NodeHashTable **hitMapHT)
{
    HASH_SRT(hh_hitMapBufNode2NodeHT, *hitMapHT, compareHitMapHTItem);
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
    // printf("---------------\nHitMapRecord src:\n");
    // printMemNodeLit(src);
    // printf("dst:\n");
    // printMemNodeLit(dst);

    HitMapNode *HMNSrc, *HMNDst;
    HitTransition *t;

    HMNSrc = createHitMapRecordNode(src, hitMapCtxt);
    HMNDst = createHitMapRecordNode(dst, hitMapCtxt);
    t = createHitTransition(0, 0, HMNDst);
    attachHitTransition(HMNSrc, t);

    // printf("---------------\nHitMap Node src:\n");
    // printHitMapNode(HMNSrc);
    // printf("HitMap Node dst:\n");
    // printHitMapNode(HMNDst);
    // printf("HitMap Transition:\n");
    // printHitMapTransition(t);
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
        HMNode = createHitMapNode(node->bufid, node->addr, node->version, node->val, node->bytesz, node->lastUpdateTS, node->type);

        updateHitMapHashTable(node, HMNode, hitMap);
        updateHMNodeVersion(HMNode, hitMap);
        updateHitMapNeighbor(HMNode, hitMap);
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

    u32 bufAryIdx = getBufArrayIdx(hmNode->bufId);
    u32 addr = hmNode->addr;
    addrIdx = getTPMBufAddrIdx(hmNode->bufId, addr, hitMap->tpmBuf);

    // printf("update HMNode version bufID:%u addr:%x addrIdx:%d\n", bufAryIdx, addr, addrIdx);
    if(hitMap->bufArray[bufAryIdx]->addrArray[addrIdx] == NULL) {
        hitMap->bufArray[bufAryIdx]->addrArray[addrIdx] = hmNode;
    }
    else {
        linkNextVersionHitMapNode(hitMap->bufArray[bufAryIdx]->addrArray[addrIdx], hmNode);
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
    u32 currVersion, bufAryIdx, addr, addrIdx;

    if( hmNode == NULL || hitMap == NULL) {
        fprintf(stderr, "updateHitMapArray: HitMap Node:%p hitMap:%p\n",
                hmNode, hitMap);
        return;
    }

    bufAryIdx = getBufArrayIdx(hmNode->bufId);;
    addr = hmNode->addr;
    addrIdx = getTPMBufAddrIdx(hmNode->bufId, addr, hitMap->tpmBuf);

    head = hitMap->bufArray[bufAryIdx]->addrArray[addrIdx];
    earliest = head;

    currVersion = head->version;
    do{
        if(head->version < earliest->version)
            earliest = head;

        head = head->nextVersion;
    }
    while(head->version != currVersion);

    hitMap->bufArray[bufAryIdx]->addrArray[addrIdx] = earliest;
}

static u32
getBufArrayIdx(u32 bufID)
{
    assert(bufID > 0);
    return bufID - 1;
}

static void
updateHitMapNeighbor(HitMapNode *hmNode, HitMapContext *hitMap)
{
    int addrIdx;

    u32 bufAryIdx = getBufArrayIdx(hmNode->bufId);
    u32 addr = hmNode->addr;
    addrIdx = getTPMBufAddrIdx(hmNode->bufId, addr, hitMap->tpmBuf);

    if(addrIdx == 0) {
        updateRightNeighbor(bufAryIdx, addrIdx, hmNode, hitMap);
    }
    else if(addrIdx == (hitMap->bufArray[bufAryIdx]->numOfAddr - 1) ) {
        updateLeftNeighbor(bufAryIdx, addrIdx, hmNode, hitMap);
    }
    else if(addrIdx > 0 &&
            addrIdx < (hitMap->bufArray[bufAryIdx]->numOfAddr - 1) ) {
        updateLeftNeighbor(bufAryIdx, addrIdx, hmNode, hitMap);
        updateRightNeighbor(bufAryIdx, addrIdx, hmNode, hitMap);
    }
    else {
        fprintf(stderr, "update neighbors: addrIdx:%d\n", addrIdx);
        return;
    }
}

static void
updateLeftNeighbor(
        u32 bufArrayIdx,
        int addrIdx,
        HitMapNode *hmNode,
        HitMapContext *hitMap)
{
    if(hitMap->bufArray[bufArrayIdx]->addrArray[addrIdx-1] != NULL) {
        HitMapNode *left = hitMap->bufArray[bufArrayIdx]->addrArray[addrIdx-1];
        HitMapNode *this = hmNode;
        // printf("update left neighbor:\n");
        // printHitMapNode(left);
        // printHitMapNode(hmNode);
        getEarliestVersion(&left);
        getEarliestVersion(&this);
        hmNode->leftNBR = left;

        // left->rightNBR = hmNode;
        u32 leftVersion = left->version;
        do {
            left->rightNBR = this;
            left = left->nextVersion;
        } while(leftVersion != left->version);
    }
    else {}
}

static void
updateRightNeighbor(
        u32 bufArrayIdx,
        int addrIdx,
        HitMapNode *hmNode,
        HitMapContext *hitMap)
{
    if(hitMap->bufArray[bufArrayIdx]->addrArray[addrIdx+1] != NULL) {
        HitMapNode *right = hitMap->bufArray[bufArrayIdx]->addrArray[addrIdx+1];
        HitMapNode *this = hmNode;
        // printf("update right neighbor:\n");
        // printHitMapNode(right);
        // printHitMapNode(hmNode);
        getEarliestVersion(&right);
        getEarliestVersion(&this);
        hmNode->rightNBR = right;

        // right->leftNBR = hmNode;
        u32 rightVersion = right->version;
        do {
            right->leftNBR = this;
            right = right->nextVersion;
        } while (rightVersion != right->version);
    }
    else {}
}

static void
getEarliestVersion(HitMapNode **hmNode)
{
    u32 currVersion;
    HitMapNode *earliest, *curr;
    // printHitMapNode(*hmNode);

    curr = *hmNode;
    earliest = curr;
    currVersion = (*hmNode)->version;

    do {
        if(earliest->version < curr->version) {
           earliest = curr;
        }
        curr = curr->nextVersion;
    } while(currVersion != curr->version);

    *hmNode = earliest;
    // printf("----------\nearliest version: \n");
    // printHitMapNode(earliest);
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
    printf("HitMapNode:%p bufID:%u addr:0x%-8x val:%-8x sz:%u lastUpdateTS:%-16d"
            " firstChild:%-8p leftNBR:%-10p rightNBR:%-10p nextVersion:%-8p"
            " version:%-9u hitcnt:%-8u\n",
            node, node->bufId, node->addr, node->val, node->bytesz, node->lastUpdateTS,
            node->firstChild, node->leftNBR, node->rightNBR, node->nextVersion,
            node->version, node->hitcnt);
}

void
printHitMapNodeAllVersion(HitMapNode *node)
{
    u32 currVersion = node->version;
    do {
        printHitMapNode(node);
        node = node->nextVersion;
    } while (currVersion != node->version);
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

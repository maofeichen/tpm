#include "hitmappropagate.h"

/* HitMap node propagate */
/* HitMap Transition hash table operation */
static void
add2HitTransitionHT(HitTransitionHashTable **hitTransitionht, HitTransition *toTrans);

static HitTransitionHashTable*
findInHitTransitionHT(HitTransitionHashTable *hitTransitionht, HitTransition *hitTrans);

static void
delHitTransitionHT(HitTransitionHashTable **hitTransitionht);

static void
countHitTransitionHT(HitTransitionHashTable *hitTransitionht);

/* HitMap Transition stack */
static void
stackHitTransPush(
        HitTransition *trans,
        StackHitTransitionItem **stackTransTop,
        u32 *stackTransCnt);

static HitTransition *
stackHitTransPop(
        StackHitTransitionItem **stackTransTop,
        u32 *stackTransCnt);

static void
stackHitTransDisplay(
        StackHitTransitionItem *stackTransTop,
        u32 stackTransCnt);

static void
stackHitTransPopAll(
        StackHitTransitionItem **stackTransTop,
        u32 *stackTransCnt);

static bool
isStackHitTransEmpty(StackHitTransitionItem *stackTransTop);

static void
printHitTransitionNode(StackHitTransitionItem *transNode);

static int
dfsHitMapNodePropagate(
        HitMapNode *srcnode,
        HitMapContext *hitMap,
        HitMapAddr2NodeItem *hmAddr2NodeItem,
        u32 dstAddrStart,
        u32 dstAddrEnd,
        int dstMinSeqN,
        int dstMaxSeqN);

static void
storeAllUnvisitHitTransChildren(
        HitTransitionHashTable **hitTransitionht,
        HitTransition *firstChild,
        int maxseq,
        StackHitTransitionItem **stackHitTransTop,
        u32 *stackHitTransCnt);

static bool
isHitTransitionVisited(
        HitTransitionHashTable *hitTransitionht,
        HitTransition *hitTransition);

static void
markVisitHitTransition(
        HitTransitionHashTable **hitTransitionht,
        HitTransition *hitTransition);

int
hitMapNodePropagate(
        HitMapNode *srcnode,
        HitMapContext *hitMap,
        HitMapAddr2NodeItem *hmAddr2NodeItem,
        u32 dstAddrStart,
        u32 dstAddrEnd,
        int dstMinSeqN,
        int dstMaxSeqN)
// Returns:
//  >= 0: num of hitmap nodes that the srcnode can propagate to
//  <0: error
{
    return dfsHitMapNodePropagate(srcnode, hitMap, hmAddr2NodeItem, dstAddrStart, dstAddrEnd, dstMinSeqN, dstMaxSeqN);
}

int
cmpHitMapAddr2NodeItem(HitMapAddr2NodeItem *l, HitMapAddr2NodeItem *r)
{
    if(l->addr < r->addr) { return -1; }
    else if(l->addr == r->addr) {
        if(l->node->version < r->node->version) { return -1; }
        else if(l->node->version < r->node->version) { return 0; }
        else { return 1; }
    }
    else { return 1; }
}

static void
add2HitTransitionHT(HitTransitionHashTable **hitTransitionht, HitTransition *toTrans)
{
    HitTransitionHashTable *t;
    t = findInHitTransitionHT(*hitTransitionht, toTrans);
    if(t == NULL) {
        t = calloc(1, sizeof(HitTransitionHashTable));
        t->toTrans = toTrans;
        HASH_ADD(hh_hitTrans, *hitTransitionht, toTrans, 4, t);
    }
    else {}
}

static HitTransitionHashTable*
findInHitTransitionHT(HitTransitionHashTable *hitTransitionht, HitTransition *hitTrans)
{
    HitTransitionHashTable *s = NULL;
    HASH_FIND(hh_hitTrans, hitTransitionht, hitTrans, 4, s);
    return s;
}

static void
delHitTransitionHT(HitTransitionHashTable **hitTransitionht)
{
    HitTransitionHashTable *curr, *tmp;
    HASH_ITER(hh_hitTrans, *hitTransitionht, curr, tmp) {
       HASH_DELETE(hh_hitTrans, *hitTransitionht, curr);
       free(curr);
    }
}

static void
countHitTransitionHT(HitTransitionHashTable *hitTransitionht)
{
    // TODO
}

static void
stackHitTransPush(
        HitTransition *hitTrans,
        StackHitTransitionItem **stackHitTransTop,
        u32 *stackHitTransCnt)
{
    StackHitTransitionItem *i = calloc(1, sizeof(StackHitTransitionItem));
    i->transition = hitTrans;

    i->next = *stackHitTransTop;
    *stackHitTransTop = i;
    (*stackHitTransCnt)++;
}

static HitTransition *
stackHitTransPop(
        StackHitTransitionItem **stackHitTransTop,
        u32 *stackHitTransCnt)
{
    StackHitTransitionItem *toDel;
    HitTransition *hitTrans = NULL;

    if(*stackHitTransTop != NULL) {
        toDel = *stackHitTransTop;
        *stackHitTransTop = toDel->next;

        hitTrans = toDel->transition;
        free(toDel);
        (*stackHitTransCnt)--;
    }
    return hitTrans;
}

static void
stackHitTransDisplay(
        StackHitTransitionItem *stackHitTransTop,
        u32 stackHitTransCnt)
{
    if(stackHitTransCnt > 0)
        printf("--------------------\ntotal transitions in stack:%u\n", stackHitTransCnt);

    while(stackHitTransTop != NULL) {
        printHitMapNode(stackHitTransTop->transition->child);
        stackHitTransTop = stackHitTransTop->next;
    }
}

static void
stackHitTransPopAll(
        StackHitTransitionItem **stackHitTransTop,
        u32 *stackHitTransCnt)
{
    while(*stackHitTransTop != NULL) {
        stackHitTransPop(stackHitTransTop, stackHitTransCnt);
    }
}

static bool
isStackHitTransEmpty(StackHitTransitionItem *stackHitTransTop)
{
    if(stackHitTransTop != NULL)
        return false;
    else
        return true;
}

static void
printHitTransitionNode(StackHitTransitionItem *transNode)
{

}
/* HitMap node propagate */

static int
dfsHitMapNodePropagate(
        HitMapNode *srcnode,
        HitMapContext *hitMap,
        HitMapAddr2NodeItem *hmAddr2NodeItem,
        u32 dstAddrStart,
        u32 dstAddrEnd,
        int dstMinSeqN,
        int dstMaxSeqN)
{
    if(srcnode == NULL) {
        fprintf(stderr, "dfsHitMapNodePropagate: hit map srcnode:%p\n", srcnode);
        return -1;
    }

    // printf("---------------\nsource:");
    // printHitMapNode(srcnode);
    // printf("dst max seqN:%u\n", dstMaxSeqN);

    HitTransitionHashTable *markVisitHitTransHT = NULL;

    StackHitTransitionItem *stackHitTransTop = NULL;
    u32 stackHitTransCnt = 0;

    HitTransition *sourceHitTrans = srcnode->firstChild;
    if(sourceHitTrans == NULL) {
        // printf("given source node is a leaf\n");
        // printHitMapNode(srcnode);
        return 0;
    }

    storeAllUnvisitHitTransChildren(&markVisitHitTransHT, sourceHitTrans, dstMaxSeqN,
            &stackHitTransTop, &stackHitTransCnt);
    // stackHitTransDisplay(stackHitTransTop, stackHitTransCnt);

    while(!isStackHitTransEmpty(stackHitTransTop) ) {
        HitTransition *popTrans = stackHitTransPop(&stackHitTransTop, &stackHitTransCnt);
        HitMapNode *popDstHitMapNode = popTrans->child;

        if(popDstHitMapNode->bufId > 0) {
            // printHitMapNodeLit(popDstHitMapNode);
        }

        if(popDstHitMapNode->bufId > 0
           && popDstHitMapNode->addr >= dstAddrStart && popDstHitMapNode->addr <= dstAddrEnd
           && popDstHitMapNode->lastUpdateTS >= dstMinSeqN && popDstHitMapNode->lastUpdateTS <= dstMaxSeqN) {
            // printHitMapNodeLit(popDstHitMapNode);
            HitMapAddr2NodeItem *toHitMapNodeItem = createHitMapAddr2NodeItem(popDstHitMapNode->addr, popDstHitMapNode, NULL, NULL);
            HASH_ADD(hh_hmAddr2NodeItem, hmAddr2NodeItem->subHash, node, 4, toHitMapNodeItem);
        }

        storeAllUnvisitHitTransChildren(&markVisitHitTransHT, popDstHitMapNode->firstChild, dstMaxSeqN,
                &stackHitTransTop, &stackHitTransCnt);
        // stackHitTransDisplay(stackHitTransTop, stackHitTransCnt);

    }
    delHitTransitionHT(&markVisitHitTransHT);
    stackHitTransPopAll(&stackHitTransTop, &stackHitTransCnt);

    HASH_SRT(hh_hmAddr2NodeItem, hmAddr2NodeItem->subHash, cmpHitMapAddr2NodeItem);
    return 0;
}

static void
storeAllUnvisitHitTransChildren(
        HitTransitionHashTable **hitTransitionht,
        HitTransition *firstChild,
        int maxseq,
        StackHitTransitionItem **stackHitTransTop,
        u32 *stackHitTransCnt)
{

    while(firstChild != NULL) {
        if(!isHitTransitionVisited(*hitTransitionht, firstChild)
            && firstChild->maxSeqNo <= maxseq) {
            stackHitTransPush(firstChild, stackHitTransTop, stackHitTransCnt);
            markVisitHitTransition(hitTransitionht, firstChild);
        }
        firstChild = firstChild->next;
    }
}

static bool
isHitTransitionVisited(
        HitTransitionHashTable *hitTransitionht,
        HitTransition *hitTransition)
{
	if(hitTransition == NULL)
		return false;

	HitTransitionHashTable *found = NULL;

	found = findInHitTransitionHT(hitTransitionht, hitTransition);
	if(found != NULL)
		return true;
	else
		return false;
}

static void
markVisitHitTransition(
        HitTransitionHashTable **hitTransitionht,
        HitTransition *hitTransition)
{
	if (hitTransitionht == NULL || hitTransition == NULL)
		return;

	add2HitTransitionHT(hitTransitionht, hitTransition);
}


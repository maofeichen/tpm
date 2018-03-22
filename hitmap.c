#include "env.h"
#include "hitmap.h"
#include "propagate.h"
#include <assert.h>

/* build HitMap of each buffer in TPM*/
static BufContext *
initBufContext(
        TPMContext *tpm,
        HitMapContext *hitMap,
        TPMBufHashTable *buf);

static BufHitcntCtxt *
initBufHitCntCtxt(TPMBufHashTable *buf);

static void
buildBufContext(
        TPMContext *tpm,
        HitMapContext *hitMap,
        TPMBufHashTable *buf);

static void
delBufContext(BufContext *bufCtxt);

static void
getAggregtHitcnt(
        HitMapNode *head,
        u32 *aggregtHitcntIn,
        u32 *aggregtHitcntOut);

/* build HitMap of each addr of each buffer */
static void
buildHitMapAddr(
        TPMContext *tpm,
        HitMapContext *hitMap,
        TPMNode2 *headNode);

static u32
getHitMapTotalNode(HitMapContext *hitMap);

static u32
getHitMapTotalTransaction(HitMapContext *hitMap);

static u32
getHitMapReverseTotalTrans(HitMapContext *hitMap);

static u32
getHitMapNodeTransactionNumber(HitMapNode *hmNode);

static u32
getHitMapNodeReverseTransNum(HitMapNode *hmNode);

static u32
getHitMapTotalIntermediateNode(HitMapContext *hitMapCtxt);

static u32
getHitMapIntermediateTotalTrans(HitMapContext *hitMap);

static void
compHitMapBufStat(
        HitMapNode *hmNode,
        u32 *baddr,
        u32 *eaddr,
        int *minseq,
        int *maxseq,
        u32 *numOfAddr,
        HitMapNode **firstnode,
        u32 *totalNode);

static HitMapNode *
getLeftMost(HitMapNode *node);

static bool
isAllVersionNodeLeftMost(HitMapNode *node);

static void
getFirstVerNode(HitMapNode **first);

static HitMapBufHash *
initHitMapBufHTNode(
        u32 baddr,
        u32 eaddr,
        int minseq,
        int maxseq,
        u32 numOfAddr,
        HitMapNode *firstnode,
        u32 totalNode);

static int
cmpHitMapBufHashNode(HitMapBufHash *l, HitMapBufHash *r);

HitMapContext *
initHitMap(TPMContext *tpm)
{
    HitMapContext *hitMap;
    TPMBufHashTable *tpmBuf, *currBuf;
    int numOfBuf, i;
    u32 maxBufSeqN;

    tpmBuf = analyzeTPMBuf(tpm);
    assignTPMBufID(tpmBuf);
    numOfBuf= HASH_CNT(hh_tpmBufHT, tpmBuf);
    printTPMBufHashTable(tpmBuf);

    hitMap = calloc(1, sizeof(HitMapContext) );
    assert(hitMap != NULL);

    hitMap->hitMapNodeHT = NULL;
    hitMap->intrtmdt2HitMapNodeHT = NULL;
    hitMap->maxBufSeqN = getTPMBufMaxSeqN(tpmBuf);
    // printf("maxBufSeqN:%u\n", hitMap->maxBufSeqN);
    hitMap->numOfBuf = numOfBuf;
    hitMap->tpmBuf = tpmBuf;

    hitMap->bufArray = calloc(1, sizeof(BufContext *) * numOfBuf);
    hitMap->bufHitcntInArray = calloc(1, sizeof(BufHitcntCtxt *) * numOfBuf);
    hitMap->bufHitcntOutArray = calloc(1, sizeof(BufHitcntCtxt *) * numOfBuf);
    assert(hitMap->bufArray != NULL);
    assert(hitMap->bufHitcntInArray != NULL);
    assert(hitMap->bufHitcntOutArray != NULL);

    i = 0;
    for(currBuf = tpmBuf; currBuf != NULL; currBuf = currBuf->hh_tpmBufHT.next) {
        hitMap->bufArray[i] = initBufContext(tpm, hitMap, currBuf);
        hitMap->bufHitcntInArray[i] = initBufHitCntCtxt(currBuf);
        hitMap->bufHitcntOutArray[i] = initBufHitCntCtxt(currBuf);
        i++;
    }
    // printHitMap(hitMap);
    // printHitMapLit(hitMap);
    return hitMap;
}

void
buildHitMap(HitMapContext *hitMap, TPMContext *tpm)
{
    TPMBufHashTable *currBuf;
    int numOfBuf, i;
    u32 maxBufSeqN;

    // printTPMBufHashTable(hitMap->tpmBuf);
    i = 0;
    currBuf = hitMap->tpmBuf;
    for(; currBuf != NULL; currBuf = currBuf->hh_tpmBufHT.next) {
        buildBufContext(tpm, hitMap, currBuf);
        i++;
    }
}

void
updateHitMapBuftHitCnt(HitMapContext *hitMap)
{
    for(int bufIdx = 0; bufIdx < hitMap->numOfBuf; bufIdx++) {
        BufHitcntCtxt *bufHitcntIn = hitMap->bufHitcntInArray[bufIdx];
        BufHitcntCtxt *bufHitcntOut = hitMap->bufHitcntOutArray[bufIdx];
        assert(bufHitcntIn->numOfAddr == bufHitcntOut->numOfAddr);

        u32 numOfAddr = bufHitcntIn->numOfAddr;
        for(int addrIdx = 0; addrIdx < numOfAddr; addrIdx++) {
            u32 aggregtHitcntIn = 0;
            u32 aggregtHitcntOut = 0;
            HitMapNode *addrHead = hitMap->bufArray[bufIdx]->addrArray[addrIdx];

            getAggregtHitcnt(addrHead, &aggregtHitcntIn, &aggregtHitcntOut);
            bufHitcntIn->addrHitcntArray[addrIdx] = aggregtHitcntIn;
            bufHitcntOut->addrHitcntArray[addrIdx] = aggregtHitcntOut;
        }
    }
}

static void
getAggregtHitcnt(
        HitMapNode *head,
        u32 *aggregtHitcntIn,
        u32 *aggregtHitcntOut)
{
    if(head == NULL)
        return;

    u32 ver = head->version;
    do {
        *aggregtHitcntIn += head->hitcntIn;
        *aggregtHitcntOut += head->hitcntOut;

        head = head->nextVersion;
    } while(ver != head->version);
}

void
compHitMapStat(HitMapContext *hitMap)
{
    u32 numOfNode, numOfIntermediateNode;
    u32 totalTrans, totalIntermediateTrans;
    HitMapBufHash *hitMapBufHash = NULL;

    sortHitMapHashTable(&(hitMap->hitMapNodeHT) );
    hitMapBufHash = analyzeHitMapBuf(hitMap);
    printHitMapBufHash(hitMapBufHash);

    numOfNode = getHitMapTotalNode(hitMap);
    printf("----------\ntotal number of node in HitMap:%u\n", numOfNode);

    totalTrans = getHitMapTotalTransaction(hitMap);
    printf("total transitions: %u\n", totalTrans);

    numOfIntermediateNode = getHitMapTotalIntermediateNode(hitMap);
    printf("total number of intermediate node in HitMap:%u\n", numOfIntermediateNode);

    totalIntermediateTrans = getHitMapIntermediateTotalTrans(hitMap);
    printf("total intermediate transitions:%u\n", totalIntermediateTrans);
}

void
compReverseHitMapStat(HitMapContext *hitMap)
{
    u32 numOfNode, numOfIntermediateNode;
    u32 totalTrans, totalIntermediateTrans;

    sortHitMapHashTable(&(hitMap->hitMapNodeHT) );

    numOfNode = getHitMapTotalNode(hitMap);
    printf("----------\ntotal number of node in HitMap:%u\n", numOfNode);

    totalTrans = getHitMapReverseTotalTrans(hitMap);
    printf("total transitions: %u\n", totalTrans);
}

HitMapBufHash *
analyzeHitMapBuf(HitMapContext *hitMap)
{
    HitMapBufNodePtr2NodeHashTable *hmBufNodeHash;
    HitMapBufHash *hitMapBufHash = NULL, *bufHash, *bufFound;

    HitMapNode *hitMapNode, *hitMapHeadNode;
    u32 baddr, eaddr, numOfAddr, totalNode = 0;
    int minseq, maxseq;

    hmBufNodeHash = hitMap->hitMapNodeHT;
    for(; hmBufNodeHash != NULL; hmBufNodeHash = hmBufNodeHash->hh_hitMapBufNode2NodeHT.next) {
        hitMapNode = hmBufNodeHash->toHitMapNode;

        HitMapNode *leftMost = getLeftMost(hitMapNode);
        // while(leftMost->leftNBR != NULL) { leftMost = leftMost->leftNBR; }
        baddr = leftMost->addr;
        HASH_FIND(hh_hmBufHash, hitMapBufHash, &baddr, 4, bufFound);
        if(bufFound != NULL)
            continue;

        compHitMapBufStat(hitMapNode, &baddr, &eaddr, &minseq, &maxseq,
                          &numOfAddr, &hitMapHeadNode, &totalNode);
        if(eaddr - baddr >= 8) { // TODO: add 8 to hitMap context
            bufHash = initHitMapBufHTNode(baddr, eaddr, minseq, maxseq,
                                          numOfAddr, hitMapHeadNode, totalNode);
            HASH_FIND(hh_hmBufHash, hitMapBufHash, &baddr, 4, bufFound);
            if(bufFound == NULL) {
                HASH_ADD(hh_hmBufHash, hitMapBufHash, baddr, 4, bufHash);
            } else { free(bufHash); bufHash = NULL; }
        }
    }
    HASH_SRT(hh_hmBufHash, hitMapBufHash, cmpHitMapBufHashNode);
    return hitMapBufHash;
}

static u32
getHitMapTotalNode(HitMapContext *hitMap)
{
    return HASH_CNT(hh_hitMapBufNode2NodeHT, hitMap->hitMapNodeHT);
}

static u32
getHitMapTotalTransaction(HitMapContext *hitMap)
{
    u32 totalTrans = 0;
    HitMapBufNodePtr2NodeHashTable *item, *temp;
    HASH_ITER(hh_hitMapBufNode2NodeHT, hitMap->hitMapNodeHT, item, temp ) {
        // printHitMapNode(item->toHitMapNode);
        totalTrans +=  getHitMapNodeTransactionNumber(item->toHitMapNode);
    }
    return totalTrans;
}

static u32
getHitMapReverseTotalTrans(HitMapContext *hitMap)
{
    u32 totalTrans = 0, totalNode = 0;
    HitMapBufNodePtr2NodeHashTable *item, *temp;
    HASH_ITER(hh_hitMapBufNode2NodeHT, hitMap->hitMapNodeHT, item, temp ) {
        // printHitMapNode(item->toHitMapNode);
        totalTrans += getHitMapNodeReverseTransNum(item->toHitMapNode);
        totalNode++;
    }
    // printf("total nodes:%u\n", totalNode);
    return totalTrans;
}

static u32
getHitMapNodeTransactionNumber(HitMapNode *hmNode)
{
    u32 numOfTrans = 0;
    HitTransition *firstChild = hmNode->firstChild;
    // printf("-----farther\n");
    // printHitMapNodeLit(hmNode);
    while(firstChild != NULL) {
        numOfTrans++;
        // printHitMapTransition(firstChild);
        firstChild = firstChild->next;
    }
    return numOfTrans;
}

static u32
getHitMapNodeReverseTransNum(HitMapNode *hmNode)
{
    u32 numOfTrans = 0;
    HitTransition *taintedBy = hmNode->taintedBy;
    while(taintedBy != NULL) {
        numOfTrans++;
        taintedBy = taintedBy->next;
    }
    return numOfTrans;
}

static u32
getHitMapTotalIntermediateNode(HitMapContext *hitMapCtxt)
{
    return HASH_CNT(hh_intrtmdtNode2HitMapNodeHT, hitMapCtxt->intrtmdt2HitMapNodeHT);
}

static u32
getHitMapIntermediateTotalTrans(HitMapContext *hitMap)
{
    u32 totalIntermediateTrans = 0;
    IntrtmdtNode2HitMapNodeHashTalbe *item, *temp;
    HASH_ITER(hh_intrtmdtNode2HitMapNodeHT, hitMap->intrtmdt2HitMapNodeHT, item, temp) {
        totalIntermediateTrans += getHitMapNodeTransactionNumber(item->toHitMapNode);
    }
    return totalIntermediateTrans;
}

static void
compHitMapBufStat(
        HitMapNode *hmNode,
        u32 *baddr,
        u32 *eaddr,
        int *minseq,
        int *maxseq,
        u32 *numOfAddr,
        HitMapNode **firstnode,
        u32 *totalNode)
{
    HitMapNode *b, *e, *lastend;

    assert(hmNode != NULL);

    *totalNode = 0;
    *numOfAddr = 0;
    b = e = hmNode;

    // while(b->leftNBR != NULL) { b = b->leftNBR; }; // traverse to left most
    b = getLeftMost(hmNode);
    *baddr = b->addr;
    *firstnode = b;
    getFirstVerNode(firstnode);

    *minseq = (*firstnode)->lastUpdateTS;
    *maxseq = (*firstnode)->lastUpdateTS;

    e = *firstnode;
    while(e != NULL) {
        u32 ver = e->version;
        int seqN = 0;
        do {
            seqN = e->lastUpdateTS;
            if(*minseq > seqN)
                *minseq = seqN;

            if(*maxseq < seqN)
                *maxseq = seqN;

            *totalNode += 1;
            e = e->nextVersion;
        } while (ver != e->version);

        lastend = e;
        e = e->rightNBR;
        (*numOfAddr)++;
    }
    *eaddr = lastend->addr + lastend->bytesz;
}

static HitMapNode *
getLeftMost(HitMapNode *node)
{
    HitMapNode *leftMost = node;

    while (true) {
        if (isAllVersionNodeLeftMost(leftMost))
            break;

        if (leftMost->leftNBR != NULL) {
            leftMost = leftMost->leftNBR;
        } else {
            leftMost = leftMost->nextVersion;
        }
    }
    return leftMost;
}

static bool
isAllVersionNodeLeftMost(HitMapNode *node)
{
    u32 ver = node->version;
    do {
        if(node->leftNBR != NULL) {
            return false;
        }
        else {
            node = node->nextVersion;
        }
    } while(ver != node->version);
    return true;
}


static void
getFirstVerNode(HitMapNode **first)
{
    assert(*first != NULL);
    HitMapNode *node = *first;

    u32 ver = (*first)->version;
    do {
        if((*first)->version > node->version)
            *first = node;
        node = node->nextVersion;
    } while(ver != node->version);
}

static HitMapBufHash *
initHitMapBufHTNode(
        u32 baddr,
        u32 eaddr,
        int minseq,
        int maxseq,
        u32 numOfAddr,
        HitMapNode *firstnode,
        u32 totalNode)
{
    HitMapBufHash *node = calloc(1, sizeof(HitMapBufHash) );
    assert(node != NULL);

    node->baddr = baddr;
    node->eaddr = eaddr;
    node->minseq = minseq;
    node->maxseq = maxseq;
    node->numOfAddr = numOfAddr;
    node->headNode = firstnode;
    node->totalNode = totalNode;
    return node;
}

static int
cmpHitMapBufHashNode(HitMapBufHash *l, HitMapBufHash *r)
{
//    if(l->minseq < r->minseq) { return -1; }
//    else if(l->minseq == r->minseq) { return 0; }
//    else { return 1; }

    if(l->headNode->bufId < r->headNode->bufId) { return -1; }
    else if(l->headNode->bufId == r->headNode->bufId) { return 0; }
    else { return 1; }
}

void
delHitMap(HitMapContext *hitmap)
{
    if(hitmap == NULL)
        return;

    for(int i = 0; i < hitmap->numOfBuf; i++) {
        delBufContext(hitmap->bufArray[i]);
        hitmap->bufArray[i] = NULL;
    }

    free(hitmap->bufArray);
    hitmap->bufArray = NULL;
    free(hitmap);
    printf("del HitMap\n");
}


void
printHitMap(HitMapContext *hitmap)
{
    if(hitmap == NULL) {
        fprintf(stderr, "printHitMap:%p\n", hitmap);
        return;
    }

    printf("HitMap: num of buf:%u maxSeqN:%u\n", hitmap->numOfBuf, hitmap->maxBufSeqN);
    for(int i = 0; i < hitmap->numOfBuf; i++) {
        printf("--------------------Buf Idx:%d\n", i);
        // printHitMapBuf(hitmap->bufArray[i]);
        printf("----------\nBuf Hitcnt In array:\n");
        printHitMapBufHitCnt(hitmap->bufHitcntInArray[i]);
        printf("----------\nBuf Hitcnt out array:\n");
        printHitMapBufHitCnt(hitmap->bufHitcntOutArray[i]);
    }
}

void
printHitMapLit(HitMapContext *hitmap)
{
    if(hitmap == NULL) {
        fprintf(stderr, "printHitMapLit:%p\n", hitmap);
        return;
    }

    printf("HitMap Summary: TPMBufHTPtr:%p HitMapNodeHTPtr:%p maxBufSeqN:%u num of Bufs:%u buf context ary ptr:%p\n",
            hitmap->tpmBuf, hitmap->hitMapNodeHT, hitmap->maxBufSeqN, hitmap->numOfBuf, hitmap->bufArray);
}

void
printHitMapBuf(BufContext *hitMapBuf)
{
    if(hitMapBuf == NULL) {
        printf("HitMapBuf:%p\n", hitMapBuf);
        return;
    }
    printf("----------\nHitMapBuf: num of addr:%u\n", hitMapBuf->numOfAddr);
    for(int i = 0; i < hitMapBuf->numOfAddr; i++) {
        printf("HitMapBuf addr:%p\n", hitMapBuf->addrArray[i]);
        printHitMapNodeAllVersion(hitMapBuf->addrArray[i]);
    }
}

void
printHitMapBufHitCnt(BufHitcntCtxt *bufHitcntCtxt)
{
    if(bufHitcntCtxt == NULL) { return; }
    printf("HitMap Buf Hitcnt: num of addr:%u\n", bufHitcntCtxt->numOfAddr);
    for(int i = 0; i < bufHitcntCtxt->numOfAddr; i++) {
        printf("addr Hitcnt:%u\n", bufHitcntCtxt->addrHitcntArray[i]);
    }
}

void
printHitMapBufHash(HitMapBufHash *hitMapBufHash)
{
    HitMapBufHash *buf, *tmp;
    int bufCnt = 0;
    u32 avg_node, minNode, maxNode, totalNode;

    bufCnt = HASH_CNT(hh_hmBufHash, hitMapBufHash);
    printf("---------------------\ntotal hit map buffer:%d - minimum buffer size:%u\n", bufCnt, 8);

    totalNode = 0;
    minNode = hitMapBufHash->totalNode;
    maxNode = hitMapBufHash->totalNode;

    HASH_ITER(hh_hmBufHash, hitMapBufHash, buf, tmp) {
        printf("begin:0x%-8x end:0x%-8x sz:%-4u numofaddr:%-4u minseq:%-7d maxseq:%-7d diffseq:%-7d bufID:%u total nodes:%u\n",
            buf->baddr, buf->eaddr, buf->eaddr - buf->baddr,
            buf->numOfAddr, buf->minseq, buf->maxseq, (buf->maxseq - buf->minseq),
            buf->headNode->bufId, buf->totalNode);

        if(buf->totalNode < minNode)
            minNode = buf->totalNode;
        if(buf->totalNode > maxNode)
            maxNode = buf->totalNode;
        totalNode += buf->totalNode;
    }
    printf("minimum num of node:%u - maximum num of node:%u - total num of node:%u "
            "- total buf:%u - avg num of node:%u\n",
            minNode, maxNode, totalNode, bufCnt, totalNode / bufCnt);
}

static BufContext *
initBufContext(
        TPMContext *tpm,
        HitMapContext *hitMap,
        TPMBufHashTable *buf)
{
    BufContext *bufCtxt;
    u32 numOfAddr;

    bufCtxt = calloc(1, sizeof(BufContext));
    assert(bufCtxt != NULL);

    numOfAddr= buf->numOfAddr;
    bufCtxt->numOfAddr = numOfAddr;
    bufCtxt->addrArray = calloc(1, sizeof(HitMapNode *) * numOfAddr);
    for(int i = 0; i < numOfAddr; i++)
        bufCtxt->addrArray[i] = NULL;

    return bufCtxt;
}

static BufHitcntCtxt *
initBufHitCntCtxt(TPMBufHashTable *buf)
{
    BufHitcntCtxt *bufHitCntCtxt;
    u32 numOfAddr;

    bufHitCntCtxt = calloc(1, sizeof(BufHitcntCtxt) );
    assert(bufHitCntCtxt != NULL);

    numOfAddr = buf->numOfAddr;
    bufHitCntCtxt->numOfAddr = numOfAddr;

#if defined ENV32
    // printf("init buf hit count context 32 bit\n");
    bufHitCntCtxt->addrHitcntArray = calloc(1, sizeof(u32) * numOfAddr);
#elif defined ENV64
    // printf("init buf hit count context 64 bit\n");
    bufHitCntCtxt->addrHitcntArray = calloc(1, sizeof(u64) * numOfAddr);
#endif
    assert(bufHitCntCtxt->addrHitcntArray != NULL);

    for(int i = 0; i < numOfAddr; i++) {
        bufHitCntCtxt->addrHitcntArray[i] = 0;
    }

    return bufHitCntCtxt;
}

static void
buildBufContext(
        TPMContext *tpm,
        HitMapContext *hitMap,
        TPMBufHashTable *buf)
{

    // printf("----------\nbegin addr:0x%-8x end addr:0x%-8x sz:%u numofaddr:%-2u minseq:%d maxseq:%d diffseq:%d bufID:%u\n",
    //         buf->baddr, buf->eaddr, buf->eaddr - buf->baddr,
    //         buf->numOfAddr, buf->minseq, buf->maxseq, (buf->maxseq - buf->minseq), buf->headNode->bufid);
    // printMemNode(buf->headNode);

    TPMNode2 *bufHead = buf->headNode;
    while(bufHead != NULL) {
        // printMemNodeLit(bufHead);
        buildHitMapAddr(tpm, hitMap, bufHead);
        bufHead = bufHead->rightNBR;
    }
}

static void
delBufContext(BufContext *bufCtxt)
{
    if(bufCtxt == NULL)
        return;

    free(bufCtxt->addrArray);
    bufCtxt->addrArray = NULL;
    free(bufCtxt);
}

static void
buildHitMapAddr(
        TPMContext *tpm,
        HitMapContext *hitMap,
        TPMNode2 *headNode)
{
    if(hitMap == NULL || headNode == NULL){
        fprintf(stderr, "hitMap:%p headNode:%p\n", hitMap, headNode);
        return;
    }
    else {
        if(headNode->version != 0) {
           fprintf(stderr, "headnode version:%u\n", headNode->version);
           return;
        }
    }
    // printMemNode(headNode);
    u32 currVersion = headNode->version;

    do {
        bufnodePropgt2HitMapNode(tpm, headNode, hitMap);
        headNode = headNode->nextVersion;
    } while (currVersion != headNode->version);
}

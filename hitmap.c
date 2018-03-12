#include "hitmap.h"
#include "propagate.h"
#include <assert.h>

/* build HitMap of each buffer in TPM*/
static BufContext *
initBufContext(
        TPMContext *tpm,
        HitMapContext *hitMap,
        TPMBufHashTable *buf);


static void
buildBufContext(
        TPMContext *tpm,
        HitMapContext *hitMap,
        TPMBufHashTable *buf);

static void
delBufContext(BufContext *bufCtxt);

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

//static HitMapNode *
//createHitMapRecordNode(TPMNode2 *node, HitMapContext *hitMap);
//
//static void
//attachHitTransition(HitMapNode *srcHMN, HitTransition *t);

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
    hitMap->bufArray = calloc(1, sizeof(BufContext *) * numOfBuf);
    hitMap->tpmBuf = tpmBuf;

    // printHitMapLit(hitMap);

    i = 0;
    for(currBuf = tpmBuf; currBuf != NULL; currBuf = currBuf->hh_tpmBufHT.next) {
        hitMap->bufArray[i] = initBufContext(tpm, hitMap, currBuf);
        i++;
    }

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
compHitMapStat(HitMapContext *hitMap)
{
    u32 numOfNode, numOfIntermediateNode;
    u32 totalTrans, totalIntermediateTrans;

    sortHitMapHashTable(&(hitMap->hitMapNodeHT) );

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
        printHitMapBuf(hitmap->bufArray[i]);
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
    printf("HitMapBuf: num of addr:%u\n", hitMapBuf->numOfAddr);
    for(int i = 0; i < hitMapBuf->numOfAddr; i++) {
        printf("----------\nHitMapBuf addr:%p\n", hitMapBuf->addrArray[i]);
        printHitMapNodeAllVersion(hitMapBuf->addrArray[i]);
    }
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

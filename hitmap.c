#include "hitmap.h"
#include "propagate.h"
#include <assert.h>

/* build HitMap of each buffer in TPM*/
static BufContext *
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

//static HitMapNode *
//createHitMapRecordNode(TPMNode2 *node, HitMapContext *hitMap);
//
//static void
//attachHitTransition(HitMapNode *srcHMN, HitTransition *t);

HitMapContext *
buildHitMap(TPMContext *tpm)
{
    HitMapContext *hitMap;
    TPMBufHashTable *tpmBuf, *currBuf;;
    int numOfBuf, i;
    u32 maxBufSeqN;

    tpmBuf = analyzeTPMBuf(tpm);
    assignTPMBufID(tpmBuf);
    numOfBuf= HASH_CNT(hh_tpmBufHT, tpmBuf);
    printTPMBufHashTable(tpmBuf);

    hitMap = calloc(1, sizeof(HitMapContext) );
    assert(hitMap != NULL);

    hitMap->hitMapNodeHT = NULL;
    hitMap->maxBufSeqN = getTPMBufMaxSeqN(tpmBuf);
    hitMap->numOfBuf = numOfBuf;
    hitMap->bufArray = calloc(1, sizeof(BufContext *) * numOfBuf);

    i = 0;
    for(currBuf = tpmBuf; currBuf != NULL; currBuf = currBuf->hh_tpmBufHT.next) {
        hitMap->bufArray[i] = buildBufContext(tpm, hitMap, currBuf);
        i++;
    }

    delAllTPMBuf(tpmBuf);
    return hitMap;
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
printHitMapBuf(BufContext *hitMapBuf)
{
    if(hitMapBuf == NULL) {
        printf("HitMapBuf:%p\n", hitMapBuf);
        return;
    }
    printf("HitMapBuf: num of addr:%u\n", hitMapBuf->numOfAddr);
    for(int i = 0; i < hitMapBuf->numOfAddr; i++) {
        printf("HitMapBuf addr:%p\n", hitMapBuf->addrArray[i]);
    }
}


static BufContext *
buildBufContext(
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

    TPMNode2 *bufHead = buf->headNode;
    while(bufHead != NULL) {
        // printMemNode(bufHead);
        buildHitMapAddr(tpm, hitMap, bufHead);
        bufHead = bufHead->rightNBR;
    }

    return bufCtxt;
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

    u32 currVersion = headNode->version;

    do {
        bufnodePropgt2HitMapNode(tpm, headNode, hitMap);
        headNode = headNode->nextVersion;
    } while (currVersion != headNode->version);
}

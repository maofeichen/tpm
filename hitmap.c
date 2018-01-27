#include "hitmap.h"
#include <assert.h>

/* build HitMap of each buffer in TPM*/
static BufContext *
buildBufContext(HitMapContext *hitMap, TPMBufHashTable *buf);

static void
delBufContext(BufContext *bufCtxt);

/* build HitMap of each addr of each buffer */
static void
buildHitMapAddr(HitMapContext *hitMap, TPMNode2 *headNode);

HitMapContext *
buildHitMap(TPMContext *tpm)
{
    HitMapContext *hitMap;
    TPMBufHashTable *tpmBuf, *currBuf;;
    int numOfBuf, i;

    tpmBuf = analyzeTPMBuf(tpm);
    assignTPMBufID(tpmBuf);
    numOfBuf= HASH_CNT(hh_tpmBufHT, tpmBuf);
    printTPMBufHashTable(tpmBuf);

    hitMap = calloc(1, sizeof(HitMapContext) );
    assert(hitMap != NULL);

    // hitMap->hitMapNodeHT = NULL;
    hitMap->numOfBuf = numOfBuf;
    hitMap->bufArray = calloc(1, sizeof(BufContext *) * numOfBuf);

    i = 0;
    for(currBuf = tpmBuf; currBuf != NULL; currBuf = currBuf->hh_tpmBufHT.next) {
        hitMap->bufArray[i] = buildBufContext(hitMap, currBuf);
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

    printf("HitMap: num of buf:%u\n", hitmap->numOfBuf);
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
buildBufContext(HitMapContext *hitMap, TPMBufHashTable *buf)
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
        buildHitMapAddr(hitMap, bufHead);
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
buildHitMapAddr(HitMapContext *hitMap, TPMNode2 *headNode)
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
        headNode = headNode->nextVersion;
    } while (currVersion != headNode->version);
}

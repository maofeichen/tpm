#include "hitmap.h"
#include <assert.h>

static BufContext *
buildBufContext(TPMBufHashTable *buf);

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

    hitMap->numOfBuf = numOfBuf;
    hitMap->bufArray = calloc(1, sizeof(BufContext *) * numOfBuf);

    i = 0;
    for(currBuf = tpmBuf; currBuf != NULL; currBuf = currBuf->hh_tpmBufHT.next) {
        hitMap->bufArray[i] = buildBufContext(currBuf);
        i++;
    }

    return hitMap;
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
buildBufContext(TPMBufHashTable *buf)
{
    BufContext *bufCtxt;
    int numOfAddr;

    TPMNode2 *bufHead = buf->headNode;
    numOfAddr= buf->numOfAddr;

    bufCtxt = calloc(1, sizeof(BufContext));
    assert(bufCtxt != NULL);

    bufCtxt->numOfAddr = numOfAddr;
    bufCtxt->addrArray = calloc(1, sizeof(HitMapNode *) * numOfAddr);
    for(int i = 0; i < numOfAddr; i++)
        bufCtxt->addrArray[i] = NULL;

    return bufCtxt;
}

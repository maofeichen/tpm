#include "bufhitcnt.h"
#include "hitmappropagate.h"
#include <assert.h>

static u32 **
initBufHitCntArray(u32 numOfBuf);

static void
buildBufHitCntAryOfBuf(
        u32 **bufHitCntAry,
        u32 numOfBuf,
        BufContext *hitMapBuf);

static void
buildBufHitCntAryOfAddr(
        u32 **bufHitCntAry,
        u32 numOfBuf,
        HitMapNode *addrHead);

u32 **
buildBufHitCntArray(HitMapContext *hitMap)
{
    TPMBufHashTable *tpm_buf;
    u32 **bufHitCntAry = NULL;
    u32 numOfBuf, bufIdx;

    if(hitMap == NULL) { return NULL; }

    numOfBuf = hitMap->numOfBuf;
    bufHitCntAry = initBufHitCntArray(numOfBuf);

    bufIdx = 0;
    tpm_buf = hitMap->tpmBuf;
    for(; tpm_buf != NULL; tpm_buf = tpm_buf->hh_tpmBufHT.next) {
        if(tpm_buf->minseq >= 0) // minseq < 0 indicates it might contain source nodes
            break;

        buildBufHitCntAryOfBuf(bufHitCntAry, numOfBuf, hitMap->bufArray[bufIdx]);
        bufIdx++;
    }

    return bufHitCntAry;
}

void
delBufHitCntArray(u32 **bufHitCntArray, u32 numOfBuf)
{
    if(bufHitCntArray != NULL) {
        for(int i = 0; i < numOfBuf; i++) {
            if(bufHitCntArray[i] != NULL) {
                free(bufHitCntArray[i]);
                bufHitCntArray[i] = NULL;
            }
        }

        free(bufHitCntArray);
        bufHitCntArray = NULL;
        printf("del buffer hit count array\n");
    }
}

void
compBufHitCntArrayStat(
        u32 **bufHitCntArray,
        u32 numOfBuf,
        u32 byteThreashold)
{
    u32 hitThreash = 0;
    for(int r = 0; r < numOfBuf; r++) {
        for (int c = 0; c < numOfBuf; c++) {
            if(bufHitCntArray[r][c] >= byteThreashold)
                hitThreash++;
        }
    }
    printf("----------\nnum of buf pair hitcnt > %u bytes:%u - total buf pair:%u - ratio:%u%%\n",
            byteThreashold, hitThreash, numOfBuf*numOfBuf, (hitThreash * 100) / (numOfBuf*numOfBuf) );
}


void
printBufHitCntArray(u32 **bufHitCntArray, u32 numOfBuf)
{
    for(int r = 0; r < numOfBuf; r++) {
        for (int c = 0; c < numOfBuf; c++) {
            printf("buffer hit count array[%d][%d]:%u\n", r, c, bufHitCntArray[r][c]);
        }
    }
}


static u32 **
initBufHitCntArray(u32 numOfBuf)
{
    u32 **bufHitCntAry = NULL;

    if((bufHitCntAry = calloc(1, sizeof(u32) * numOfBuf) ) != NULL ) {
        for(int i = 0; i < numOfBuf; i++) {
            bufHitCntAry[i] = calloc(1, sizeof(u32) * numOfBuf);
            assert(bufHitCntAry[i] != NULL);
        }
    }
    else { fprintf(stderr, "fails allocating 2D buffer hit count array\n"); }
    // printf("num of tpm buffers:%u\n", numOfBuf);

    return bufHitCntAry;
}

static void
buildBufHitCntAryOfBuf(
        u32 **bufHitCntAry,
        u32 numOfBuf,
        BufContext *hitMapBuf)
{
    HitMapNode *addrHead;
    u32 addrIdx;

    if(bufHitCntAry == NULL || hitMapBuf == NULL) { return; }

    for(addrIdx = 0; addrIdx < hitMapBuf->numOfAddr; addrIdx++) {
        if((addrHead = hitMapBuf->addrArray[addrIdx]) != NULL) {
            buildBufHitCntAryOfAddr(bufHitCntAry, numOfBuf, addrHead);
        }
    }
}

static void
buildBufHitCntAryOfAddr(
        u32 **bufHitCntAry,
        u32 numOfBuf,
        HitMapNode *addrHead)
{
    if(bufHitCntAry == NULL || addrHead == NULL) { return; }

    u32 ver = addrHead->version;
    do {
        if(addrHead->lastUpdateTS < 0) {
            // printHitMapNodeLit(addrHead);
            hitMapNodePropgtOfBuildBufHitCntAry(bufHitCntAry, numOfBuf, addrHead);
        }
        addrHead = addrHead->nextVersion;
    } while(ver != addrHead->version);
}

#include "bufhitcnt.h"
#include "hitmappropagate.h"
#include "misc.h"
#include <assert.h>

#ifdef ENV64
static u64 *
initBufHitCntArray(u32 numOfBuf);
#else
static u32 *
initBufHitCntArray(u32 numOfBuf);
#endif

static void
buildBufHitCntAryOfBuf(
#ifdef ENV64
        u64 *bufHitCntAry,
#else
        u32 *bufHitCntAry,
#endif
        u32 numOfBuf,
        BufContext *hitMapBuf);

static void
buildBufHitCntAryOfAddr(
#ifdef ENV64
        u64 *bufHitCntAry,
#else
        u32 *bufHitCntAry,
#endif
        u32 numOfBuf,
        HitMapNode *addrHead);

#ifdef ENV64
u64 *
buildBufHitCntArray(HitMapContext *hitMap)
#else
u32 *
buildBufHitCntArray(HitMapContext *hitMap)
#endif
{
    TPMBufHashTable *tpm_buf;
#if defined ENV64
	u64 *bufHitCntAry = NULL;
#else
	u32 *bufHitCntAry = NULL;
#endif
    u32 numOfBuf, bufIdx;

    if(hitMap == NULL) { return NULL; }

    printTime("Before build buffer hit count array");
    // printf("num of TPM buffers:%u\n", hitMap->numOfBuf);

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
	printTime("After build buffer hit count array");
    return bufHitCntAry;
}

#ifdef ENV64
void
delBufHitCntArray(u64 *bufHitCntArray, u32 numOfBuf)
#else
void
delBufHitCntArray(u32 *bufHitCntArray, u32 numOfBuf)
#endif
{
    if(bufHitCntArray != NULL) {
        free(bufHitCntArray);
        bufHitCntArray = NULL;
        printf("del buffer hit count array\n");
    }
}

#ifdef ENV64
void
compBufHitCntArrayStat(
        u64 *bufHitCntArray,
        u32 numOfBuf,
        u32 byteThreashold)
#else
void
compBufHitCntArrayStat(
        u32 *bufHitCntArray,
        u32 numOfBuf,
        u32 byteThreashold)
#endif
{
    u32 hitThreash = 0;
    for(size_t r = 0; r < numOfBuf; r++) {
        for (size_t c = 0; c < numOfBuf; c++) {
            // u32 val  = *(bufHitCntArray + r * numOfBuf + c);
            u32 val = bufHitCntArray[r * numOfBuf + c];
            if(val >= byteThreashold)
                hitThreash++;
        }
    }
    printf("----------\nnum of buf pair hitcnt > %u bytes:%u - total buf pair:%u - ratio:%u%%\n",
            byteThreashold, hitThreash, numOfBuf*numOfBuf, (hitThreash * 100) / (numOfBuf*numOfBuf) );
}


void
printBufHitCntArray(u32 *bufHitCntArray, u32 numOfBuf)
{
    for(int r = 0; r < numOfBuf; r++) {
        for (int c = 0; c < numOfBuf; c++) {
            // printf("buffer hit count array[%d][%d]:%u\n", r, c, bufHitCntArray[r][c]);
            u32 val = *(bufHitCntArray + r * numOfBuf + c);
            printf("buffer hit count array[%d][%d]:%u\n", r, c, val);
        }
    }
}

#ifdef ENV64
static u64 *
initBufHitCntArray(u32 numOfBuf)
#else
static u32 *
initBufHitCntArray(u32 numOfBuf)
#endif
{
#ifdef ENV64
    u64 *bufHitCntAry = NULL;
#else
    u32 *bufHitCntAry = NULL;
#endif

#ifdef ENV64
    // printf("init buf hit count context 64 bit\n");
    bufHitCntAry = calloc(1, sizeof(u32) * numOfBuf * numOfBuf);
#else
    // printf("init buf hit count context 32 bit\n");
    bufHitCntAry = calloc(1, sizeof(u32) * numOfBuf * numOfBuf);
#endif
    assert(bufHitCntAry != NULL);

    for(size_t r = 0; r < numOfBuf; r++) {
        for(size_t c = 0; c < numOfBuf; c++) {
            bufHitCntAry[r*numOfBuf + c] = 0;
        }
    }

    return bufHitCntAry;
}

static void
buildBufHitCntAryOfBuf(
#ifdef ENV64
        u64 *bufHitCntAry,
#else
        u32 *bufHitCntAry,
#endif
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
#ifdef ENV64
        u64 *bufHitCntAry,
#else
        u32 *bufHitCntAry,
#endif
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

#include "hitmapavalanche.h"
#include <assert.h>

static HitMapAvalSearchCtxt *
initHitMapAvalSearchCtxt(
        u32 srcBufIdx,
        TPMBufHashTable *srcTPMBuf,
        u32 dstbufIdx,
        TPMBufHashTable *dstTPMBuf);

static void
freeHitMapAvalSearchCtxt(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt);

static void
detectHitMapAvalInOut(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt);

void
detectHitMapAvalanche(HitMapContext *hitMap, TPMContext *tpm)
{
    u32 numOfBuf;
    TPMBufHashTable *srcTPMBuf;
    TPMBufHashTable *dstTPMBuf;
    HitMapAvalSearchCtxt *hitMapAvalSrchCtxt;

    numOfBuf = hitMap->numOfBuf;
    for(u32 srcBufIdx = 0; srcBufIdx < numOfBuf-1; srcBufIdx++) {
        for(u32 dstBufIdx = srcBufIdx + 1; dstBufIdx < numOfBuf; dstBufIdx++) {
            srcTPMBuf = getTPMBuf(hitMap->tpmBuf, srcBufIdx);
            dstTPMBuf = getTPMBuf(hitMap->tpmBuf, dstBufIdx);
            hitMapAvalSrchCtxt = initHitMapAvalSearchCtxt(srcBufIdx, srcTPMBuf, dstBufIdx, dstTPMBuf);
            detectHitMapAvalInOut(hitMapAvalSrchCtxt);
            freeHitMapAvalSearchCtxt(hitMapAvalSrchCtxt);
        }
//        for(int addrIdx = 0; addrIdx < hitMap->bufArray[srcBufIdx]->numOfAddr; addrIdx++) {
//            HitMapNode *addrHeadNode = hitMap->bufArray[srcBufIdx]->addrArray[addrIdx];
//            // printHitMapNode(addrHeadNode);
//            // hitMapNodePropagate(addrHeadNode, hitMap, tpm);
//            goto OutOfLoop;
//        }
    }
OutOfLoop:
    printf("");
}

static HitMapAvalSearchCtxt *
initHitMapAvalSearchCtxt(
        u32 srcBufIdx,
        TPMBufHashTable *srcTPMBuf,
        u32 dstbufIdx,
        TPMBufHashTable *dstTPMBuf)
{
    HitMapAvalSearchCtxt *h = calloc(1, sizeof(HitMapAvalSearchCtxt) );
    assert(h != NULL);

    h->srcTPMBuf = srcTPMBuf;
    h->dstTPMBuf = dstTPMBuf;
    h->srcBufID = srcBufIdx;
    h->dstBufID = dstbufIdx;
    h->srcAddrStart = srcTPMBuf->baddr;
    h->srcAddrEnd = srcTPMBuf->eaddr;
    h->dstAddrStart = dstTPMBuf->baddr;
    h->dstAddrEnd = dstTPMBuf->eaddr;
    h->srcMinSeqN = srcTPMBuf->minseq;
    h->srcMaxSeqN = srcTPMBuf->maxseq;
    h->dstMinSeqN= dstTPMBuf->minseq;
    h->dstMaxSeqN = dstTPMBuf->maxseq;
    h->numOfSrcAddr = srcTPMBuf->numOfAddr;
    h->numOfDstAddr = dstTPMBuf->numOfAddr;
    h->hitMapAddr2NodeAry = calloc(1, srcTPMBuf->numOfAddr * sizeof(HitMapAddr2NodeItem) );
    assert(h->hitMapAddr2NodeAry != NULL);

    return h;
}

static void
freeHitMapAvalSearchCtxt(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt)
{
    free(hitMapAvalSrchCtxt->hitMapAddr2NodeAry);
    hitMapAvalSrchCtxt->hitMapAddr2NodeAry = NULL;
    free(hitMapAvalSrchCtxt);
    hitMapAvalSrchCtxt = NULL;
}

static void
detectHitMapAvalInOut(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt)
{
    printf("---------------\n");
    print1TPMBufHashTable("srcTPMBuf:\n", hitMapAvalSrchCtxt->srcTPMBuf);
    print1TPMBufHashTable("dstTPMBuf:\n", hitMapAvalSrchCtxt->dstTPMBuf);
}

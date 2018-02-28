#include "hitmapavalanche.h"
#include "hitmappropagate.h"
#include "misc.h"
#include "uthash.h"
#include <assert.h>
#include <unistd.h>

static HitMapAvalSearchCtxt *
initHitMapAvalSearchCtxt(
        u32 srcBufIdx,
        TPMBufHashTable *srcTPMBuf,
        u32 dstbufIdx,
        TPMBufHashTable *dstTPMBuf);

static void
freeHitMapAvalSearchCtxt(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt);

static void
detectHitMapAvalInOut(
        HitMapAvalSearchCtxt *hitMapAvalSrchCtxt,
        HitMapContext *hitMap,
        double *totalElapse);

static void
searchHitMapPropgtInOut(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt, HitMapContext *hitMap);

void
detectHitMapAvalanche(HitMapContext *hitMap, TPMContext *tpm)
{
    u32 numOfBuf, srcBufIdx, dstBufIdx;
    TPMBufHashTable *srcTPMBuf;
    TPMBufHashTable *dstTPMBuf;
    HitMapAvalSearchCtxt *hitMapAvalSrchCtxt;

    double totalElapse = 0;
    u32 searchCnt = 0;

    numOfBuf = hitMap->numOfBuf;
    for(srcBufIdx = 0; srcBufIdx < numOfBuf-1; srcBufIdx++) {
        for(dstBufIdx = srcBufIdx + 1; dstBufIdx < numOfBuf; dstBufIdx++) {

            // if((srcBufIdx >= 265 && srcBufIdx <= 270)
            //     || (srcBufIdx >= 925 && srcBufIdx <= 930) ) {
            //     if(dstBufIdx == srcBufIdx+1 || dstBufIdx == numOfBuf-1) {
            //         srcTPMBuf = getTPMBuf(hitMap->tpmBuf, srcBufIdx);
            //         dstTPMBuf = getTPMBuf(hitMap->tpmBuf, dstBufIdx);
            //         hitMapAvalSrchCtxt = initHitMapAvalSearchCtxt(srcBufIdx, srcTPMBuf, dstBufIdx, dstTPMBuf);
            //         detectHitMapAvalInOut(hitMapAvalSrchCtxt, hitMap);
            //         freeHitMapAvalSearchCtxt(hitMapAvalSrchCtxt);

            //         searchCnt++;
            //     }
            // }

            srcTPMBuf = getTPMBuf(hitMap->tpmBuf, srcBufIdx);
            dstTPMBuf = getTPMBuf(hitMap->tpmBuf, dstBufIdx);
            hitMapAvalSrchCtxt = initHitMapAvalSearchCtxt(srcBufIdx, srcTPMBuf, dstBufIdx, dstTPMBuf);
            detectHitMapAvalInOut(hitMapAvalSrchCtxt, hitMap, &totalElapse);
            freeHitMapAvalSearchCtxt(hitMapAvalSrchCtxt);

            searchCnt++;
        }
        break;
    }
    if(searchCnt > 0)
        printf("---------------\navg build 2-level hash table time:%.1f microseconds\n", totalElapse/searchCnt);
OutOfLoop:
    printf("");
}

void
printHitMapAvalSrchCtxt(HitMapAvalSearchCtxt *hmAvalSrchCtxt)
{
    if(hmAvalSrchCtxt == NULL)
        return;

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
    for(int addrIdx = 0; addrIdx < hitMapAvalSrchCtxt->numOfSrcAddr; addrIdx++) {
        freeHitMapAddr2NodeItem(hitMapAvalSrchCtxt->hitMapAddr2NodeAry[addrIdx]);
    }

    free(hitMapAvalSrchCtxt->hitMapAddr2NodeAry);
    hitMapAvalSrchCtxt->hitMapAddr2NodeAry = NULL;
    free(hitMapAvalSrchCtxt);
    hitMapAvalSrchCtxt = NULL;
    // printf("del hitMapAvalSrchCtxt\n");
}

static void
detectHitMapAvalInOut(
        HitMapAvalSearchCtxt *hitMapAvalSrchCtxt,
        HitMapContext *hitMap,
        double *totalElapse)
{
    u32 srcBufNodeTotal, dstBufNodeTotal;
    u32 numOfTrans, srcAddrIdx, srcBufID;

    srcBufNodeTotal = getTPMBufNodeTotal(hitMapAvalSrchCtxt->srcTPMBuf);
    dstBufNodeTotal = getTPMBufNodeTotal(hitMapAvalSrchCtxt->dstTPMBuf);

    printf("----------------------------------------\n");
    print1TPMBufHashTable("src buf: ", hitMapAvalSrchCtxt->srcTPMBuf);
    print1TPMBufHashTable("dst buf: ", hitMapAvalSrchCtxt->dstTPMBuf);
    printf("total src buf node:%u - total dst buf node:%u\n", srcBufNodeTotal, dstBufNodeTotal);
    // printTime("before search propagation");
    printTimeMicroStart();

    searchHitMapPropgtInOut(hitMapAvalSrchCtxt, hitMap);

    // printTime("after search propagation");
    printTimeMicroEnd(totalElapse);

    numOfTrans = 0;
    srcBufID = hitMapAvalSrchCtxt->srcBufID;
    for(srcAddrIdx = 0; srcAddrIdx < hitMap->bufArray[srcBufID]->numOfAddr; srcAddrIdx++) {
        numOfTrans += getHitMap2LAddr2NodeItemTotal(hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx]);
    }
    printf("number of transition of 2-level hash table:%u\n", numOfTrans);
}

static void
searchHitMapPropgtInOut(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt, HitMapContext *hitMap)
// Searches propagations of source buffer (all version of each node) to dst buf,
// results store in dstMemNodesHT
// 1. Search propagation
// For each version node of each addr of input buffer as source
// 1.1 searches the source node propagations to destination buffers (within addr/seqNo range)
{
    u32 srcAddrIdx, srcBufID;

    srcBufID = hitMapAvalSrchCtxt->srcBufID;
    if(hitMapAvalSrchCtxt->srcBufID >= hitMap->numOfBuf) {
        fprintf(stderr, "searchHitMapPropgtInOut error: invalid src buf ID\n");
        return;
    }

    for(srcAddrIdx = 0; srcAddrIdx < hitMap->bufArray[srcBufID]->numOfAddr; srcAddrIdx++) {
        HitMapNode *head = hitMap->bufArray[srcBufID]->addrArray[srcAddrIdx];
        if(head == NULL)
            continue;   // TODO: Debug

        u32 ver = head->version;

        do {
            // printHitMapNodeLit(head);
            HitMapAddr2NodeItem *hmAddr2NodeItem = createHitMapAddr2NodeItem(head->addr, head, NULL, NULL);
            HASH_ADD(hh_hmAddr2NodeItem, hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx], node, 4, hmAddr2NodeItem);

            //Dbg
            // if(head->addr == 0xefccbd9c && head->version == 34)
            //     printf("dbg\n");

            hitMapNodePropagate(head, hitMap, hmAddr2NodeItem, hitMapAvalSrchCtxt->dstAddrStart, hitMapAvalSrchCtxt->dstAddrEnd,
                    hitMapAvalSrchCtxt->dstMinSeqN, hitMapAvalSrchCtxt->dstMaxSeqN);
            // printHitMapAddr2NodeItemSubhash(hmAddr2NodeItem);
            head = head->nextVersion;
        } while(ver != head->version);

        HASH_SRT(hh_hmAddr2NodeItem, hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx], cmpHitMapAddr2NodeItem);
        printHitMap2LAddr2NodeItem(hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx]);
        // assert(head->leftNBR == NULL);
    }
}

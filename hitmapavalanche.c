#include "hitmapavalanche.h"
#include "hitmappropagate.h"
#include "uthash.h"
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
detectHitMapAvalInOut(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt, HitMapContext *hitMap);

static void
searchHitMapPropgtInOut(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt, HitMapContext *hitMap);

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
            detectHitMapAvalInOut(hitMapAvalSrchCtxt, hitMap);
            freeHitMapAvalSearchCtxt(hitMapAvalSrchCtxt);
            break;
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
    free(hitMapAvalSrchCtxt->hitMapAddr2NodeAry);
    hitMapAvalSrchCtxt->hitMapAddr2NodeAry = NULL;
    free(hitMapAvalSrchCtxt);
    hitMapAvalSrchCtxt = NULL;
}

static void
detectHitMapAvalInOut(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt, HitMapContext *hitMap)
{
    printf("---------------\n");
    print1TPMBufHashTable("srcTPMBuf:\n", hitMapAvalSrchCtxt->srcTPMBuf);
    print1TPMBufHashTable("dstTPMBuf:\n", hitMapAvalSrchCtxt->dstTPMBuf);

    searchHitMapPropgtInOut(hitMapAvalSrchCtxt, hitMap);

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
            printHitMapNodeLit(head);
            HitMapAddr2NodeItem *hmAddr2NodeItem = createHitMapAddr2NodeItem(head->addr, head, NULL, NULL);
            HASH_ADD(hh_hmAddr2NodeItem, hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx], node, 4, hmAddr2NodeItem);
            hitMapNodePropagate(head, hitMap, hmAddr2NodeItem, hitMapAvalSrchCtxt->dstAddrStart, hitMapAvalSrchCtxt->dstAddrEnd,
                    hitMapAvalSrchCtxt->dstMinSeqN, hitMapAvalSrchCtxt->dstMaxSeqN);
            // printHitMapAddr2NodeItemSubhash(hmAddr2NodeItem);
            head = head->nextVersion;
        } while(ver != head->version);

        printHitMap2LAddr2NodeItem(hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx]);
        // assert(head->leftNBR == NULL);
        break;
    }
}

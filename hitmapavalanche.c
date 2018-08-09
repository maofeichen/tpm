#include "continbuf.h"
#include "hitmapavalanche.h"
#include "hitmappropagate.h"
#include "hitmap_addr2nodeitem_datastruct.h"
#include "misc.h"
#include "uthash.h"
#include "utlist.h"
#include <assert.h>
#include <unistd.h>

typedef enum { srcbuf = 0, dstbuf = 1} BufDirect;

typedef struct ContHitCntRange
{
  u32 rstart;
  u32 rend;
  struct ContHitCntRange *next;
} ContHitCntRange;
// stores the sub range of the buffer such that its hitcnt >= min buf sz

static HitMapAvalSearchCtxt *
initHitMapAvalSearchCtxt(
    u32 srcBufIdx,
    TPMBufHashTable *srcTPMBuf,
    u32 dstbufIdx,
    TPMBufHashTable *dstTPMBuf,
    u32 minBufSz);

static HitMapAvalSearchCtxt *
init_HM_avalnch_ctxt_HMBuf(
    u32 srcbuf_idx,
    HitMapBufHash *srcHitMapBuf,
    u32 dstbuf_idx,
    HitMapBufHash *dstHitMapbuf,
    u32 min_bufsz);

static void
freeHitMapAvalSearchCtxt(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt);

static void
detect_HM_avalanche_tpmbuf(
    HitMapContext *hitMap,
    TPMContext *tpm,
    BufType buf_type,
    u8 *buf_hitcnt_ary,
    u32 avalanche_threashold);

static void
detect_HM_avalanche_hitmapbuf(
    HitMapContext *hitMap,
    TPMContext *tpm,
    BufType buf_type,
    u8 *buf_hitcnt_ary,
    u32 avalanche_threashold);

static void
detect_HM_avalnch_HMBuf_noHitCntAry(
    HitMapContext *hitMap,
    TPMContext *tpm,
    BufType bufType);

static void
detect_HM_avalnch_HMBuf_bruteforce(
    HitMapContext *hitMap,
    TPMContext *tpm,
    BufType bufType);

static void
detectHitMapAvalInOut(
    HitMapAvalSearchCtxt *hitMapAvalSrchCtxt,
    HitMapContext *hitMap,
    double *totalElapse);

static void
detect_HM_inoutbuf_HMBuf(
    HitMapAvalSearchCtxt *hitMapAvalSrchCtxt,
    HitMapContext *hitMap,
    double *totalElapse);
// Same as detectHitMapAvalInOut(), but uses HitMap buffer instead of TPM buffer

/* ----- -----  ----- ----- ----- ----- ----- ----- ----- ----- ----- -----*/
static void
searchHitMapPropgtInOut(
    HitMapAvalSearchCtxt *hitMapAvalSrchCtxt,
    HitMapContext *hitMap);

static int
search_HM_inoutbuf_propgt(
    HitMapAvalSearchCtxt *avalnch_HM_ctxt,
    HitMapContext *hitMap);
// Same as searchHitMapPropgtInOut(), but uses HitMap buffer instead of TPM buffer

static int
init_HM_buf_hitcnt(HitMapNode *bufhead);

/* ----- -----  ----- ----- ----- ----- ----- ----- ----- ----- ----- -----*/
static u32
srchHitMapPropgtInOutReverse(
    HitMapAvalSearchCtxt *hitMapAvalSrchCtxt,
    HitMapContext *hitMap);

/* ----- -----  ----- ----- ----- ----- ----- ----- ----- ----- ----- -----*/
static void
create_HMBuf_aggrgt_hitCntAry(
    HitMapNode *bufhead,
    BufDirect bufdirct,
    u32 bufstart,
    u32 bufend,
    HitMapAvalSearchCtxt *avalnch_HM_ctxt);

static void
print_HMBuf_aggrgt_hitCntAry(
    BufDirect bufdirct,
    u8 *hitCntAry,
    u32 bufstart,
    u32 bufend);

/* ----- -----  ----- ----- ----- ----- ----- ----- ----- ----- ----- -----*/
static void
search_inoutbuf_avalnch(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt);

static void
search_inoutbuf_avalnch_subrange(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt);

static ContHitCntRange *
analyze_hitcnt_range(
    u8 *hitCntAry,
    u32 bufstart,
    u32 bufend,
    u32 min_bufsz);

static void
compt_addridx_range(
    u32 *addridx_start,
    u32 *addridx_end,
    u32 rangestart,
    u32 rangeend,
    HitMapAddr2NodeItem **hitMapAddr2NodeAry,
    u32 numOfAddr);

static bool
isSameContRange(ContHitCntRange *l, ContHitCntRange *r);

static void
delContRange(ContHitCntRange **lst);

static void
print_conthitcnt_range(ContHitCntRange *lst, char *s);

static bool
has_valid_range(ContHitCntRange *lst_src, ContHitCntRange *lst_dst);

static bool
has_enough_dstnode(
    HitMapAddr2NodeItem *srcnode,
    u32 min_bufsz);

static void
search_srcnode_avalanche(
    HitMapAddr2NodeItem *srcnode,
    u32 srcbuf_addridx,
    u32 *block_sz_detect,
    HitMapAvalSearchCtxt *hitMapAvalSrchCtxt);

static void
store_addr2nodeitem_rightnbr(
    HitMapAddr2NodeItem *rightnbr_b,
    StackHitMapAddr2NodeItem **stackHitMapAddr2NodeItemTop,
    u32 *stackHitMapAddr2NodeItemCount,
    int curnode_lastupdate_ts,
    u32 min_bufsz);

static RangeArray *
build_range_array(HitMapAddr2NodeItem *addrnodes);

static void
delOldNewRangeArray(RangeArray **old, RangeArray **new);

static void
display_avalanche(
    StackHitMapAddr2NodeItem *stack_srcbuf_top,
    RangeArray *new_dst_ra,
    u32 *srcbuf_oldstart,
    u32 *srcbuf_oldend,
    ContHitCntRange **lst_olddst_avalnch,
    u32 min_bufsz);

static ContHitCntRange *
compt_avalnch_srcbuf_range(
    StackHitMapAddr2NodeItem *stack_srcbuf_top,
    u32 min_bufsz);

static void
compt_avalnch_srcbuf(
    StackHitMapAddr2NodeItem *stack_srcbuf_top,
    u32 min_bufsz,
    u32 *bufstart,
    u32 *bufend);

static ContHitCntRange *
compt_avalnch_dstbuf_range(
    RangeArray *dstbuf_ra,
    u32 min_bufsz);

/* Public functions */
void
detectHitMapAvalanche(
    HitMapContext *hitMap,
    TPMContext *tpm,
    BufType buf_type,
    u8 *buf_hitcnt_ary,
    u32 avalanche_threashold)
{
  u32 numOfBuf, srcBufIdx, dstBufIdx;
  TPMBufHashTable *srcTPMBuf;
  TPMBufHashTable *dstTPMBuf;
  HitMapAvalSearchCtxt *hitMapAvalSrchCtxt;

  double totalElapse = 0;
  u32 searchCnt = 0;

  if(buf_hitcnt_ary != NULL) {
    if(buf_type == TPMBuf)
      detect_HM_avalanche_tpmbuf(hitMap, tpm, buf_type, buf_hitcnt_ary, avalanche_threashold);
    else
      detect_HM_avalanche_hitmapbuf(hitMap, tpm, buf_type, buf_hitcnt_ary, avalanche_threashold);
  }
  else {
    /* uses to detect avalanche for specific <src,dst> pairs. Hardcodes src and/or dst buffers. */
    // detect_HM_avalnch_HMBuf_noHitCntAry(hitMap, tpm, buf_type); 
    detect_HM_avalnch_HMBuf_bruteforce(hitMap, tpm, buf_type);

    /*
    numOfBuf = hitMap->numOfBuf;
    for(srcBufIdx = 0; srcBufIdx < numOfBuf-1; srcBufIdx++) {
      for(dstBufIdx = srcBufIdx + 1; dstBufIdx < numOfBuf; dstBufIdx++) {
        srcTPMBuf = getTPMBuf(hitMap->tpmBuf, srcBufIdx);
        dstTPMBuf = getTPMBuf(hitMap->tpmBuf, dstBufIdx);

        hitMapAvalSrchCtxt = initHitMapAvalSearchCtxt(srcBufIdx, srcTPMBuf, dstBufIdx, dstTPMBuf, tpm->minBufferSz);
        detectHitMapAvalInOut(hitMapAvalSrchCtxt, hitMap, &totalElapse);
        freeHitMapAvalSearchCtxt(hitMapAvalSrchCtxt);

        searchCnt++;
      }
      break;  // Detects first buffer to all other buffers
    }

    if(searchCnt > 0)
      printf("---------------\navg build 2-level hash table time:%.1f microseconds\n", totalElapse/searchCnt);
    */
  }
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
    TPMBufHashTable *dstTPMBuf,
    u32 minBufSz)
{
  HitMapAvalSearchCtxt *h = calloc(1, sizeof(HitMapAvalSearchCtxt) );
  assert(h != NULL);

  h->minBufferSz = minBufSz;
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

static HitMapAvalSearchCtxt *
init_HM_avalnch_ctxt_HMBuf(
    u32 srcbuf_idx,
    HitMapBufHash *srcHitMapBuf,
    u32 dstbuf_idx,
    HitMapBufHash *dstHitMapbuf,
    u32 min_bufsz)
{
  HitMapAvalSearchCtxt *h = calloc(sizeof(HitMapAvalSearchCtxt), 1);
  assert(h != NULL);

  h->minBufferSz = min_bufsz;

  h->srcHitMapBuf = srcHitMapBuf;
  h->dstHitMapBuf = dstHitMapbuf;
  h->srcBufID = srcbuf_idx;
  h->dstBufID = dstbuf_idx;

  h->srcAddrStart = srcHitMapBuf->baddr;
  h->srcAddrEnd = srcHitMapBuf->eaddr;
  h->dstAddrStart = dstHitMapbuf->baddr;
  h->dstAddrEnd = dstHitMapbuf->eaddr;

  h->srcMinSeqN = srcHitMapBuf->minseq;
  h->srcMaxSeqN = srcHitMapBuf->maxseq;
  h->dstMinSeqN = dstHitMapbuf->minseq;
  h->dstMaxSeqN = dstHitMapbuf->maxseq;

  h->numOfSrcAddr = srcHitMapBuf->numOfAddr;
  h->numOfDstAddr = dstHitMapbuf->numOfAddr;

  h->hitMapAddr2NodeAry = calloc(sizeof(HitMapAddr2NodeItem), srcHitMapBuf->numOfAddr);
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
detect_HM_avalanche_tpmbuf(
    HitMapContext *hitMap,
    TPMContext *tpm,
    BufType buf_type,
    u8 *buf_hitcnt_ary,
    u32 avalanche_threashold)
{
  u32 numOfBuf;
  u32 srcBufIdx, dstBufIdx;
  HitMapAvalSearchCtxt *hitMapAvalSrchCtxt;

  double totalElapse = 0;
  u32 searchCnt = 0;

  numOfBuf = hitMap->tpmBufCtxt->numOfBuf;
  TPMBufHashTable *srcTPMBuf;
  TPMBufHashTable *dstTPMBuf;

  for(u32 r = 0; r < numOfBuf; r++) {
    for (u32 c = 0; c < numOfBuf; c++) {
      u8 val = buf_hitcnt_ary[r*numOfBuf + c];
      if(val >= avalanche_threashold) {
        srcBufIdx = r;
        dstBufIdx = c;
        srcTPMBuf = getTPMBuf(hitMap->tpmBufCtxt->tpmBufHash, srcBufIdx);
        dstTPMBuf = getTPMBuf(hitMap->tpmBufCtxt->tpmBufHash, dstBufIdx);

        hitMapAvalSrchCtxt = initHitMapAvalSearchCtxt(srcBufIdx, srcTPMBuf, dstBufIdx, dstTPMBuf, tpm->minBufferSz);
        detectHitMapAvalInOut(hitMapAvalSrchCtxt, hitMap, &totalElapse);
        freeHitMapAvalSearchCtxt(hitMapAvalSrchCtxt);

        searchCnt++;
      }
    }
  }

  if(searchCnt > 0)
    printf("---------------\navg build 2-level hash table time:%.1f microseconds\n", totalElapse/searchCnt);
}

static void
detect_HM_avalanche_hitmapbuf(
    HitMapContext *hitMap,
    TPMContext *tpm,
    BufType buf_type,
    u8 *buf_hitcnt_ary,
    u32 avalanche_threashold)
{
  u32 numOfBuf;
  u32 srcBufIdx, dstBufIdx;
  HitMapAvalSearchCtxt *hitMapAvalSrchCtxt;

  double totalElapse = 0;
  u32 searchCnt = 0;

  numOfBuf = hitMap->hitMapBufCtxt->numOfBuf;
  HitMapBufHash *src_HM_buf;
  HitMapBufHash *dst_HM_buf;

  for(u32 r = 0; r < numOfBuf; r++) {
    for (u32 c = 0; c < numOfBuf; c++) {
      u8 val = buf_hitcnt_ary[r*numOfBuf + c];
      if(val >= avalanche_threashold) {
        srcBufIdx = r;
        dstBufIdx = c;
        src_HM_buf = get_hitmap_buf(hitMap->hitMapBufCtxt->hitMapBufHash, srcBufIdx);
        dst_HM_buf = get_hitmap_buf(hitMap->hitMapBufCtxt->hitMapBufHash, dstBufIdx);

        assert(srcBufIdx+1 == src_HM_buf->headNode->bufId);
        assert(dstBufIdx+1 == dst_HM_buf->headNode->bufId);

        hitMapAvalSrchCtxt = init_HM_avalnch_ctxt_HMBuf(srcBufIdx, src_HM_buf, dstBufIdx, dst_HM_buf, tpm->minBufferSz);
        detect_HM_inoutbuf_HMBuf(hitMapAvalSrchCtxt, hitMap, &totalElapse);
        freeHitMapAvalSearchCtxt(hitMapAvalSrchCtxt);

        searchCnt++;
      }
    }
  }

  if(searchCnt > 0)
    printf("---------------\navg avalanche detection time:%.1f microseconds\n", totalElapse/searchCnt);
}

static void
detect_HM_avalnch_HMBuf_noHitCntAry(
    HitMapContext *hitMap,
    TPMContext *tpm,
    BufType bufType)
// Temporary avalanche detect function. Based on the ground truth of large size
// log, the 2D hit count array misses legitimate buffer pairs. So uses this function
// to detect avalanche without 2D hit count array.
// We know the dst buffer, so we brute-force each buffer as potential src buffer.
{
  u32 srcIdx, dstIdx1, dstIdx2;
  HitMapAvalSearchCtxt *hitMapAvalSrchCtxt;

  double totalElapse = 0;
  u32 searchCnt = 0;

  HitMapBufHash *src;
  HitMapBufHash *dst;

  // search 1st dst buffer
  dstIdx1 = 6-1;
  dst = get_hitmap_buf(hitMap->hitMapBufCtxt->hitMapBufHash, dstIdx1);
  for(src = hitMap->hitMapBufCtxt->hitMapBufHash; src != NULL; src = src->hh_hmBufHash.next) {
    u32 srcID = src->headNode->bufId;
    u32 dstID = dst->headNode->bufId;
    srcIdx = srcID - 1;
    assert(dstID == 6);
    if(srcID != dstID && 
       src->minseq < dst->maxseq && 
       (src->eaddr - src->baddr) >= 16) { /* 1. no need to search by it
    self. 2. src buf seqN range must be smaller or overlap with dst seqN range. */
      hitMapAvalSrchCtxt = init_HM_avalnch_ctxt_HMBuf(srcIdx, src, dstIdx1, dst, tpm->minBufferSz);
      detect_HM_inoutbuf_HMBuf(hitMapAvalSrchCtxt, hitMap, &totalElapse);
      freeHitMapAvalSearchCtxt(hitMapAvalSrchCtxt);
      printf("Finish searching %uth buf pair.\n", searchCnt);
      searchCnt++;
    }
  }

  // searches 2nd dst buffer
  dstIdx1 = 7-1;
  dst = get_hitmap_buf(hitMap->hitMapBufCtxt->hitMapBufHash, dstIdx1);
  for(src = hitMap->hitMapBufCtxt->hitMapBufHash; src != NULL; src = src->hh_hmBufHash.next) {
    u32 srcID = src->headNode->bufId;
    u32 dstID = dst->headNode->bufId;
    srcIdx = srcID - 1;
    assert(dstID == 7);
    if(srcID != dstID &&
       src->minseq < dst->maxseq &&
       (src->eaddr - src->baddr) >= 16) { /* 1. no need to search by it
    self. 2. src buf seqN range must be smaller or overlap with dst seqN range. */
      hitMapAvalSrchCtxt = init_HM_avalnch_ctxt_HMBuf(srcIdx, src, dstIdx1, dst, tpm->minBufferSz);
      detect_HM_inoutbuf_HMBuf(hitMapAvalSrchCtxt, hitMap, &totalElapse);
      freeHitMapAvalSearchCtxt(hitMapAvalSrchCtxt);
      printf("Finish searching %uth buf pair.\n", searchCnt);
      searchCnt++;
    }
  }

  if(searchCnt > 0)
    printf("---------------\ntotal search pairs:%u - avg avalanche detection time:%.1f microseconds\n", 
      searchCnt, totalElapse/searchCnt);
}

/* Brute fource avalanche detection: begin with 1st HitMap buffer, detects if it
 * has avalanche to all following buffers; then with the 2nd HitMap, etc.
 * Only works for small size log, otherwise, it takes too long to finish.
 */
static void
detect_HM_avalnch_HMBuf_bruteforce(
    HitMapContext *hitMap,
    TPMContext *tpm,
    BufType bufType)
{
  HitMapAvalSearchCtxt *hitMapAvalSrchCtxt;

  double totalElapse = 0;
  u32 searchCnt = 0;

  HitMapBufHash *src;
  HitMapBufHash *dst;

  if(bufType == HitMapBuf) {
    for(src = hitMap->hitMapBufCtxt->hitMapBufHash;
        src->hh_hmBufHash.next != NULL; src = src->hh_hmBufHash.next) {
      for(dst = src->hh_hmBufHash.next; dst != NULL; dst = dst->hh_hmBufHash.next) {
        u32 srcIdx = src->headNode->bufId - 1;
        u32 dstIdx = dst->headNode->bufId - 1;

        // dbg
        if( (src->baddr == 0x8142220 && dst->baddr == 0x813e9c0) ||
            (src->baddr == 0xde911000 && dst->baddr == 0x804c170) ||
            (src->baddr == 0x813e1e0 && dst->baddr == 0x813e9c0) ||
            (src->baddr == 0x804a080 && dst->baddr == 0x804a860) ||
            (src->baddr == 0x814b180 && dst->baddr == 0x814b960) ||
            (src->baddr == 0x804b0a0 && dst->baddr == 0x804b880) ) {
          printf("Detect HitMap Avalanche for speical pair\n");
          hitMapAvalSrchCtxt = init_HM_avalnch_ctxt_HMBuf(srcIdx, src, dstIdx, dst, tpm->minBufferSz);
          detect_HM_inoutbuf_HMBuf(hitMapAvalSrchCtxt, hitMap, &totalElapse);
          freeHitMapAvalSearchCtxt(hitMapAvalSrchCtxt);
          searchCnt++;
          goto OutLoop;
        }

        // Comment for dbg
//        hitMapAvalSrchCtxt = init_HM_avalnch_ctxt_HMBuf(srcIdx, src, dstIdx, dst, tpm->minBufferSz);
//        detect_HM_inoutbuf_HMBuf(hitMapAvalSrchCtxt, hitMap, &totalElapse);
//        freeHitMapAvalSearchCtxt(hitMapAvalSrchCtxt);
//        searchCnt++;
      }
    }

OutLoop:
    if(searchCnt > 0)
      printf("---------------\ntotal search pairs:%u - avg avalanche detection time:%.1f microseconds\n",
             searchCnt, totalElapse/searchCnt);
  } else {
    printf("detect_HM_avalnch_HMBuf_bruteforce: buf type is not HitMapBuf, skip.\n");
  }
}

static void
detectHitMapAvalInOut(
    HitMapAvalSearchCtxt *hitMapAvalSrchCtxt,
    HitMapContext *hitMap,
    double *totalElapse)
{
  u32 srcBufNodeTotal, dstBufNodeTotal;
  u32 numOfTrans, srcAddrIdx, srcBufID;
  u32 totalTraverse = 0;

  srcBufNodeTotal = getTPMBufNodeTotal(hitMapAvalSrchCtxt->srcTPMBuf);
  dstBufNodeTotal = getTPMBufNodeTotal(hitMapAvalSrchCtxt->dstTPMBuf);

  printf("---------------------------------------- ----------------------------------------\n");
  print1TPMBufHashTable("src buf: ", hitMapAvalSrchCtxt->srcTPMBuf);
  print1TPMBufHashTable("dst buf: ", hitMapAvalSrchCtxt->dstTPMBuf);
  printf("total src buf node:%u - total dst buf node:%u\n", srcBufNodeTotal, dstBufNodeTotal);

  printTimeMicroStart();
  searchHitMapPropgtInOut(hitMapAvalSrchCtxt, hitMap);
  create_HMBuf_aggrgt_hitCntAry(hitMap->bufArray[hitMapAvalSrchCtxt->srcBufID]->addrArray[0], srcbuf,
                                hitMapAvalSrchCtxt->srcAddrStart, hitMapAvalSrchCtxt->srcAddrEnd, hitMapAvalSrchCtxt);
  create_HMBuf_aggrgt_hitCntAry(hitMap->bufArray[hitMapAvalSrchCtxt->dstBufID]->addrArray[0], dstbuf,
                                hitMapAvalSrchCtxt->dstAddrStart, hitMapAvalSrchCtxt->dstAddrEnd, hitMapAvalSrchCtxt);

  // print_HMBuf_aggrgt_hitCntAry(srcbuf, hitMapAvalSrchCtxt->srcAddrOutHitCnt,
  //                              hitMapAvalSrchCtxt->srcAddrStart, hitMapAvalSrchCtxt->srcAddrEnd);
  // print_HMBuf_aggrgt_hitCntAry(dstbuf, hitMapAvalSrchCtxt->dstAddrINHitCnt,
  //                              hitMapAvalSrchCtxt->dstAddrStart, hitMapAvalSrchCtxt->dstAddrEnd);

  search_inoutbuf_avalnch(hitMapAvalSrchCtxt);
  // totalTraverse = srchHitMapPropgtInOutReverse(hitMapAvalSrchCtxt, hitMap);
  printTimeMicroEnd(totalElapse);

  // numOfTrans = 0;
  // srcBufID = hitMapAvalSrchCtxt->srcBufID;
  // for(srcAddrIdx = 0; srcAddrIdx < hitMap->bufArray[srcBufID]->numOfAddr; srcAddrIdx++) {
  //   numOfTrans += getHitMap2LAddr2NodeItemTotal(hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx]);
  // }
  // printf("--------------------\nnumber of transition of 2-level hash table:%u\n", numOfTrans);
  // printf("total number of traverse steps:%u\n", totalTraverse);
}

static void
detect_HM_inoutbuf_HMBuf(
    HitMapAvalSearchCtxt *hitMapAvalSrchCtxt,
    HitMapContext *hitMap,
    double *totalElapse)
{
  u32 numOfTrans, srcAddrIdx, srcBufID;
  u32 totalTraverse = 0;

  printf("---------------------------------------- ----------------------------------------\n");
  printOneHitMapBufHash(hitMapAvalSrchCtxt->srcHitMapBuf);
  printOneHitMapBufHash(hitMapAvalSrchCtxt->dstHitMapBuf);
  // printf("total src buf node:%u - total dst buf node:%u\n", srcBufNodeTotal, dstBufNodeTotal);

  // printTimeMicroStart();
  if(search_HM_inoutbuf_propgt(hitMapAvalSrchCtxt, hitMap) >= 0) {
    // Temp disable for testing building 2Level hash
    printTime("Finish building 2Level hash table");

    create_HMBuf_aggrgt_hitCntAry(hitMapAvalSrchCtxt->srcHitMapBuf->headNode, srcbuf,
        hitMapAvalSrchCtxt->srcAddrStart, hitMapAvalSrchCtxt->srcAddrEnd, hitMapAvalSrchCtxt);
    create_HMBuf_aggrgt_hitCntAry(hitMapAvalSrchCtxt->dstHitMapBuf->headNode, dstbuf,
        hitMapAvalSrchCtxt->dstAddrStart, hitMapAvalSrchCtxt->dstAddrEnd, hitMapAvalSrchCtxt);
    // print_HMBuf_aggrgt_hitCntAry(srcbuf, hitMapAvalSrchCtxt->srcAddrOutHitCnt,
    //                              hitMapAvalSrchCtxt->srcAddrStart, hitMapAvalSrchCtxt->srcAddrEnd);
    // print_HMBuf_aggrgt_hitCntAry(dstbuf, hitMapAvalSrchCtxt->dstAddrINHitCnt,
    //                              hitMapAvalSrchCtxt->dstAddrStart, hitMapAvalSrchCtxt->dstAddrEnd);
    printTime("Finish creating aggregate hit count array");
    search_inoutbuf_avalnch(hitMapAvalSrchCtxt);
    // totalTraverse = srchHitMapPropgtInOutReverse(hitMapAvalSrchCtxt, hitMap);

  }
  // printTimeMicroEnd(totalElapse);
}

static void
searchHitMapPropgtInOut(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt, HitMapContext *hitMap)
// Searches propagations of source buffer (all version of each node) to dst buf,
// results store in dstMemNodesHT
// 1. Search propagation
// For each version node of each addr of input buffer as source
// 1.1 searches the source node propagations to destination buffers (within addr/seqNo range)
{
  u32 srcAddrIdx;
  u32 srcBufID, dstBufID;

  srcBufID = hitMapAvalSrchCtxt->srcBufID;
  dstBufID = hitMapAvalSrchCtxt->dstBufID;
  if(hitMapAvalSrchCtxt->srcBufID >= hitMap->numOfBuf) {
    fprintf(stderr, "searchHitMapPropgtInOut error: invalid src buf ID\n");
    return;
  }

  // init all version nodes's IN/OUT hit counts of src and dst buffer to 0
  // printf("----- src buf:\n");
  // print_HM_all_buf_node(hitMap->bufArray[srcBufID]->addrArray[0]);
  // printf("----- dst buf:\n");
  // print_HM_all_buf_node(hitMap->bufArray[dstBufID]->addrArray[0]);
  init_HM_buf_hitcnt(hitMap->bufArray[srcBufID]->addrArray[0]);
  init_HM_buf_hitcnt(hitMap->bufArray[dstBufID]->addrArray[0]);
  // printf("----- src buf after init:\n");
  // print_HM_all_buf_node(hitMap->bufArray[srcBufID]->addrArray[0]);
  // printf("----- dst buf after init:\n");
  // print_HM_all_buf_node(hitMap->bufArray[dstBufID]->addrArray[0]);

  for(srcAddrIdx = 0; srcAddrIdx < hitMap->bufArray[srcBufID]->numOfAddr; srcAddrIdx++) {
    HitMapNode *head = hitMap->bufArray[srcBufID]->addrArray[srcAddrIdx];
    if(head == NULL)
      continue;   // TODO: Debug: due to HitMap has less buffers than TPM.

    u32 ver = head->version;

    do {
      // printHitMapNodeLit(head);
      HitMapAddr2NodeItem *hmAddr2NodeItem = createHitMapAddr2NodeItem(head->addr, head, NULL, NULL);
      HASH_ADD(hh_hmAddr2NodeItem, hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx], node, 4, hmAddr2NodeItem);

      hitMapNodePropagate(head, hitMap, hmAddr2NodeItem, hitMapAvalSrchCtxt->dstAddrStart, hitMapAvalSrchCtxt->dstAddrEnd,
          hitMapAvalSrchCtxt->dstMinSeqN, hitMapAvalSrchCtxt->dstMaxSeqN);
      // printHitMapAddr2NodeItemSubhash(hmAddr2NodeItem);
      head = head->nextVersion;
    } while(ver != head->version);

    HASH_SRT(hh_hmAddr2NodeItem, hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx], cmpHitMapAddr2NodeItem);
    // printHitMap2LAddr2NodeItem(hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx]);
    // assert(head->leftNBR == NULL);
  }

  // printf("----- src buf after building 2Level:\n");
  // print_HM_all_buf_node(hitMap->bufArray[srcBufID]->addrArray[0]);
  // printf("----- dst buf after building 2Level:\n");
  // print_HM_all_buf_node(hitMap->bufArray[dstBufID]->addrArray[0]);
}

static int
search_HM_inoutbuf_propgt(
    HitMapAvalSearchCtxt *avalnch_HM_ctxt,
    HitMapContext *hitMap)
{
  HitMapNode *srcbuf_head;
  u32 srcbuf_baddr, srcbuf_eaddr;

  /* dbg */
  u32 printFlag = 0;
  // if(avalnch_HM_ctxt->srcBufID == 0 && avalnch_HM_ctxt->dstBufID == 3)
  //   printFlag = 1;

  if(avalnch_HM_ctxt != NULL && hitMap != NULL) {
    init_HM_buf_hitcnt(avalnch_HM_ctxt->srcHitMapBuf->headNode);
    init_HM_buf_hitcnt(avalnch_HM_ctxt->dstHitMapBuf->headNode);

    srcbuf_baddr = avalnch_HM_ctxt->srcHitMapBuf->baddr;
    srcbuf_eaddr = avalnch_HM_ctxt->srcHitMapBuf->eaddr;

    srcbuf_head = avalnch_HM_ctxt->srcHitMapBuf->headNode;
    assert(srcbuf_head->addr == srcbuf_baddr);

    u32 srcAddrIdx = 0;
    while(srcbuf_head != NULL) {
      u32 ver = srcbuf_head->version;

      do {
        HitMapAddr2NodeItem *hmAddr2NodeItem = createHitMapAddr2NodeItem(srcbuf_head->addr, srcbuf_head, NULL, NULL);
        HASH_ADD(hh_hmAddr2NodeItem, avalnch_HM_ctxt->hitMapAddr2NodeAry[srcAddrIdx], node, 4, hmAddr2NodeItem);

        hitMapNodePropagate(srcbuf_head, hitMap, hmAddr2NodeItem,
                            avalnch_HM_ctxt->dstAddrStart, avalnch_HM_ctxt->dstAddrEnd,
                            avalnch_HM_ctxt->dstMinSeqN, avalnch_HM_ctxt->dstMaxSeqN);
        // printHitMapAddr2NodeItemSubhash(hmAddr2NodeItem);

        srcbuf_head = srcbuf_head->nextVersion;
      } while(ver != srcbuf_head->version);

      HASH_SRT(hh_hmAddr2NodeItem, avalnch_HM_ctxt->hitMapAddr2NodeAry[srcAddrIdx], cmpHitMapAddr2NodeItem);
      // printHitMap2LAddr2NodeItem(avalnch_HM_ctxt->hitMapAddr2NodeAry[srcAddrIdx]);
      // if(printFlag)
      //   printHitMap2LAddr2NodeItem(avalnch_HM_ctxt->hitMapAddr2NodeAry[srcAddrIdx]);

      // if(srcbuf_head->rightNBR == NULL)
      //   assert(srcbuf_head->addr + srcbuf_head->bytesz == srcbuf_eaddr);

      srcbuf_head = srcbuf_head->rightNBR;
      srcAddrIdx++;
    }
    return 0;
  }
  fprintf(stderr, "search_HM_inoutbuf_propgt: error\n");
  return -1;
}

static int
init_HM_buf_hitcnt(HitMapNode *bufhead)
{
  if(bufhead != NULL) {
    while(bufhead != NULL) {
      u32 ver = bufhead->version;

      do {
        bufhead->hitcntIn = 0;
        bufhead->hitcntOut = 0;

        bufhead = bufhead->nextVersion;
      } while(ver != bufhead->version);
      bufhead = bufhead->rightNBR;
    }
    return 0;
  }
  fprintf(stderr, "init_HM_buf_hitcnt: error\n");
  return -1;
}

static u32
srchHitMapPropgtInOutReverse(
    HitMapAvalSearchCtxt *hitMapAvalSrchCtxt,
    HitMapContext *hitMap)
// Instead of searching from src to dst, searching from dst to src via taintedBy
// Hit Transition. But result still store as <src dst> in 2Level hash
{
  u32 srcBufId, dstBufId;
  u32 srcAddrIdx, dstAddrIdx;
  u32 totalTraverse = 0;

  srcBufId = hitMapAvalSrchCtxt->srcBufID;
  dstBufId = hitMapAvalSrchCtxt->dstBufID;

  if(srcBufId >= hitMap->numOfBuf ||
      dstBufId >= hitMap->numOfBuf) {
    fprintf(stderr, "searchHitMapPropgtInOutReverse error: invalid src/dst buf ID\n");
    return 0;
  }

  // Adds all nodes of src buf in 1stLevel hash
  for(srcAddrIdx = 0; srcAddrIdx < hitMap->bufArray[srcBufId]->numOfAddr; srcAddrIdx++) {
    HitMapNode *head = hitMap->bufArray[srcBufId]->addrArray[srcAddrIdx];
    if(head == NULL)
      continue;   // TODO: Debug

    u32 ver = head->version;
    do {
      HitMapAddr2NodeItem *hmAddr2NodeItem = createHitMapAddr2NodeItem(head->addr, head, NULL, NULL);
      HASH_ADD(hh_hmAddr2NodeItem, hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx], node, 4, hmAddr2NodeItem);

      head = head->nextVersion;
    } while(ver != head->version);
  }

  // Search reverse taint propagation and build 2Level hash
  for(dstAddrIdx = 0; dstAddrIdx < hitMap->bufArray[dstBufId]->numOfAddr; dstAddrIdx++) {
    HitMapNode *head = hitMap->bufArray[dstBufId]->addrArray[dstAddrIdx];
    if(head == NULL)
      continue;
    u32 ver = head->version;
    u32 traverse = 0;
    do {
      traverse = hitMapNodePropagateReverse(head, hitMap, hitMapAvalSrchCtxt->hitMapAddr2NodeAry,
          hitMapAvalSrchCtxt->srcAddrStart, hitMapAvalSrchCtxt->srcAddrEnd,
          hitMapAvalSrchCtxt->srcMinSeqN, hitMapAvalSrchCtxt->srcMaxSeqN);
      totalTraverse += traverse;
      head = head->nextVersion;
    } while (ver != head->version);
  }

  for(srcAddrIdx = 0; srcAddrIdx < hitMap->bufArray[srcBufId]->numOfAddr; srcAddrIdx++) {
    HASH_SRT(hh_hmAddr2NodeItem, hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx], cmpHitMapAddr2NodeItem);

    HitMapAddr2NodeItem *hmAddr2NodeItem = hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx];
    for(; hmAddr2NodeItem != NULL; hmAddr2NodeItem = hmAddr2NodeItem->hh_hmAddr2NodeItem.next) {
      HASH_SRT(hh_hmAddr2NodeItem, hmAddr2NodeItem->subHash, cmpHitMapAddr2NodeItem);
    }
    // printHitMap2LAddr2NodeItem(hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx]);
  }
  return totalTraverse;
}

static void
create_HMBuf_aggrgt_hitCntAry(
    HitMapNode *bufhead,
    BufDirect bufdirct,
    u32 bufstart,
    u32 bufend,
    HitMapAvalSearchCtxt *avalnch_HM_ctxt)
{
  if(bufhead != NULL && avalnch_HM_ctxt != NULL) {
    u32 bufsz = bufend - bufstart;
    u8 *hitCntAry = calloc(sizeof(u8), bufsz);
    assert(hitCntAry != NULL);

    while(bufhead != NULL) {
      u32 ver = bufhead->version;
      do {

        assert(bufhead->addr >= bufstart &&
               (bufhead->addr + bufhead->bytesz) <= bufend);
        u32 bytestart = bufhead->addr - bufstart;
        for(u32 bytesz = 0; bytesz < bufhead->bytesz; bytesz++) {
          u32 byteidx = bytestart + bytesz;
          assert(byteidx < bufsz);

          if(bufdirct == srcbuf)
            hitCntAry[byteidx] += bufhead->hitcntOut;
          else
            hitCntAry[byteidx] += bufhead->hitcntIn;
        }
        bufhead = bufhead->nextVersion;
      } while(ver != bufhead->version);

      bufhead = bufhead->rightNBR;
    }

    if(bufdirct == srcbuf)
      avalnch_HM_ctxt->srcAddrOutHitCnt = hitCntAry;
    else
      avalnch_HM_ctxt->dstAddrINHitCnt = hitCntAry;
  }
}

static void
print_HMBuf_aggrgt_hitCntAry(
    BufDirect bufdirct,
    u8 *hitCntAry,
    u32 bufstart,
    u32 bufend)
{
  if(hitCntAry != NULL) {
    if(bufdirct == srcbuf)
      printf("----- srcbuf: bufstart:%x bufend:%x\n", bufstart, bufend);
    else
      printf("----- dstbuf: bufstart:%x bufend:%x\n", bufstart, bufend);

    u32 bufsz = bufend - bufstart;
    for(u32 byteidx = 0; byteidx < bufsz; byteidx++) {
      printf("byteidx:%u hitcnt:%u\n", byteidx, hitCntAry[byteidx]);
    }
  } else { printf("HitMap buffer hit count array:%p\n", hitCntAry); }
}

static void
search_inoutbuf_avalnch(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt)
{
  u32 srcbuf_addridx = 0;

  ContHitCntRange *lst_srcHitCntRange;
  ContHitCntRange *lst_dstHitCntRange;

  assert(hitMapAvalSrchCtxt->minBufferSz >= 8);

  if(hitMapAvalSrchCtxt->srcAddrOutHitCnt != NULL &&
     hitMapAvalSrchCtxt->dstAddrINHitCnt != NULL) {
    search_inoutbuf_avalnch_subrange(hitMapAvalSrchCtxt);
  }
  else {
    // for(; srcbuf_addridx < (hitMapAvalSrchCtxt->numOfSrcAddr-1); /* srcbuf_addridx++ */) {
    //   // No need to search last addr
    //   HitMapAddr2NodeItem *srcnode = hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcbuf_addridx];
    //   u32 block_sz = 1;      // block sz s.t. continuous src nodes propagate to same destinations (considered blocks)
    //   u32 max_block_sz = 1;  // max block sz found for all version nodes of same address

    //   for(; srcnode != NULL; srcnode = srcnode->hh_hmAddr2NodeItem.next) {
    //     if(has_enough_dstnode(srcnode, hitMapAvalSrchCtxt->minBufferSz) ) {
    //       printf("-------------------- --------------------\n");
    //       printf("detect avalanche: begin node: addr:%x - version:%u\n", srcnode->node->addr, srcnode->node->version);
    //       // printTime("");
    //       search_srcnode_avalanche(srcnode, srcbuf_addridx+1, &block_sz, hitMapAvalSrchCtxt);

    //       if(block_sz > max_block_sz)
    //         max_block_sz = block_sz;
    //     }
    //   }
    //   srcbuf_addridx += max_block_sz;
    // }
  }
}

static void
search_inoutbuf_avalnch_subrange(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt)
{

  ContHitCntRange *lst_srcHitCntRange;
  ContHitCntRange *lst_dstHitCntRange;
  ContHitCntRange *elt;

  lst_srcHitCntRange = analyze_hitcnt_range(hitMapAvalSrchCtxt->srcAddrOutHitCnt,
      hitMapAvalSrchCtxt->srcAddrStart, hitMapAvalSrchCtxt->srcAddrEnd, hitMapAvalSrchCtxt->minBufferSz);
  lst_dstHitCntRange = analyze_hitcnt_range(hitMapAvalSrchCtxt->dstAddrINHitCnt,
      hitMapAvalSrchCtxt->dstAddrStart, hitMapAvalSrchCtxt->dstAddrEnd, hitMapAvalSrchCtxt->minBufferSz);

  print_conthitcnt_range(lst_srcHitCntRange, "src range:");
  print_conthitcnt_range(lst_dstHitCntRange, "dst range:");

  if(!has_valid_range(lst_srcHitCntRange, lst_dstHitCntRange) )
    return;
  printTime("Finish analyzing aggregate hit count array");

  LL_FOREACH(lst_srcHitCntRange, elt) {
    u32 addridx_start, addridx_end;
    compt_addridx_range(&addridx_start, &addridx_end, elt->rstart, elt->rend,
                        hitMapAvalSrchCtxt->hitMapAddr2NodeAry, hitMapAvalSrchCtxt->numOfSrcAddr);
    // printf("addridx start:%u end:%u - nAddr:%u - range: start:%x end:%x\n",
    //        addridx_start, addridx_end, hitMapAvalSrchCtxt->numOfSrcAddr, elt->rstart, elt->rend);
    assert(addridx_end >= addridx_start && addridx_end < hitMapAvalSrchCtxt->numOfSrcAddr);

    u32 srcbuf_addridx = addridx_start;
    for(; srcbuf_addridx <= addridx_end; /* srcbuf_addridx++ */) {
      // No need to search last addr
      HitMapAddr2NodeItem *srcnode = hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcbuf_addridx];
      u32 block_sz = 1;      // block sz s.t. continuous src nodes propagate to same destinations (considered blocks)
      u32 max_block_sz = 1;  // max block sz found for all version nodes of same address

      for(; srcnode != NULL; srcnode = srcnode->hh_hmAddr2NodeItem.next) {
        if(has_enough_dstnode(srcnode, hitMapAvalSrchCtxt->minBufferSz) ) {
          printf("-------------------- --------------------\n");
          printf("detect avalanche: begin node: addr:%x - version:%u\n",
                 srcnode->node->addr, srcnode->node->version);
          search_srcnode_avalanche(srcnode, srcbuf_addridx+1, &block_sz, hitMapAvalSrchCtxt);

          if(block_sz > max_block_sz)
            max_block_sz = block_sz;
        }
      }
      srcbuf_addridx += max_block_sz;
    }
  }
  printTime("Finish detect avalanche");
}


static ContHitCntRange *
analyze_hitcnt_range(
    u8 *hitCntAry,
    u32 bufstart,
    u32 bufend,
    u32 min_bufsz)
// Returns:
//  list of sub range of buffer that aggregate hitcnt >= min buf sz
{
  ContHitCntRange *lst_head = NULL, *r = NULL;
  if(hitCntAry != NULL) {
    // print_HMBuf_aggrgt_hitCntAry(srcbuf, hitCntAry, bufstart, bufend);

    u32 bufsz = bufend - bufstart;
    for(u32 byteidx = 0; byteidx < bufsz; byteidx++) {
      if(hitCntAry[byteidx] >= min_bufsz) {  // has valid hit counts
        if(r == NULL) {
          r = calloc(sizeof(ContHitCntRange), 1);
          assert(r != NULL);
          r->rstart = bufstart + byteidx;
          r->rend = r->rstart;
        }
        else { r->rend = bufstart + byteidx + 1; }
      }
      else {    // not valid hit count
        if(r != NULL) { // has alreay a range
          if( (r->rend - r->rstart) >= min_bufsz) {
            // printf("range: start:%x - end:%x\n", r->rstart, r->rend);
            LL_APPEND(lst_head, r); /* there are at least >= min_bufsz continuous
            address range, each byte's hit coutn >= min_bufsz */
            r = NULL;
          }
          else { free(r); r = NULL; }
        }
      }
    }

    if(r != NULL && (r->rend - r->rstart) >= min_bufsz) {
      // printf("range: start:%x - end:%x\n", r->rstart, r->rend);
      LL_APPEND(lst_head, r);
    }
  }
  return lst_head;
}

/* Computes addr idx range given address range. */
static void
compt_addridx_range(
    u32 *addridx_start,
    u32 *addridx_end,
    u32 rangestart,
    u32 rangeend,
    HitMapAddr2NodeItem **hitMapAddr2NodeAry,
    u32 numOfAddr)
{
  u32 addridx = 0;
  *addridx_start = 0;
  *addridx_end = 0;
  int flagset = 0;

  if(hitMapAddr2NodeAry != NULL) {
    // printf("range: start:%x end:%x\n", rangestart, rangeend);
    for(; addridx < numOfAddr; addridx++) {
      HitMapAddr2NodeItem *itm = hitMapAddr2NodeAry[addridx];
      // printf("addr idx:%u - item address:%x\n", addridx, itm->addr);
      if(itm->addr >= rangestart && flagset == 0) {
        *addridx_start = addridx;
        flagset = 1;
      }

      if(itm->node->addr + itm->node->bytesz >= rangeend) {
        *addridx_end = addridx;
        return;
      }
    }
    // addr idx doesn't exceed range end
    *addridx_end = addridx-1;
  }
}


static bool
isSameContRange(ContHitCntRange *l, ContHitCntRange *r)
{
  int l_cnt = 0, r_cnt = 0;
  ContHitCntRange *tmp;
  if(l != NULL && r != NULL) {
    LL_COUNT(l, tmp, l_cnt);
    LL_COUNT(r, tmp, r_cnt);
    if(l_cnt == r_cnt) {
      while(l != NULL && r != NULL) {
        if(l->rstart != r->rstart || l->rend != r->rend) {
          // printf("l: start:%x end:%x -r: start:%x end:%x\n",
          //        l->rstart, l->rend, r->rstart, r->rend);
          return false;
        }
        l = l->next;
        r = r->next;
      }
      return true;
    }
    else { return false; }
  }
  return false;
}

static void
delContRange(ContHitCntRange **lst)
{
  ContHitCntRange *elt, *tmp;
  if(lst != NULL && *lst != NULL) {
    LL_FOREACH_SAFE(*lst, elt, tmp) {
      LL_DELETE(*lst, elt);
      free(elt);
    }
    *lst = NULL;
  }
}

static void
print_conthitcnt_range(ContHitCntRange *lst, char *s)
{
  if(lst != NULL) {
    ContHitCntRange *temp;
    printf("%s\n", s);
    LL_FOREACH(lst, temp) {
      printf("start:%x end:%x sz:%u\n",
             temp->rstart, temp->rend, temp->rend - temp->rstart);
    }
  }
  // else { fprintf(stderr, "lst:%p\n", lst); }
}

static bool
has_valid_range(ContHitCntRange *lst_src, ContHitCntRange *lst_dst)
{
  ContHitCntRange *tmp;
  int srccnt = 0, dstcnt = 0;
  LL_COUNT(lst_src, tmp, srccnt);
  LL_COUNT(lst_dst, tmp, dstcnt);
  if(srccnt > 0 && dstcnt > 0)
    return true;
  else{
    printf("no valid ranges: src range cnt:%d dst range cnt:%d\n", srccnt, dstcnt);
    return false;
  }
}

static bool
has_enough_dstnode(
    HitMapAddr2NodeItem *srcnode,
    u32 min_bufsz)
{
  if(srcnode != NULL) {
    // HitMapAddr2NodeItem *propgt_to_dstnode = srcnode->subHash;
    // u32 num_of_dstnode = HASH_CNT(hh_hmAddr2NodeItem, propgt_to_dstnode);
    // if(num_of_dstnode > 1)
    //   return true;
    if(srcnode->node->hitcntOut >= min_bufsz)
      return true;
  }
  return false;
}

static void
search_srcnode_avalanche(
    HitMapAddr2NodeItem *srcnode,
    u32 srcbuf_addridx,
    u32 *block_sz_detect,
    HitMapAvalSearchCtxt *hitMapAvalSrchCtxt)
{
  HitMapAddr2NodeItem *old_srcnode, *new_srcnode;
  RangeArray *old_ra = NULL, *new_ra = NULL;
  RangeArray *oldintersect_ra = NULL, *newintersect_ra = NULL;

  StackHitMapAddr2NodeItem *stack_traverse_top = NULL;  // maintains traverse nodes during search
  u32 stack_traverse_cnt = 0;

  StackHitMapAddr2NodeItem *stack_srcnode_top = NULL;   // maintains src nodes have avalanche
  u32 stack_srcnode_cnt = 0;

  bool has_print_rslt = false;

  // saves the old avalanche src and dst buffer ranges
  u32 srcbuf_oldstart, srcbuf_oldend;
  ContHitCntRange *lst_oldsrc_avalnch = NULL;
  ContHitCntRange *lst_olddst_avalnch = NULL;

  if(srcnode == NULL || hitMapAvalSrchCtxt == NULL) {
    return;
  }

  // printHitMapAddr2NodeItemSubhash(srcnode);
  hitMapAddr2NodeItemPush(srcnode, &stack_srcnode_top, &stack_srcnode_cnt);
  old_srcnode = srcnode;
  old_ra = build_range_array(old_srcnode->subHash);
  // printRangeArray(old_ra, "");

  store_addr2nodeitem_rightnbr(hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcbuf_addridx],
      &stack_traverse_top, &stack_traverse_cnt, old_srcnode->node->lastUpdateTS, hitMapAvalSrchCtxt->minBufferSz);
  // hitMapAddr2NodeItemDisplay(stack_traverse_top);

  while(!isHitMapAddr2NodeItemStackEmpty(stack_traverse_top, stack_traverse_cnt) ) {
    new_srcnode = hitMapAddr2NodeItemPop(&stack_traverse_top, &stack_traverse_cnt);
    // TODO: add comment
    // newnode's addr <= oldnode's addr, indicates the stack is bouncing back
    if(new_srcnode->node->addr <= old_srcnode->node->addr) {
      if(!has_print_rslt){
        if(stack_srcnode_cnt >= 2 && stack_srcnode_cnt >= *block_sz_detect) {
          display_avalanche(stack_srcnode_top, oldintersect_ra,
                            &srcbuf_oldstart, &srcbuf_oldend, &lst_olddst_avalnch, hitMapAvalSrchCtxt->minBufferSz);
          *block_sz_detect = stack_srcnode_cnt;  // set to max num src node has avalanche
        }
      }

      // Bounces back source stack accordingly
      while(new_srcnode->node->addr <= stack_srcnode_top->hitMapAddr2NodeItem->node->addr) {
        hitMapAddr2NodeItemPop(&stack_srcnode_top, &stack_srcnode_cnt);
        srcbuf_addridx--;
      }

      delOldNewRangeArray(&old_ra, &new_ra);
      delOldNewRangeArray(&oldintersect_ra, &newintersect_ra);


      old_srcnode = stack_srcnode_top->hitMapAddr2NodeItem;
      old_ra = build_range_array(old_srcnode->subHash);
      // printRangeArray(old_ra, "");
    }

    // can't delete here, due to in the yes case below, newra is assigned to oldra,
    // if delete newra, then oldra will be deleted also. Now I set new to NULL if the case.
    new_ra = build_range_array(new_srcnode->subHash);
    newintersect_ra = get_common_rangearray(old_srcnode, old_ra, new_srcnode, new_ra);
    // printRangeArray(new_ra, "");
    // printRangeArray(newintersect_ra, "");

    if(newintersect_ra->rangeAryUsed > 0) { // valid intersection range array
      if(oldintersect_ra != NULL &&
         !is_rangearray_same(oldintersect_ra, newintersect_ra) ) {
        goto NEW_BLOCK;
      }

      old_srcnode = new_srcnode;
      hitMapAddr2NodeItemPush(old_srcnode, &stack_srcnode_top, &stack_srcnode_cnt);

      delRangeArray(&old_ra);
      delRangeArray(&oldintersect_ra);

      old_ra = new_ra;
      oldintersect_ra = newintersect_ra;
      // printRangeArray(oldintersect_ra, "");

      new_ra = NULL;    // since newra assigns to oldra, set it to NULL after
      newintersect_ra = NULL;

      has_print_rslt = false;   // only has new src aval node, indicating new avalanche
    }
    else {  // no valid intersection ranges
NEW_BLOCK:
      if(!has_print_rslt){
        if(stack_srcnode_cnt >= 2 && stack_srcnode_cnt >= *block_sz_detect) {
          display_avalanche(stack_srcnode_top, oldintersect_ra,
                            &srcbuf_oldstart, &srcbuf_oldend, &lst_olddst_avalnch, hitMapAvalSrchCtxt->minBufferSz);
          *block_sz_detect = stack_srcnode_cnt;  // set to max num src node has avalanche
        }
        has_print_rslt = true;
      }

      delRangeArray(&new_ra);  // only del new ones due to invalid
      delRangeArray(&newintersect_ra);
      continue;   // no valid intersect propagation, no need to go further (as dfs)
    }

    if(srcbuf_addridx < hitMapAvalSrchCtxt->numOfSrcAddr) {
      srcbuf_addridx++;
      if(srcbuf_addridx < hitMapAvalSrchCtxt->numOfSrcAddr) {
        store_addr2nodeitem_rightnbr(hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcbuf_addridx],
            &stack_traverse_top, &stack_traverse_cnt, old_srcnode->node->lastUpdateTS, hitMapAvalSrchCtxt->minBufferSz);
        // hitMapAddr2NodeItemDisplay(stack_traverse_top);
      }
    }
  }

  // handle last case
  if(!has_print_rslt){
    if(stack_srcnode_cnt >= 2 && stack_srcnode_cnt >= *block_sz_detect) {
      display_avalanche(stack_srcnode_top, oldintersect_ra,
          &srcbuf_oldstart, &srcbuf_oldend, &lst_olddst_avalnch, hitMapAvalSrchCtxt->minBufferSz);
      *block_sz_detect = stack_srcnode_cnt;  // set to max num src node has avalanche
    }
  }

  delOldNewRangeArray(&old_ra, &new_ra);
  delOldNewRangeArray(&oldintersect_ra, &newintersect_ra);
}

static void
store_addr2nodeitem_rightnbr(
    HitMapAddr2NodeItem *rightnbr_b,
    StackHitMapAddr2NodeItem **stackHitMapAddr2NodeItemTop,
    u32 *stackHitMapAddr2NodeItemCount,
    int curnode_lastupdate_ts,
    u32 min_bufsz)
// Enforces the increasing last update ts policy.
{
  if(rightnbr_b != NULL) {
    for(; rightnbr_b != NULL; rightnbr_b = rightnbr_b->hh_hmAddr2NodeItem.next) {
      if(has_enough_dstnode(rightnbr_b, min_bufsz) ) { // TODO: uses minBufSz later
        if(curnode_lastupdate_ts < 0 && rightnbr_b->node->lastUpdateTS < 0) {
          hitMapAddr2NodeItemPush(rightnbr_b, stackHitMapAddr2NodeItemTop, stackHitMapAddr2NodeItemCount);
          // if both are negative, smaller is later
          // !!! Disable it, TPM avalanche search as standard
          // if(rightnbr_b->node->lastUpdateTS < curnode_lastupdate_ts)
          //   hitMapAddr2NodeItemPush(rightnbr_b, stackHitMapAddr2NodeItemTop, stackHitMapAddr2NodeItemCount);
        }
        else {
          if(rightnbr_b->node->lastUpdateTS > curnode_lastupdate_ts)
             hitMapAddr2NodeItemPush(rightnbr_b, stackHitMapAddr2NodeItemTop, stackHitMapAddr2NodeItemCount);
        }
      }
    }
  }
}

static RangeArray *
build_range_array(HitMapAddr2NodeItem *addrnodes)
{
  RangeArray *ra;
  Range *r;
  u32 cur_rstart, cur_rend;

  if(addrnodes != NULL) {
    ra = initRangeArray();

    r = initRange();
    r->start = addrnodes->node->addr;
    r->end = addrnodes->node->addr + addrnodes->node->bytesz;

    cur_rstart = r->start;
    cur_rend = r->end;

    HitMapAddr2NodeItem *addrnode = addrnodes->hh_hmAddr2NodeItem.next; // starts from next node
    for(; addrnode != NULL; addrnode = addrnode->hh_hmAddr2NodeItem.next) {
      HitMapNode *node = addrnode->node;
      u32 cur_node_start = node->addr;

      if(cur_rend > cur_node_start) {
        // TODO: propagate to multiple version of same addr, handles latter
        // printf("buildRangeAry: TODO: multiple version of same addr:%x\n", cur_node_start);
      }
      else if(cur_rend == cur_node_start) {
        r->end += node->bytesz;
        cur_rend += node->bytesz;
      }
      else {    // new range
        add2Range(ra, r);

        r = initRange();
        r->start = node->addr;
        r->end = node->addr + node->bytesz;

        cur_rstart = r->start;
        cur_rend = r->end;
      }
    }
    add2Range(ra, r);   // adds last range
    return ra;
  }
  else { return NULL; }
}

static void
delOldNewRangeArray(RangeArray **old, RangeArray **new)
{
  if(*old == *new) { delRangeArray(old); }
  else {
    delRangeArray(old);
    delRangeArray(new);
  }
}

static void
display_avalanche(
    StackHitMapAddr2NodeItem *stack_srcbuf_top,
    RangeArray *new_dst_ra,
    u32 *srcbuf_oldstart,
    u32 *srcbuf_oldend,
    ContHitCntRange **lst_olddst_avalnch,
    u32 min_bufsz)
{
  ContHitCntRange *lst_newsrc = NULL, *lst_newdst = NULL;

  u32 srcbuf_newstart, srcbuf_newend;
  u32 new_dstbuf_start, new_dstbuf_end;

  compt_avalnch_srcbuf(stack_srcbuf_top, min_bufsz, &srcbuf_newstart, &srcbuf_newend);
  // printRangeArray(new_dst_ra, "");
  lst_newdst = compt_avalnch_dstbuf_range(new_dst_ra, min_bufsz);

  // avoid duplicate printing out avalanche results
  if(srcbuf_newend - srcbuf_newstart >= min_bufsz &&
     lst_newdst != NULL) {
    if(*srcbuf_oldstart == srcbuf_newstart &&
       *srcbuf_oldend == srcbuf_newend &&
       isSameContRange(*lst_olddst_avalnch, lst_newdst) ) {
    }
    else {
      printf("--------------------\navalanche found:\n");
      printf("src buf:\nstart:%x end:%x sz:%u\n",
          srcbuf_newstart, srcbuf_newend, srcbuf_newend-srcbuf_newstart);
      print_conthitcnt_range(lst_newdst, "dst buf:");
    }
  }
  delContRange(lst_olddst_avalnch);

  *srcbuf_oldstart = srcbuf_newstart;
  *srcbuf_oldend = srcbuf_newend;
  (*lst_olddst_avalnch) = lst_newdst;

  // printf("--------------------\n");
  // hitMapAddr2NodeItemDispRange(stack_srcbuf_top, "avalanche found:\nsrc buf:");
  // printf("dst buf:\n");
  // printRangeArray(new_dst_ra, "\t");
}

static ContHitCntRange *
compt_avalnch_srcbuf_range(
    StackHitMapAddr2NodeItem *stack_srcbuf_top,
    u32 min_bufsz)
{
  ContHitCntRange *lst = NULL;
  u32 bufstart = 0, bufend = 0;
  StackHitMapAddr2NodeItem *t;
  HitMapNode *n;

  if(stack_srcbuf_top != NULL) {
    t = stack_srcbuf_top;
    n = t->hitMapAddr2NodeItem->node;
    bufend = n->addr + n->bytesz;

    while(t != NULL && t->next != NULL) { t = t->next; }
    n = t->hitMapAddr2NodeItem->node; // gets last node
    bufstart = n->addr;

    if(bufend - bufstart >= min_bufsz) {
      ContHitCntRange *r = calloc(sizeof(ContHitCntRange), 1);
      r->rstart = bufstart;
      r->rend = bufend;
      LL_APPEND(lst, r);
    }
  }
  return lst;
}

static void
compt_avalnch_srcbuf(
    StackHitMapAddr2NodeItem *stack_srcbuf_top,
    u32 min_bufsz,
    u32 *bufstart,
    u32 *bufend)
{
  StackHitMapAddr2NodeItem *t;
  HitMapNode *n;

  if(stack_srcbuf_top != NULL) {
    t = stack_srcbuf_top;
    n = t->hitMapAddr2NodeItem->node;
    *bufend = n->addr + n->bytesz;

    while(t != NULL && t->next != NULL) { t = t->next; }
    n = t->hitMapAddr2NodeItem->node; // gets last node
    *bufstart = n->addr;
  }
}

static ContHitCntRange *
compt_avalnch_dstbuf_range(
    RangeArray *dstbuf_ra,
    u32 min_bufsz)
{
  ContHitCntRange *lst = NULL;
  if(dstbuf_ra != NULL) {
    for(u32 aryidx = 0; aryidx < dstbuf_ra->rangeAryUsed; aryidx++) {
      u32 bufstart = dstbuf_ra->rangeAry[aryidx]->start;
      u32 bufend = dstbuf_ra->rangeAry[aryidx]->end;
      if(bufend - bufstart >= min_bufsz) {
        ContHitCntRange *r = calloc(sizeof(ContHitCntRange), 1);
        r->rstart = bufstart;
        r->rend = bufend;
        LL_APPEND(lst, r);
      }
    }
  }
  return lst;
}

#include "bufhitcnt.h"
#include "hitmappropagate.h"
#include "misc.h"
#include <assert.h>
#include <stdbool.h>

static u8 *
initBufHitCntArray(u32 numOfBuf);

/* TPM Buffer */
static u8 *
buildTPMBufHitCntAry(HitMapContext *hitMap);

static void
buildBufHitCntAryOfBuf(
    u8 *bufHitCntAry,
    u32 numOfBuf,
    BufContext *hitMapBuf);

static void
buildBufHitCntAryOfAddr(
    u8 *bufHitCntAry,
    u32 numOfBuf,
    HitMapNode *addrHead);

/* HitMap Buffer */
static u8 *
buildHitMapBufHitCntAry(HitMapContext *hitMap);

static void
buildHitMapBufHitCntAryOfOneBuf(
    u8 *bufHitCntAry,
    u32 numOfBuf,
    HitMapBufHash *hitMapBuf);

static bool
hasContAddrRange(
    u32 *hitCntAry,
    u32 bufsz,
    u32 min_bufsz);

/* -------------------------------------------------------------------------- */
u8 *
buildBufHitCntArray(HitMapContext *hitMap, BufType bufType)
{
  u8 *bufHitCntAry;

  if(bufType == TPMBuf) {
    return buildTPMBufHitCntAry(hitMap);
  }
  else {
    return buildHitMapBufHitCntAry(hitMap);
  }
}

static u8 *
initBufHitCntArray(u32 numOfBuf)
{
  u8 *bufHitCntAry = NULL;

  bufHitCntAry = calloc(sizeof(u8), numOfBuf * numOfBuf);
  assert(bufHitCntAry != NULL);

  // printf("Init 2D array:\n");
  // printBufHitCntArray(bufHitCntAry, numOfBuf);

  // for(size_t r = 0; r < numOfBuf; r++) {
  //     for(size_t c = 0; c < numOfBuf; c++) {
  //         printf("bufHitCntAry:%p bufHitCntAry+offset:%p\n",
  //                 bufHitCntAry, bufHitCntAry+(r*numOfBuf + c) );
  //         bufHitCntAry[r*numOfBuf + c] = 0;
  //     }
  // }
  return bufHitCntAry;
}

static u8 *
buildTPMBufHitCntAry(HitMapContext *hitMap)
{
  TPMBufHashTable *tpm_buf;
  u8 *bufHitCntAry = NULL;
  u32 numOfBuf, bufIdx;

  if(hitMap == NULL) { return NULL; }

  printTime("Before build buffer hit count array");
  // printf("num of TPM buffers:%u\n", hitMap->numOfBuf);

  numOfBuf = hitMap->numOfBuf;
  bufHitCntAry = initBufHitCntArray(numOfBuf);
  // printf("buildBufHitCntArray: bufHitCntAry:%p\n", bufHitCntAry);

  bufIdx = 0;
  tpm_buf = hitMap->tpmBuf;
  for(; tpm_buf != NULL; tpm_buf = tpm_buf->hh_tpmBufHT.next) {
    if(tpm_buf->minseq >= 0) // minseq < 0 indicates it might contain source nodes
      break;

    buildBufHitCntAryOfBuf(bufHitCntAry, numOfBuf, hitMap->bufArray[bufIdx]);
    bufIdx++;
  }
  printTime("After build buffer hit count array");
  // printBufHitCntArray(bufHitCntArray, hitMap->numOfBuf);
  return bufHitCntAry;
}

void
delBufHitCntArray(u8 *bufHitCntArray)
{
  // printf("updateBufHitCntArray: bufHitCntAry:%p\n", bufHitCntArray);
  if(bufHitCntArray != NULL) {
    free(bufHitCntArray);
    bufHitCntArray = NULL;
    printf("del buffer hit count array\n");
  }
}

void
analyze_aggrgt_hitcntary(
    HitMapContext *hitMap,
    BufType bufType,
    u8 *bufHitCntArray,
    u32 byteThreashold)
//  analyzes:
//      if src buf's out hit count array meets the continuous address range requirment
//      if dst buf's in hit count array meets...
{
  u32 numOfBuf;

  if(bufType == TPMBuf)
    numOfBuf = hitMap->tpmBufCtxt->numOfBuf;
  else
    numOfBuf = hitMap->hitMapBufCtxt->numOfBuf;

  for(size_t r = 0; r < numOfBuf; r++) {
    for (size_t c = 0; c < numOfBuf; c++) {
      u8 val = bufHitCntArray[r*numOfBuf + c];
      if(val >= byteThreashold) {
        u32 srcbufidx = r;
        u32 dstbufidx = c;

        HitMapBufHash *src = get_hitmap_buf(hitMap->hitMapBufCtxt->hitMapBufHash, srcbufidx);
        HitMapBufHash *dst = get_hitmap_buf(hitMap->hitMapBufCtxt->hitMapBufHash, dstbufidx);
        // printOneHitMapBufHash(src);
        // printOneHitMapBufHash(dst);
        if(!hasContAddrRange(hitMap->outHitCntBufAry[srcbufidx], src->eaddr-src->baddr, hitMap->minBufSz) ||
           !hasContAddrRange(hitMap->inHitCntBufAry[dstbufidx], dst->eaddr-dst->baddr, hitMap->minBufSz) ) {
          bufHitCntArray[r*numOfBuf + c] = 0;   // invalid the buf pair
        }
      }
    }
  }
}

void
compBufHitCntArrayStat(
    HitMapContext *hitMap,
    BufType bufType,
    u8 *bufHitCntArray,
    u32 byteThreashold)
{
  // printf("compBufHitCntArrayStat: bufHitCntAry:%p\n", bufHitCntArray);
  u32 numOfBuf;
  u32 hitThreash = 0;

  if(bufType == TPMBuf)
    numOfBuf = hitMap->tpmBufCtxt->numOfBuf;
  else
    numOfBuf = hitMap->hitMapBufCtxt->numOfBuf;

//  printBufHitCntArray(bufHitCntArray, numOfBuf);
  for(size_t r = 0; r < numOfBuf; r++) {
    for (size_t c = 0; c < numOfBuf; c++) {
      u8 val = bufHitCntArray[r*numOfBuf + c];
      if(val >= byteThreashold) {
        // printf("2D hit count array: src id:%-4u - dst id:%-4u - hit count:%u\n", r+1, c+1, val);
        hitThreash++;
      }
    }
  }
  printf("----------\nnum of buf pair hitcnt > %u bytes:%u - total buf pair:%u - ratio:%u%%\n",
      byteThreashold, hitThreash, numOfBuf*numOfBuf, (hitThreash * 100) / (numOfBuf*numOfBuf) );
}

void
printBufHitCntArray(
    u8 *bufHitCntArray,
    u32 numOfBuf)
{
  for(size_t r = 0; r < numOfBuf; r++) {
    for (size_t c = 0; c < numOfBuf; c++) {
      // printf("buffer hit count array[%d][%d]:%u\n", r, c, bufHitCntArray[r][c]);
      // #ifdef ENV64
      //             u64 val = bufHitCntArray[r*numOfBuf + c];
      //             printf("buffer hit count array[%zu][%zu]:%lu\n", r, c, val);
      // #else
      //             // u32 val = *(bufHitCntArray + r * numOfBuf + c);
      //             u32 val = bufHitCntArray[r*numOfBuf + c];
      //             printf("buffer hit count array[%zu][%zu]:%u\n", r, c, val);
      // #endif
      u8 val = bufHitCntArray[r*numOfBuf + c];
      printf("buffer hit count array[%zu][%zu]:%u\n", r, c, val);
    }
  }
}

static void
buildBufHitCntAryOfBuf(
    u8 *bufHitCntAry,
    u32 numOfBuf,
    BufContext *hitMapBuf)
{
  HitMapNode *addrHead;
  u32 addrIdx;

  if(bufHitCntAry == NULL || hitMapBuf == NULL) { return; }

  // printf("buildBufHitCntAryOfBuf: bufHitCntAry:%p\n", bufHitCntAry);
  for(addrIdx = 0; addrIdx < hitMapBuf->numOfAddr; addrIdx++) {
    if((addrHead = hitMapBuf->addrArray[addrIdx]) != NULL) {
      buildBufHitCntAryOfAddr(bufHitCntAry, numOfBuf, addrHead);
    }
  }
}

static void
buildBufHitCntAryOfAddr(
    u8 *bufHitCntAry,
    u32 numOfBuf,
    HitMapNode *addrHead)
{
  if(bufHitCntAry == NULL || addrHead == NULL) { return; }

  // printf("buildBufHitCntAryOfAddr: bufHitCntAry:%p\n", bufHitCntAry);
  u32 ver = addrHead->version;
  do {
    if(addrHead->lastUpdateTS < 0) {
      // printHitMapNodeLit(addrHead);
      hitMapNodePropgtOfBuildBufHitCntAry(bufHitCntAry, numOfBuf, addrHead);
    }
    addrHead = addrHead->nextVersion;
  } while(ver != addrHead->version);
}


/*
 * For each HitMap buffer, creates its own in/out hit count array
 */

static u8 *
buildHitMapBufHitCntAry(HitMapContext *hitMap)
{
  u8 *bufHitCntAry = NULL;
  u32 numOfBuf;
  HitMapBufHash *hitMapBufHash;

  if(hitMap != NULL) {
    printTime("Before build buffer hit count array");

    numOfBuf = hitMap->hitMapBufCtxt->numOfBuf;
    bufHitCntAry = initBufHitCntArray(numOfBuf);

    for(hitMapBufHash = hitMap->hitMapBufCtxt->hitMapBufHash; hitMapBufHash != NULL;
        hitMapBufHash = hitMapBufHash->hh_hmBufHash.next) {
      if(hitMapBufHash->minseq >= 0) // minseq < 0 indicates it might contain source nodes
        continue;

      buildHitMapBufHitCntAryOfOneBuf(bufHitCntAry, numOfBuf, hitMapBufHash);
//      for(size_t r = 0; r < numOfBuf; r++) {
//          for(size_t c = 0; c < numOfBuf; c++) {
//              printf("bufHitCntAry[%zu][%zu]:%u \n", r, c, bufHitCntAry[r*numOfBuf + c]);
//          }
//      }
    }
    printTime("After build buffer hit count array");
    return bufHitCntAry;
  }
  else { return NULL; }
}

/*
 * For each node in buffer, aggregate their total in/out hit count
 */
static void
buildHitMapBufHitCntAryOfOneBuf(
    u8 *bufHitCntAry,
    u32 numOfBuf,
    HitMapBufHash *hitMapBuf)
{
  if(bufHitCntAry == NULL || hitMapBuf == NULL) {
    fprintf(stderr, "buildHitMapBufHitCntAryOfOneBuf: error\n");
    return;
  }

  HitMapNode *head = hitMapBuf->headNode;
  assert(head->addr == hitMapBuf->baddr);

  do {
    u32 ver = head->version;

    do {
      if(head->lastUpdateTS < 0) {
        hitMapNodePropgtOfBuildBufHitCntAry(bufHitCntAry, numOfBuf, head);
      }
      head = head->nextVersion;
    } while (ver != head->version);

    head = head->rightNBR;
  } while (head != NULL);
}

static bool
hasContAddrRange(
    u32 *hitCntAry,
    u32 bufsz,
    u32 min_bufsz)
{
  int rstart = -1, rend = -1;
  if(hitCntAry != NULL) {
    for(u32 byteidx = 0; byteidx < bufsz; byteidx++) {
      if(hitCntAry[byteidx] >= min_bufsz) {
          if(rstart == -1) {
            rstart = byteidx;
            rend = byteidx;
          } else {
            rend = byteidx + 1;
          }
      }
      else {
        if(rstart != -1) {
          if(rend - rstart >= min_bufsz)
            return true;
          else {
            rstart = -1;
            rend = -1;
          }
        }
      }
    }

    if(rstart != -1 && (rend - rstart) >= min_bufsz)
      return true;
  }
  return false;
}

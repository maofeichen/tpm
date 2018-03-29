#ifndef HITMAP_H
#define HITMAP_H

#include "hitmapnode.h"
// #include "tpm.h"    // move in hitmapnode.h
#include "type.h"
#include "uthash.h"

typedef struct HitMapBufHash
{
  u32 baddr;      // start addr
  u32 eaddr;      // end addr
  int minseq;     // minimum seqNo
  int maxseq;     // maximum seqNo
  u32 numOfAddr;  // num of diff addr in the buf
  u32 totalNode;  // num of total nodes in buffer
  HitMapNode *headNode;
  UT_hash_handle hh_hmBufHash;
} HitMapBufHash;

HitMapContext *
initHitMap(TPMContext *tpm, TPMBufHashTable *tpmBufHash);

HitMapContext *
buildHitMap(TPMContext *tpm, TPMBufHashTable *tpmBufHash);

void
updateHitMapBuftHitCnt(HitMapContext *hitMap);

void
compHitMapStat(HitMapContext *hitMap);

void
compReverseHitMapStat(HitMapContext *hitMap);

HitMapBufHash *
analyzeHitMapBuf(HitMapContext *hitMap);

void
delHitMap(HitMapContext *hitmap);

void
printHitMap(HitMapContext *hitmap);

void
printHitMapLit(HitMapContext *hitmap);

void
printHitMapBuf(BufContext *hitMapBuf);

void
printHitMapBufHitCnt(BufHitcntCtxt *bufHitcntCtxt);

void
printHitMapBufHash(HitMapBufHash *hitMapBufHash);
#endif

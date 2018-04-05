#ifndef HITMAP_H
#define HITMAP_H

#include "hitmapnode.h"
#include "type.h"
#include "uthash.h"

HitMapContext *
initHitMap(TPMContext *tpm, TPMBufContext *tpmBufCtxt);

HitMapContext *
buildHitMap(TPMContext *tpm, TPMBufContext *tpmBufCtxt);

// void
// updateHitMapBuftHitCnt(HitMapContext *hitMap);

void
compHitMapStat(HitMapContext *hitMap);

void
compReverseHitMapStat(HitMapContext *hitMap);

/* HitMap Buffer */
void
updateHitMapBufContext(HitMapContext *hitMap);

HitMapBufContext *
initHitMapBufContext(HitMapContext *hitMap);

void
delHitMapBufContext(HitMapBufContext *hitMapBufCtxt);

HitMapBufHash *
analyzeHitMapBuf(HitMapContext *hitMap);

HitMapBufHash *get_hitmap_buf(
    HitMapBufHash *buf_head,
    u32 buf_idx);

void
delHitHitMapBufHash(HitMapBufHash *hitMapBufHash);

void
delHitMap(HitMapContext *hitmap);

void
printHitMap(HitMapContext *hitmap);

void
printHitMapLit(HitMapContext *hitmap);

void
printHitMapBuf(BufContext *hitMapBuf);

// void
// printHitMapBufHitCnt(BufHitcntCtxt *bufHitcntCtxt);

void
printHitMapBufHash(HitMapBufHash *hitMapBufHash);
#endif

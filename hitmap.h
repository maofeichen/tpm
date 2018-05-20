#ifndef HITMAP_H
#define HITMAP_H

#include "hitmapnode.h"
#include "type.h"
#include "uthash.h"

HitMapContext *
initHitMap(TPMContext *tpm, TPMBufContext *tpmBufCtxt);

HitMapContext *
buildHitMap(TPMContext *tpm, TPMBufContext *tpmBufCtxt);

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

/* HitMap buffer hash */
HitMapBufHash *
analyzeHitMapBuf(HitMapContext *hitMap);

HitMapBufHash *get_hitmap_buf(
    HitMapBufHash *buf_head,
    u32 buf_idx);

void
delHitHitMapBufHash(HitMapBufHash *hitMapBufHash);

/* HitMap buffer hit count array */
int
createHitMapBuftHitCnt(HitMapContext *hitMap);

void
delHitMapBufHitCnt(HitMapContext *hitMap);

void
printHitMapBufHitCntAry(HitMapContext *hitMap);

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
printOneHitMapBufHash(HitMapBufHash *buf);

void
printHitMapBufHash(HitMapBufHash *hitMapBufHash);

void print_hitmap_source(HitMapContext *hitmap);
#endif

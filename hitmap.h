#ifndef HITMAP_H
#define HITMAP_H

#include "hitmapnode.h"
// #include "tpm.h"    // move in hitmapnode.h
#include "type.h"
#include "uthash.h"

HitMapContext *
initHitMap(TPMContext *tpm);

void
buildHitMap(HitMapContext *hitMap, TPMContext *tpm);

//void
//detectHitMapAvalanche(HitMapContext *hitMap, TPMContext *tpm);

void
compHitMapStat(HitMapContext *hitMap);

void
compReverseHitMapStat(HitMapContext *hitMap);

void
delHitMap(HitMapContext *hitmap);

void
printHitMap(HitMapContext *hitmap);

void
printHitMapLit(HitMapContext *hitmap);

void
printHitMapBuf(BufContext *hitMapBuf);

#endif

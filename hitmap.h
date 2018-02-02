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

void
delHitMap(HitMapContext *hitmap);

void
printHitMap(HitMapContext *hitmap);

void
printHitMapBuf(BufContext *hitMapBuf);

#endif

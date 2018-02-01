#ifndef HITMAP_H
#define HITMAP_H

#include "hitmapnode.h"
#include "tpm.h"
#include "type.h"
#include "uthash.h"

HitMapContext *
buildHitMap(TPMContext *tpm);

void
delHitMap(HitMapContext *hitmap);

void
printHitMap(HitMapContext *hitmap);

void
printHitMapBuf(BufContext *hitMapBuf);

#endif

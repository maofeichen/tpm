#ifndef BUFHITCNT_H_
#define BUFHITCNT_H_

#include "hitmap.h"
#include "type.h"

u32 *
buildBufHitCntArray(HitMapContext *hitMap);
// builds a 2D unsigned int array (N*N), N is num of buffers in HitMap. And computes
// the hit counts from a buffer to any other buffers.

void
delBufHitCntArray(u32 *bufHitCntArray, u32 numOfBuf);

void
compBufHitCntArrayStat(
        u32 *bufHitCntArray,
        u32 numOfBuf,
        u32 byteThreashold);

void
printBufHitCntArray(u32 *bufHitCntArray, u32 numOfBuf);
#endif /* BUFHITCNT_H_ */

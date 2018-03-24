#ifndef BUFHITCNT_H_
#define BUFHITCNT_H_

#include "env.h"
#include "hitmap.h"
#include "type.h"

typedef struct BufHitCntCtxt
{
    HitMapContext *hitMap;
    HitMapBufHash *hitMapBufHash;
    u32 numOfBuf;
#ifdef ENV64
    u64 *bufHitCntAry;
#else
    u32 *bufHitCntAry;
#endif
} BufHitCntCtxt;

#ifdef ENV64
u64 *
buildBufHitCntArray(HitMapContext *hitMap);
#else
u32 *
buildBufHitCntArray(HitMapContext *hitMap);
#endif
// builds a 2D unsigned int array (N*N), N is num of buffers in HitMap. And computes
// the hit counts from a buffer to any other buffers.

#ifdef ENV64
void
delBufHitCntArray(u64 *bufHitCntArray, u32 numOfBuf);
#else
void
delBufHitCntArray(u32 *bufHitCntArray, u32 numOfBuf);
#endif

#ifdef ENV64
void
compBufHitCntArrayStat(
        u64 *bufHitCntArray,
        u32 numOfBuf,
        u32 byteThreashold);
#else
void
compBufHitCntArrayStat(
        u32 *bufHitCntArray,
        u32 numOfBuf,
        u32 byteThreashold);
#endif

void
printBufHitCntArray(u32 *bufHitCntArray, u32 numOfBuf);
#endif /* BUFHITCNT_H_ */

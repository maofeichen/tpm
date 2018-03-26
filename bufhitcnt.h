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

// #ifdef ENV64
// u64 *
// buildBufHitCntArray(HitMapContext *hitMap);
// #else
// u32 *
// buildBufHitCntArray(HitMapContext *hitMap);
// #endif
u8 *
buildBufHitCntArray(HitMapContext *hitMap);
// builds a 2D unsigned int array (N*N), N is num of buffers in HitMap. And computes
// the hit counts from a buffer to any other buffers.

void
delBufHitCntArray(
// #ifdef ENV64
//         u64 *bufHitCntArray,
// #else
//         u32 *bufHitCntArray,
// #endif
        u8 *bufHitCntArray,       
        u32 numOfBuf);

void
compBufHitCntArrayStat(
// #ifdef ENV64
//         u64 *bufHitCntArray,
// #else
//         u32 *bufHitCntArray,
// #endif
        u8 *bufHitCntArray,
        u32 numOfBuf,
        u32 byteThreashold);

void
printBufHitCntArray(
// #ifdef ENV64
//         u64 *bufHitCntArray,
// #else
//         u32 *bufHitCntArray,
// #endif
        u8 *bufHitCntArray,       
        u32 numOfBuf);
#endif /* BUFHITCNT_H_ */

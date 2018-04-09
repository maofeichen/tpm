#ifndef BUFHITCNT_H_
#define BUFHITCNT_H_

#include "env.h"
#include "hitmap.h"
#include "type.h"

typedef enum { TPMBuf = 0, HitMapBuf = 1} BufType;

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

u8 *
buildBufHitCntArray(HitMapContext *hitMap, BufType bufType);
// builds a 2D unsigned int array (N*N), N is num of buffers in HitMap. And computes
// the hit counts from a buffer to any other buffers.

void
delBufHitCntArray(u8 *bufHitCntArray);

void
analyze_aggrgt_hitcntary(
    HitMapContext *hitMap,
    BufType bufType,
    u8 *bufHitCntArray,
    u32 byteThreashold);

void
compBufHitCntArrayStat(
    HitMapContext *hitMap,
    BufType bufType,
    u8 *bufHitCntArray,
    u32 byteThreashold);

void
printBufHitCntArray(
    u8 *bufHitCntArray,
    u32 numOfBuf);
#endif /* BUFHITCNT_H_ */

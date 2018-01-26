#ifndef HITMAP_H
#define HITMAP_H

#include "hitmapnode.h"
#include "tpm.h"
#include "type.h"

typedef struct BufContext
{
    u32 numOfAddr;  // num of addr of the buffer
    HitMapNode **addrArray;
} BufContext;

typedef struct HitMapContext
{
    u32 numOfBuf;   // num of buffers in TPM
    BufContext **bufArray;
} HitMapContext;

HitMapContext *
buildHitMap(TPMContext *tpm);

#endif

#ifndef HITMAP_H
#define HITMAP_H

#include "hitmapnode.h"
#include "tpm.h"
#include "type.h"
#include "uthash.h"

typedef struct HitMapAddr2NodeHashTable
{
    u32 addr;                   // key: addr of in each node in hitmap
    HitMapNode *toHitMapNode;   // val: pointes to first version of node in HitMap
    UT_hash_handle hh_hitMapAddr2NodeHT;
} HitMapAddr2NodeHashTable;  // stores nodes that has correspond hitmap node in the hitmap

typedef struct BufContext
{
    u32 numOfAddr;  // num of addr of the buffer
    HitMapNode **addrArray; // addr array of the buffer,
                            // each points to the earliest version node in the hitmap
} BufContext;

typedef struct HitMapContext
{
    // HitMapAddr2NodeHashTable *hitMapNodeHT;  // hash table head
    u32 numOfBuf;           // num of buffers in TPM
    BufContext **bufArray;  // buf array, each points to a buffer context
} HitMapContext;

HitMapContext *
buildHitMap(TPMContext *tpm);

void
delHitMap(HitMapContext *hitmap);

void
printHitMap(HitMapContext *hitmap);

void
printHitMapBuf(BufContext *hitMapBuf);

#endif

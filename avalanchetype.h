#ifndef AVALANCHETYPE_H
#define AVALANCHETYPE_H

#include "tpmnode.h"
#include "uthash.h"

struct addr2NodeItem
{
    u32 addr;				/* 32-bit address: src addr in 1st level hash; dst addr in 2nd level hash */
    struct TPMNode2 *node;	/* used as key to hash: src node in 1st level hash; dst node in 2nd level hash */
    struct addr2NodeItem *subHash;	  /* next level hash */
    TaintedBuf *toMemNode; 			  // the mem node that the source node can propagate
    UT_hash_handle hh_addr2NodeItem;  /* makes this structure hashable */
};
typedef struct addr2NodeItem Addr2NodeItem;

typedef struct BufPropagateRes
{
    int numOfAddr;  // num of different addr of the buf
    void **addrPropagateArray;  // Pointer array of each addr, each points to sub data structure
                                // storing propagate results
} BufPropagateRes;
// stores propagate results of each bufs

typedef struct TPMPropagateRes
{
    u32 bufTotal;                // num of bufs in the TPM
    BufPropagateRes **tpmPropagateArray; // Pointer array of each buf, each points sub data structure
                                         // storing propagation results

} TPMPropagateRes;
// stores propagate results of all TPM bufs

/* Addr2NodeItem */
Addr2NodeItem *
createAddr2NodeItem(
        u32 addr,
        TPMNode2 *memNode,
        Addr2NodeItem *subHash,
        TaintedBuf *toMemNode);

/* TPMPropagateRes */
TPMPropagateRes *
createTPMPropagate(int bufTotal);

void 
delTPMPropagate(TPMPropagateRes *t);
// TODO

/* BufPropagateRes */
BufPropagateRes *
createBufPropagate(int numOfAddr);

void
delBufPropagate(BufPropagateRes **b);

/* print */
void
print2ndLevelHash(Addr2NodeItem *src);

void
printTPMPropagateRes(TPMPropagateRes *t);

void
printBufPropagateRes(BufPropagateRes *b);
#endif

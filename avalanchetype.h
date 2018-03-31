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

typedef struct AddrPropgtToNode
{
  TPMNode2 *srcnode;  // key of 1st level hash
  struct AddrPropgtToNode *subBufHash; // next level hash
  u32 dstBufID;       // val of 1st level hash, key of 2nd level hash
  TPMNode2 *propagtToNode; // val of 2nd level hash, the dst node that srcnode can propagate to
  UT_hash_handle hh_addrPropgtToNode;
} AddrPropgtToNode;
// used as to store propagated nodes from same addr, s.t:
// srcnode -->
//            bufID -->
//                     propagated nodes

typedef struct BufPropagateRes
{
  u32 numOfAddr;  // num of different addr of the buf
  AddrPropgtToNode **addrPropgtAry;  // Pointer array of each addr, each points to sub data structure
  // storing propagate results
} BufPropagateRes;
// stores propagate results of each bufs

typedef struct TPMPropagateRes
{
  u32 numOfBuf;                   // num of bufs in the TPM
  BufPropagateRes **tpmPropgtAry; // Pointer array of each buf, each points sub data structure
  // storing propagation results

} TPMPropagateRes;
// stores propagate results of all TPM bufs

typedef struct TPMPropgtSearchCtxt
{
  TPMPropagateRes *tpmPropgt; // points to propagations of all buffers of tpm
  int maxSeqN; // max seqNo of the last buffer of the tpm, used to limit the depth
  // of taint propagation search in dfs
} TPMPropgtSearchCtxt;
// Context of searching taint propagations of TPM

/* Addr2NodeItem */
Addr2NodeItem *
createAddr2NodeItem(
    u32 addr,
    TPMNode2 *memNode,
    Addr2NodeItem *subHash,
    TaintedBuf *toMemNode);

/* AddrPropgtToNode */
AddrPropgtToNode *
createAddrPropgtToNode(
    TPMNode2 *srcnode,
    AddrPropgtToNode *subBufHash,
    u32 dstBufID,
    TPMNode2 *propagtToNode);

/* TPMPropagateRes */
// TPMPropagateRes *
// createTPMPropagate(int bufTotal);

u32
getTPMPropagateArrayIdx(u32 bufID);
// converts bufID to array idx of the TPMPropagateRes

// void 
// delTPMPropagate(TPMPropagateRes *t);
// TODO

/* BufPropagateRes */
// BufPropagateRes *
// createBufPropagate(u32 numOfAddr);

void
delBufPropagate(BufPropagateRes **b);

// TPMPropgtSearchCtxt *
// createTPMPropgtSearchCtxt(
//     TPMPropagateRes *tpmPropgtRes,
//     int maxSeqN);

// void
// delTPMPropgtSearchCtxt(TPMPropgtSearchCtxt *t);

/* print */
void
print2ndLevelHash(Addr2NodeItem *src);

void
printTPMPropgtSearchCtxt(TPMPropgtSearchCtxt *t);

void
printTPMPropagateRes(TPMPropagateRes *t);

void
printBufPropagateRes(BufPropagateRes *b);
#endif

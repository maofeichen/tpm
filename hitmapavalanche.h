#ifndef HITMAPAVALANCHE_H
#define HITMAPAVALANCHE_H

#include "hitmap.h"
#include "type.h"

typedef struct HitMapAddr2NodeItem
{
    u32 addr;				/* 32-bit address: src addr in 1st level hash; dst addr in 2nd level hash */
    struct TPMNode2 *node;	/* used as key to hash: src node in 1st level hash; dst node in 2nd level hash */
    struct addr2NodeItem *subHash;	  /* next level hash */
    TaintedBuf *toMemNode; 			  // the mem node that the source node can propagate
    UT_hash_handle hh_addr2NodeItem;  /* makes this structure hashable */
} HitMapAddr2NodeItem;


typedef struct HitMapAvalSearchCtxt
{
    u32 minBufferSz;		    // minimum buffer size (such as 8) considered for avalanche effect search
    // struct TPMNode2 *srcBuf;	// point to potential source buffer
    // struct TPMNode2 *dstBuf;	// point to potential destination buffer
    TPMBufHashTable *srcTPMBuf;
    TPMBufHashTable *dstTPMBuf;
    u32 srcBufID;
    u32 dstBufID;
    u32	srcAddrStart;	// starting addr of the potential source buffer
    u32 srcAddrEnd;		// end addr of the potential source buffer. Should be >= srcAddrStart
    u32	dstAddrStart;	// starting addr of the potential destination buffer
    u32 dstAddrEnd;		// end addr of the potential destination buffer. Should be >= dstAddrStart
    int srcMinSeqN;		// minimum seq# of the source buffer
    int srcMaxSeqN;		// maximum seq# of the source buffer
    int dstMinSeqN;		// minimum seq# of the destination buffer
    int dstMaxSeqN;		// maximum seq# of the destination buffer
    unsigned char *srcAddrHitCnt;  // array[0, srcAddrEnd-srcAddrStart] to record the aggregated hit account of all versions of each source address
    unsigned char *dstAddrHitCnt;  // array[0, dstAddrEnd-dstAddrStart] to record the aggregated hit account of all versions of each destination address
    u32 numOfSrcAddr;   // number of souce addresses in the source buf
    u32 numOfDstAddr;   // number of destination addresses in the dst buf
    HitMapAddr2NodeItem **hitMapAddr2NodeAry; // array[0, srcAddrEnd-srcAddrStart] of pointers to struct addr2NodeItem (hash table)
} HitMapAvalSearchCtxt;

void
detectHitMapAvalanche(HitMapContext *hitMap, TPMContext *tpm);


#endif

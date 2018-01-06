#ifndef AVALANCHE_H
#define AVALANCHE_H 

#include "uthash.h"

#include "continbuf.h"
#include "propagate.h"
#include "tpmnode.h"
#include "tpm.h"
#include "type.h"

struct addr2NodeItem
{
    u32 addr;				/* 32-bit address: src addr in 1st level hash; dst addr in 2nd level hash */
    struct TPMNode2 *node;	/* used as key to hash: src node in 1st level hash; dst node in 2nd level hash */
    struct addr2NodeItem *subHash;	  /* next level hash */
    TaintedBuf *toMemNode; 			  // the mem node that the source node can propagate
    UT_hash_handle hh_addr2NodeItem;  /* makes this structure hashable */
};
typedef struct addr2NodeItem Addr2NodeItem;

struct AvalancheSearchCtxt
{
    u32 minBufferSz;		    // minimum buffer size (such as 8) considered for avalanche effect search
    struct TPMNode2 *srcBuf;	// point to potential source buffer
    struct TPMNode2 *dstBuf;	// point to potential destination buffer
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
    struct addr2NodeItem *addr2Node; // array[0, dstAddrEnd-dstAddrStart] of pointers to struct addr2NodeItem (hash table)
};
typedef struct AvalancheSearchCtxt AvalancheSearchCtxt;

struct AvalDstBufHTNode
{
    TPMNode2 *dstNode;
    u32 hitcnt;
    UT_hash_handle hh_avalDstBufHTNode;
};
typedef struct AvalDstBufHTNode AvalDstBufHTNode; // stores the propagate destination mem nodes

struct StackAddr2NodeItem 
{
    Addr2NodeItem *addr2NodeItem;
    struct StackAddr2NodeItem *next;
};
typedef struct StackAddr2NodeItem StackAddr2NodeItem;

struct StackDstBufHT
{
    AvalDstBufHTNode *dstBufHT;
    struct StackDstBufHT *next;
};
typedef struct StackDstBufHT StackDstBufHT;

struct StackBufAry
{
    ContinBufAry *contBufAry;
    struct StackBufAry *next; 
};
typedef struct StackBufAry StackBufAry;

struct PropagateStat
{
    u32 minstep;
    u32 maxstep;
    u32 totalstep;
    u32 numOfSearch;    
};
typedef struct PropagateStat PropagateStat;

int
init_AvalancheSearchCtxt(struct AvalancheSearchCtxt **avalsctxt, u32 minBufferSz, struct TPMNode2 *srcBuf, 
			 struct TPMNode2 *dstBuf, u32 srcAddrStart, u32 srcAddrEnd, u32 dstAddrStart, u32 dstAddrEnd);

void
free_AvalancheSearchCtxt(struct AvalancheSearchCtxt *avalsctxt);

void 
searchAllAvalancheInTPM(TPMContext *tpm);
// Searches avalanche between all pair <in, out> buffer in the tpm

int
searchAvalancheInOutBuf(TPMContext *tpm, AvalancheSearchCtxt *avalsctxt, PropagateStat *propaStat);
// Searches avalanche given in and out buffers (stored in AvalancheSearchCtxt)
// Retures:
//	0: success
//	<0: error

#endif

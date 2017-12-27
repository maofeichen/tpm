#ifndef AVALANCHE_H
#define AVALANCHE_H 

#include "tpm.h"
#include "uthash.h"

struct addr2NodeItem
{
    u32 addr;			/* 32-bit address: src addr in 1st level hash; dst addr in 2nd level hash */
    struct TMPNode2 *node;	/* used as key to hash: src node in 1st level hash; dst node in 2nd level hash */
    struct addr2NodeItem *subHash;	/* next level hash */
    UT_hash_handle hh;         /* makes this structure hashable */
};
typedef struct addr2NodeItem Addr2NodeItem;

struct AvalancheSearchCtxt
{
    u32 minBufferSz;		// minimum buffer size (such as 8) considered for avalanche effect search
    struct TPMNode2 *srcBuf;	// point to potential source buffer
    struct TPMNode2 *dstBuf;	// point to potential destination buffer
    u32	srcAddrStart;		// starting addr of the potential source buffer
    u32 srcAddrEnd;		// end addr of the potential source buffer. Should be >= srcAddrStart
    u32	dstAddrStart;		// starting addr of the potential destination buffer
    u32 dstAddrEnd;		// end addr of the potential destination buffer. Should be >= dstAddrStart
    u32 srcMinSeqN;		// minimum seq# of the source buffer
    u32 srcMaxSeqN;		// maximum seq# of the source buffer
    u32 dstMinSeqN;		// minimum seq# of the destination buffer
    u32 dstMaxSeqN;		// maximum seq# of the destination buffer
    unsigned char *srcAddrHitCnt;  // array[0, srcAddrEnd-srcAddrStart] to record the aggregated hit account of all versions of each source address
    unsigned char *dstAddrHitCnt;  // array[0, dstAddrEnd-dstAddrStart] to record the aggregated hit account of all versions of each destination address
    struct addr2NodeItem **addr2Node;	// array[0, dstAddrEnd-dstAddrStart] of pointers to struct addr2NodeItem (hash table)
};
typedef struct AvalancheSearchCtxt AvalancheSearchCtxt;

int
init_AvalancheSearchCtxt(struct AvalancheSearchCtxt *avalsctxt, u32 minBufferSz, struct TPMNode2 *srcBuf, 
			 struct TPMNode2 *dstBuf, u32 srcAddrStart, u32 srcAddrEnd, u32 dstAddrStart, u32 dstAddrEnd);

void
free_AvalancheSearchCtxt(struct AvalancheSearchCtxt *avalsctxt);

struct TPMNode2 * 
memNodeReachBuf(struct AvalancheSearchCtxt *avalsctxt, struct TPMNode2 *srcNode, struct taintedBuf *dstBuf);
/* return:
    NULL: srcNode does not reach any node in the dstBuf
    else: pointer to the node in dstBuf that srcNode reaches
*/

int
memNodePropagationSearch(struct AvalancheSearchCtxt *avalsctxt, struct TPMNode2 *srcNode, struct taintedBuf *dstBuf);

#endif
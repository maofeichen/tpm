#ifndef CONTINBUF_H
#define CONTINBUF_H 

#include "tpmnode.h"
#include "type.h"

#define INIT_CONTBUFNODEARY_SZ	4

// struct ContinBufNode
// {
//     TaintedBuf *headOfAddr;  	 // nodeptr list of the mem node (could be multiple of same addr)
// };
// typedef struct ContinBufNode ContinBufNode;   

struct ContinBuf
{
	u32 bufStart;
	u32 bufEnd;
	u32 nodeArySz;					
	u32 nodeAryUsed;	// num of nodes in the ary
	TaintedBuf **contBufNodeAry;	// dynamic pointer of array, 
									// each pointer is a list of versions of same addr
};
typedef struct ContinBuf ContinBuf;	// stores the continuous buffer

// ContinBufNode *
// createContBufNode(TPMNode2 *nodeptr);

// int 
// extendContBufNode(ContinBufNode *contBufNode, TPMNode2 *nodeptr);
//TODO

ContinBuf *
initContinBuf();

int 
extendContinBuf(ContinBuf *contBuf, TPMNode2 *nodeptr);

void 
delContinBuf(ContinBuf *contBuf);

// int 
// extendContBuf(ContinBuf *contBuf, ContinBufNode *contBufNode);
// TODO

void 
printContinBuf(ContinBuf *contBuf);

#endif
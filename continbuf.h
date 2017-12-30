#ifndef CONTINBUF_H
#define CONTINBUF_H 

#include "utarray.h"
#include "tpmnode.h"
#include "type.h"

// struct ContinBufNode
// {
//     TaintedBuf *headOfAddr;  	 // nodeptr list of the mem node (could be multiple of same addr)
// };
// typedef struct ContinBufNode ContinBufNode;   

struct ContinBuf
{
	u32 bufStart;
	u32 bufEnd;
	UT_array *continBufNodeAry;
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
AppendContinBuf(ContinBuf *contBuf, TPMNode2 *nodeptr);

// int 
// extendContBuf(ContinBuf *contBuf, ContinBufNode *contBufNode);
// TODO

void 
printContinBuf(ContinBuf *contBuf);

#endif
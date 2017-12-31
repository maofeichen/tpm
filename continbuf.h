#ifndef CONTINBUF_H
#define CONTINBUF_H 

#include "tpmnode.h"
#include "type.h"

#define INIT_CONTBUFNODEARY_SZ	4
#define INIT_CONTBUFARY_SZ 		4

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

struct ContinBufAry
{
	u32 bufArySz;
	u32 bufAryUsed;
	ContinBuf **contBufAryHead;	
};
typedef struct ContinBufAry ContinBufAry;

ContinBuf *
initContinBuf();

int 
extendContinBuf(ContinBuf *contBuf, TPMNode2 *nodeptr);

ContinBuf *
getContBufIntersect(ContinBuf *l, u32 intersectStart, u32 intersectEnd);

void 
delContinBuf(ContinBuf *contBuf);

ContinBufAry *
initContBufAry();

int 
add2ContBufAry(ContinBufAry *contBufAry, ContinBuf *contBuf);

ContinBufAry *
getBufAryIntersect(ContinBufAry *l, ContinBufAry *r);
// computes intersection between the two continuous buf arraies

void 
delContinBufAry(ContinBufAry **contBufAry);

void 
printContinBuf(ContinBuf *contBuf);

void 
printContinBufAry(ContinBufAry *contBufAry);

#endif
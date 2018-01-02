#ifndef CONTINBUF_H
#define CONTINBUF_H 

#include <stdbool.h>
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
appendContBufAry(ContinBufAry *contBufAry, ContinBuf *contBuf);

int 
add2BufAry(ContinBufAry *contBufAry, ContinBuf *contBuf);
// Adds the continuous buf to the buf ary in increasing order

ContinBufAry *
getBufAryIntersect(ContinBufAry *l, ContinBufAry *r);
// computes intersection between the two continuous buf arraies

bool 
hasMinSzContBuf(ContinBufAry *contBufAry, u32 minBufSz);
// Returns:
//	true: if any buffer in the buffer any size is larger then min buf sz
//	false: otherwise

void 
delContinBufAry(ContinBufAry **contBufAry);

void 
printContinBuf(ContinBuf *contBuf);

void 
printContinBufAry(ContinBufAry *contBufAry);

void 
printContBufAry_lit(char *s, ContinBufAry *contBufAry);

#endif
#include <stdlib.h>
#include <string.h>
#include "utlist.h"
#include "continbuf.h"

static void 
growContBufNodeAry(ContinBuf *contBuf);

static void 
growContBufAry(ContinBufAry *contBufAry);

ContinBuf *
initContinBuf()
{
	ContinBuf *contBuf = calloc(1, sizeof(ContinBuf) );
	contBuf->nodeArySz = INIT_CONTBUFNODEARY_SZ;
	contBuf->nodeAryUsed = 0;

	contBuf->contBufNodeAry = malloc(INIT_CONTBUFNODEARY_SZ * sizeof(TaintedBuf *) );
	memset(contBuf->contBufNodeAry, 0, sizeof(TaintedBuf *) * INIT_CONTBUFNODEARY_SZ);

	return contBuf;
}

int 
extendContinBuf(ContinBuf *contBuf, TPMNode2 *nodeptr)
{
	TaintedBuf *nodeHead = NULL, *node;

	node = createTaintedBuf(nodeptr);
	LL_APPEND(nodeHead, node);

	if(contBuf->nodeAryUsed == 0) {
		contBuf->bufStart = nodeptr->addr;
		contBuf->bufEnd = contBuf->bufStart + 4;
		contBuf->contBufNodeAry[contBuf->nodeAryUsed] = nodeHead;
		(contBuf->nodeAryUsed)++;
	}
	else {
		if(contBuf->nodeAryUsed == contBuf->nodeArySz) {
			growContBufNodeAry(contBuf);
		}

		contBuf->bufEnd = nodeptr->addr + 4;
		contBuf->contBufNodeAry[contBuf->nodeAryUsed] = nodeHead;
		(contBuf->nodeAryUsed)++;	
	}
	return 0;
}

void 
delContinBuf(ContinBuf *contBuf)
{
	free(contBuf->contBufNodeAry);
	free(contBuf);
}

ContinBufAry *
initContBufAry()
{
	ContinBuf **contBufAryHead;
	ContinBufAry *bufAry;

	bufAry = calloc(1, sizeof(ContinBufAry) );
	bufAry->bufArySz = INIT_CONTBUFARY_SZ;
	bufAry->bufAryUsed = 0;
	contBufAryHead = calloc(1, sizeof(ContinBuf) * INIT_CONTBUFARY_SZ);
	bufAry->contBufAryHead = contBufAryHead;

	return bufAry;
}

int 
add2ContBufAry(ContinBufAry *contBufAry, ContinBuf *contBuf)
{

	if(contBufAry->bufAryUsed == contBufAry->bufArySz) {
		growContBufAry(contBufAry);
	}

	contBufAry->contBufAryHead[contBufAry->bufAryUsed] = contBuf;
	(contBufAry->bufAryUsed)++;

	return 0;
}

void 
delContinBufAry(ContinBufAry *contBufAry)
{

}

void 
printContinBuf(ContinBuf *contBuf)
{
	TaintedBuf *nodeHead, *elt;
	int i;

	printf("cont bufstart:%x - bufend:%x - node ary sz:%u - total buf nodes:%u\n", 
		contBuf->bufStart, contBuf->bufEnd, contBuf->nodeArySz, contBuf->nodeAryUsed);

	for(i = 0; i < contBuf->nodeArySz; i++) {
		if(contBuf->contBufNodeAry[i] != NULL) {
			nodeHead = contBuf->contBufNodeAry[i];
			printf("node head:%p addr:%x next:%p\n", nodeHead, nodeHead->bufstart->addr, nodeHead->next);
			LL_FOREACH(nodeHead, elt) {
				printf("TaintedBuf:%p - addr:%x\n", elt, elt->bufstart->addr);
			}

		}
		else { printf("node head:%p\n", contBuf->contBufNodeAry[i]); }
	}
}

void 
printContinBufAry(ContinBufAry *contBufAry)
{
	int i;
	printf("cont buf ary: sz:%u - total cont buf:%u\n", 
		contBufAry->bufArySz, contBufAry->bufAryUsed);
	for(i = 0; i < contBufAry->bufArySz; i++) {
		if(contBufAry->contBufAryHead[i] != NULL) {
			printContinBuf(contBufAry->contBufAryHead[i]);
		}
	}
}

static void 
growContBufNodeAry(ContinBuf *contBuf)
// doubles the contNodeBufSz 
{
	TaintedBuf **newBufNodeAry;
	u32 newNodeArySz = contBuf->nodeArySz * 2;
	int i;

	newBufNodeAry = malloc(sizeof(TaintedBuf *) * newNodeArySz );
	memset(newBufNodeAry, 0, sizeof(TaintedBuf *) * newNodeArySz );

	for(i = 0; i < contBuf->nodeAryUsed; i++) {
		newBufNodeAry[i] = contBuf->contBufNodeAry[i];
	}
	contBuf->nodeArySz = newNodeArySz;
	free(contBuf->contBufNodeAry);
	contBuf->contBufNodeAry = newBufNodeAry;
}

static void 
growContBufAry(ContinBufAry *contBufAry)
{

}
#include <stdlib.h>
#include <string.h>
#include "utlist.h"
#include "continbuf.h"

static void 
reallocContBufNodeAry(ContinBuf *contBuf);

// static void 
// bufNodeCopy(void *_dst, const void *_src);

// static void 
// reallocContBufNodeAry(ContinBuf *contBuf);

// UT_icd continBufNodeAry_icd = {sizeof(TaintedBuf *), NULL, bufNodeCopy, NULL };

// ContinBufNode *
// createContBufNode(TPMNode2 *nodeptr)
// {
// 	ContinBufNode *bufNode;
// 	TaintedBuf *nodeHead = NULL, *node;

// 	bufNode = malloc(sizeof(ContinBufNode) );
// 	memset(bufNode, 0, sizeof(ContinBufNode) );

// 	node = createTaintedBuf(nodeptr);
// 	LL_APPEND(nodeHead, node); 
// 	bufNode->headOfAddr = nodeHead;

// 	return bufNode;
// }

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
			reallocContBufNodeAry(contBuf);
		}

		contBuf->bufEnd = nodeptr->addr + 4;
		contBuf->contBufNodeAry[contBuf->nodeAryUsed] = nodeHead;
		(contBuf->nodeAryUsed)++;	
	}
	return 0;
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

// static void 
// bufNodeCopy(void *_dst, const void *_src)
// {
// 	TaintedBuf *dst = (TaintedBuf *)_dst, *src = (TaintedBuf *)_src;
// 	*dst = *src;
// }

static void 
reallocContBufNodeAry(ContinBuf *contBuf)
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
#include <stdlib.h>
#include <string.h>
#include "utlist.h"
#include "continbuf.h"

static void 
bufNodeCopy(void *_dst, const void *_src);

UT_icd continBufNodeAry_icd = {sizeof(TaintedBuf *), NULL, bufNodeCopy, NULL };

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
	ContinBuf *contBuf = malloc(sizeof(ContinBuf) );
	memset(contBuf, 0, sizeof(contBuf) );
	utarray_new(contBuf->continBufNodeAry, &continBufNodeAry_icd);
	return contBuf;
}

int 
AppendContinBuf(ContinBuf *contBuf, TPMNode2 *nodeptr)
{
	u32 len;
	TaintedBuf *nodeHead = NULL, *node;

	node = createTaintedBuf(nodeptr);
	LL_APPEND(nodeHead, node);

	len = utarray_len(contBuf->continBufNodeAry);
	if(len == 0) {
		contBuf->bufStart = nodeptr->addr;
		contBuf->bufEnd = contBuf->bufStart + 4;
		utarray_push_back(contBuf->continBufNodeAry, nodeHead);

		nodeHead = (TaintedBuf*)utarray_front(contBuf->continBufNodeAry);
		printf("node head:%p addr:%x next:%p\n", nodeHead, nodeHead->bufstart->addr, nodeHead->next);
		// LL_FOREACH(nodeHead, elt) {
		// 	printf("TaintedBuf:%p - addr:%x\n", elt, elt->bufstart->addr);
		// }
	}
	else {
		nodeHead = (TaintedBuf*)utarray_front(contBuf->continBufNodeAry);
		printf("node head:%p addr:%x next:%p\n", nodeHead, nodeHead->bufstart->addr, nodeHead->next);
		contBuf->bufEnd = nodeptr->addr + 4;
		utarray_push_back(contBuf->continBufNodeAry, nodeHead);
	}

	return 0;
}

void 
printContinBuf(ContinBuf *contBuf)
{
	TaintedBuf *nodeHead, *elt;

	printf("cont bufstart:%x - bufend:%x - total buf nodes:%u\n", 
		contBuf->bufStart, contBuf->bufEnd, utarray_len(contBuf->continBufNodeAry) );

	nodeHead = NULL;
	while( (nodeHead = (TaintedBuf *)utarray_next(contBuf->continBufNodeAry, nodeHead) ) ) {
		// printf("node head:%p addr:%x next:%p\n", nodeHead, nodeHead->bufstart->addr, nodeHead->next);
		// LL_FOREACH(nodeHead, elt) {
		// 	printf("TaintedBuf:%p - addr:%x\n", elt, elt->bufstart->addr);
		// }
	}
}

static void 
bufNodeCopy(void *_dst, const void *_src)
{
	TaintedBuf *dst = (TaintedBuf *)_dst, *src = (TaintedBuf *)_src;
	*dst = *src;
}
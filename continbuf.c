#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "utlist.h"
#include "continbuf.h"

static void 
growContBufNodeAry(ContinBuf *contBuf);

static void 
growContBufAry(ContinBufAry *contBufAry);

static u32 
getMaxAddr(u32 addr_l, u32 addr_r);

static u32 
getMinAddr(u32 addr_l, u32 addr_r);

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

ContinBuf *
getContBufIntersect(ContinBuf *l, u32 intersectStart, u32 intersectEnd)
{
	TaintedBuf *head;
	ContinBuf *contBuf = initContinBuf();
	int i;

	for(i = 0; i < l->nodeAryUsed; i++) {
		head = l->contBufNodeAry[i];
		if(head->bufstart->addr >= intersectStart) {
			extendContinBuf(contBuf, head->bufstart);
		} 
		
		if( (head->bufstart->addr + 4) > intersectEnd) {
			break;
		}
	}

	return contBuf;
}

void 
delContinBuf(ContinBuf *contBuf)
{
	int i;
	TaintedBuf *head, *elt, *tmp;
	for(i = 0; i < contBuf->nodeAryUsed; i++) {
		head = contBuf->contBufNodeAry[i];
		LL_FOREACH_SAFE(head, elt, tmp) {
			LL_DELETE(head, elt);
			free(elt);
		}
	}
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

ContinBufAry *
getBufAryIntersect(ContinBufAry *l, ContinBufAry *r)
{
	ContinBufAry *bufAryIntrsct = NULL;
	u32 idx_l = 0, idx_r = 0;
	u32 aryUsed_l = l->bufAryUsed, aryUsed_r = r->bufAryUsed;
	ContinBuf *buf_l, *buf_r, *bufIntrsct;

	bufAryIntrsct = initContBufAry();

	while(true) {
		if(idx_l >= aryUsed_l || idx_r >= aryUsed_r)
		 	break;

		buf_l = l->contBufAryHead[idx_l];
		buf_r = r->contBufAryHead[idx_r];

		// choose the larger buf start addr, choose the smaller buf end addr
		u32 intrsctAddrStart = getMaxAddr(buf_l->bufStart, buf_r->bufStart);
		u32 intrsctAddrEnd 	 = getMinAddr(buf_l->bufEnd, buf_r->bufEnd);

		if(intrsctAddrStart < intrsctAddrEnd) { // gets the intersection buf
			// TODO: add the bufAryIntrsct buf
			printf("intersection: addr start:%x - addr end:%x\n", intrsctAddrStart, intrsctAddrEnd);
			bufIntrsct = getContBufIntersect(buf_l, intrsctAddrStart, intrsctAddrEnd);
			add2ContBufAry(bufAryIntrsct, bufIntrsct);
		}

		// if left buf range is smaller than right buf range, increases it
		// notices all bufs in buf ary are in increasing order
		if(buf_l->bufEnd < buf_r->bufEnd) { idx_l++; }
		else if(buf_l->bufEnd > buf_r->bufEnd) { idx_r++; }
		else { idx_l++, idx_r++; }	
	}


	return bufAryIntrsct;
}

void 
delContinBufAry(ContinBufAry **contBufAry)
{
	int i;
	for(i = 0; i < (*contBufAry)->bufAryUsed; i++) {
		delContinBuf( (*contBufAry)->contBufAryHead[i]);
	}
	free( (*contBufAry)->contBufAryHead);
	free(*contBufAry);
	*contBufAry = NULL;
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
	if(contBufAry == NULL){
		fprintf(stderr, "error: continuous buf ary is empty:%p\n", contBufAry);
		return;
	}

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
// doubles the bufArySz
{
	ContinBuf **newContBufAryHead;
	u32 newBufArySz = contBufAry->bufArySz * 2;
	int i;

	newContBufAryHead = calloc(1, sizeof(ContinBuf) * newBufArySz);
	for(i = 0; i < contBufAry->bufAryUsed; i++) {
		newContBufAryHead[i] = contBufAry->contBufAryHead[i];
	}
	contBufAry->bufArySz = newBufArySz;

	free(contBufAry->contBufAryHead);
	contBufAry->contBufAryHead = newContBufAryHead;
}

static u32 
getMaxAddr(u32 addr_l, u32 addr_r)
{
	if(addr_l > addr_r)
		return addr_l;
	else
		return addr_r;
}

static u32 
getMinAddr(u32 addr_l, u32 addr_r)
{
	if(addr_l < addr_r)
		return addr_l;
	else
		return addr_r;
}
#include "avalanchetype.h"
#include <assert.h>

Addr2NodeItem *
createAddr2NodeItem(u32 addr, TPMNode2 *memNode, Addr2NodeItem *subHash, TaintedBuf *toMemNode)
{
	Addr2NodeItem *i = NULL;
	i = malloc(sizeof(Addr2NodeItem) );
	i->addr = addr;
	i->node = memNode;
	i->subHash 	 = subHash;
	i->toMemNode = toMemNode;
	return i;
}

TPMPropagateRes *
createTPMPropagate(int bufTotal)
{
    TPMPropagateRes *t = calloc(1, sizeof(TPMPropagateRes) );
    t->bufTotal = bufTotal;
    t->tpmPropagateArray = calloc(1, sizeof(BufPropagateRes *) * bufTotal);

    assert(t != NULL);
    assert(t->tpmPropagateArray != NULL);

    for(int i = 0; i < bufTotal; i++)
        t->tpmPropagateArray[i] = NULL;
    return t;
}

u32
getTPMPropagateArrayIdx(u32 bufID)
{
    assert(bufID > 0);
    return bufID-1;
}

void 
delTPMPropagate(TPMPropagateRes *t)
{
    if(t == NULL)
        return;

    for(int i = 0; i < t->bufTotal; i++){
        delBufPropagate(&(t->tpmPropagateArray[i]) );
    }

    free(t->tpmPropagateArray);
    t->tpmPropagateArray = NULL;
    free(t);
    printf("del TPMPropagateRes\n");
}

BufPropagateRes *
createBufPropagate(u32 numOfAddr)
{
    BufPropagateRes *b = calloc(1, sizeof(BufPropagateRes) );
    b->numOfAddr = numOfAddr;
    b->addrPropagateArray = calloc(1, sizeof(void *) * numOfAddr);

    assert(b != NULL);
    assert(b->addrPropagateArray != NULL);

    for(int i = 0; i < numOfAddr; i++)
        b->addrPropagateArray[i] = NULL;
    return b;
}

void
delBufPropagate(BufPropagateRes **b)
{
    if(*b == NULL)
        return;

    free((*b)->addrPropagateArray);
    (*b)->addrPropagateArray = NULL;
    free(*b);
    *b = NULL;
    // printf("del BufPropagate\n");
}


void
print2ndLevelHash(Addr2NodeItem *src)
{
	Addr2NodeItem *dstNode;
	for(dstNode = src->subHash; dstNode != NULL; dstNode = dstNode->hh_addr2NodeItem.next) {
		printMemNode(dstNode->node);
	}
}

void
printTPMPropagateRes(TPMPropagateRes *t)
{
    if(t == NULL)
        return;

    for(int i = 0; i < t->bufTotal; i++) {
        printf("Buf propagate pointer:%p\n", t->tpmPropagateArray[i]);
        printBufPropagateRes(t->tpmPropagateArray[i]);
    }
}

void
printBufPropagateRes(BufPropagateRes *b)
{
    if(b == NULL)
        return;

    for(int i = 0; i < b->numOfAddr; i++) {
        printf("addr propagate pointer:%p\n", b->addrPropagateArray[i]);
    }
}

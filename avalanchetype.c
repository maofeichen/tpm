#include "avalanchetype.h"
#include <assert.h>
#include <stdio.h>

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

AddrPropgtToNode *
createAddrPropgtToNode(
    TPMNode2 *srcnode,
    AddrPropgtToNode *subBufHash,
    u32 dstBufID,
    TPMNode2 *propagtToNode)
{
  AddrPropgtToNode *a = calloc(1, sizeof(AddrPropgtToNode) );
  assert(a != NULL);
  a->srcnode = srcnode;
  a->subBufHash = subBufHash;
  a->dstBufID = dstBufID;
  a->propagtToNode = propagtToNode;
  return a;
}

// TPMPropagateRes *
// createTPMPropagate(int bufTotal)
// {
//   TPMPropagateRes *t = calloc(1, sizeof(TPMPropagateRes) );
//   t->numOfBuf = bufTotal;
//   t->tpmPropgtAry = calloc(1, sizeof(BufPropagateRes *) * bufTotal);

//   assert(t != NULL);
//   assert(t->tpmPropgtAry != NULL);

//   for(int i = 0; i < bufTotal; i++)
//     t->tpmPropgtAry[i] = NULL;
//   return t;
// }

u32
getTPMPropagateArrayIdx(u32 bufID)
{
  assert(bufID > 0);
  return bufID-1;
}

// void 
// delTPMPropagate(TPMPropagateRes *t)
// {
//   if(t == NULL)
//     return;

//   for(int i = 0; i < t->numOfBuf; i++){
//     delBufPropagate(&(t->tpmPropgtAry[i]) );
//   }

//   free(t->tpmPropgtAry);
//   t->tpmPropgtAry = NULL;
//   free(t);
//   printf("del TPMPropagateRes\n");
// }

// BufPropagateRes *
// createBufPropagate(u32 numOfAddr)
// {
//   BufPropagateRes *b = calloc(1, sizeof(BufPropagateRes) );
//   b->numOfAddr = numOfAddr;
//   b->addrPropgtAry = calloc(1, sizeof(AddrPropgtToNode *) * numOfAddr);

//   assert(b != NULL);
//   assert(b->addrPropgtAry != NULL);

//   for(int i = 0; i < numOfAddr; i++)
//     b->addrPropgtAry[i] = NULL;
//   return b;
// }

void
delBufPropagate(BufPropagateRes **b)
{
  if(*b == NULL)
    return;

  free((*b)->addrPropgtAry);
  (*b)->addrPropgtAry = NULL;
  free(*b);
  *b = NULL;
  // printf("del BufPropagate\n");
}

// TPMPropgtSearchCtxt *
// createTPMPropgtSearchCtxt(
//     TPMPropagateRes *tpmPropgtRes,
//     int maxSeqN)
// {
//   TPMPropgtSearchCtxt *t = calloc(1, sizeof(TPMPropgtSearchCtxt) );
//   assert(t != NULL);

//   t->tpmPropgt = tpmPropgtRes;
//   t->maxSeqN = maxSeqN;
//   return t;
// }

// void
// delTPMPropgtSearchCtxt(TPMPropgtSearchCtxt *t)
// {
//   if(t == NULL)
//     return;
//   free(t);
// }

void
print2ndLevelHash(Addr2NodeItem *src)
{
  Addr2NodeItem *dstNode;
  for(dstNode = src->subHash; dstNode != NULL; dstNode = dstNode->hh_addr2NodeItem.next) {
    printMemNode(dstNode->node);
  }
}

void
printTPMPropgtSearchCtxt(TPMPropgtSearchCtxt *t)
{
  if (t == NULL)
    return;
  printf("TPMPropgtSearchCtxt: maxSeqNo:%u TPMPropgtRes:%p\n", t->maxSeqN, t->tpmPropgt);
}


void
printTPMPropagateRes(TPMPropagateRes *t)
{
  if(t == NULL)
    return;

  for(int i = 0; i < t->numOfBuf; i++) {
    printf("Buf propagate pointer:%p\n", t->tpmPropgtAry[i]);
    printBufPropagateRes(t->tpmPropgtAry[i]);
  }
}

void
printBufPropagateRes(BufPropagateRes *b)
{
  if(b == NULL)
    return;

  for(int i = 0; i < b->numOfAddr; i++) {
    printf("addr propagate pointer:%p\n", b->addrPropgtAry[i]);
  }
}

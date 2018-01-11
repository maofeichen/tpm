#include "avalanchetype.h"

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

void 
print2ndLevelHash(Addr2NodeItem *src)
{
	Addr2NodeItem *dstNode;
	for(dstNode = src->subHash; dstNode != NULL; dstNode = dstNode->hh_addr2NodeItem.next) {
		printMemNode(dstNode->node);
	}
}

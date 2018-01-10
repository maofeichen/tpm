#include "avalanchetype.h"

void 
print2ndLevelHash(Addr2NodeItem *src)
{
	Addr2NodeItem *dstNode;
	for(dstNode = src->subHash; dstNode != NULL; dstNode = dstNode->hh_addr2NodeItem.next) {
		printMemNode(dstNode->node);
	}
}
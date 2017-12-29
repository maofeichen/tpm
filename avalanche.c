#include <stdbool.h>
#include <stdio.h>
#include "utlist.h"
#include "avalanche.h"

// static struct TPMNode2 * 
// memNodeReachBuf(TPMContext *tpm, struct AvalancheSearchCtxt *avalsctxt, struct TPMNode2 *srcNode, struct taintedBuf **dstBuf);
/* return:
    NULL: srcNode does not reach any node in the dstBuf
    else: pointer to the node in dstBuf that srcNode reaches
*/

// static int
// memNodePropagationSearch(struct AvalancheSearchCtxt *avalsctxt, struct TPMNode2 *srcNode, struct taintedBuf *dstBuf);

static Addr2NodeItem *
createAddr2NodeItem(u32 addr, TPMNode2 *memNode, Addr2NodeItem *subHash, TaintedBuf *toMemNode);

static int 
initSourceNode(u32 *srcAddr, TPMNode2 **srcNode);

static void 
printDstMemNodesHTTotal(Addr2NodeItem *dstMemNodesHT);

static void 
printDstMemNodesHT(Addr2NodeItem *dstMemNodesHT);

/* functions */
int
init_AvalancheSearchCtxt(struct AvalancheSearchCtxt **avalsctxt, u32 minBufferSz, struct TPMNode2 *srcBuf, 
			 struct TPMNode2 *dstBuf, u32 srcAddrStart, u32 srcAddrEnd, u32 dstAddrStart, u32 dstAddrEnd)
{
	*avalsctxt = malloc(sizeof(AvalancheSearchCtxt));
	memset(*avalsctxt, 0, sizeof(AvalancheSearchCtxt) );
	(*avalsctxt)->minBufferSz 	= minBufferSz;
	(*avalsctxt)->srcBuf 		= srcBuf;
	(*avalsctxt)->dstBuf 		= dstBuf;
	(*avalsctxt)->srcAddrStart 	= srcAddrStart;
	(*avalsctxt)->srcAddrEnd 	= srcAddrEnd;
	(*avalsctxt)->dstAddrStart 	= dstAddrStart;
	(*avalsctxt)->dstAddrEnd 	= dstAddrEnd;
	(*avalsctxt)->addr2Node		= NULL;
}

void
free_AvalancheSearchCtxt(struct AvalancheSearchCtxt *avalsctxt)
{
	free(avalsctxt);	
}


void 
searchAllAvalancheInTPM(TPMContext *tpm)
{
    AvalancheSearchCtxt *avalsctxt;
	TPMNode2 *srcBuf;

	/* test one buffer */
    srcBuf = mem2NodeSearch(tpm, 0xde911000);
    getMemNode1stVersion(&srcBuf);

    init_AvalancheSearchCtxt(&avalsctxt, 8, srcBuf, NULL, 0, 0, 0, 0);
    searchAvalancheInOutBuf(tpm, avalsctxt);
    free_AvalancheSearchCtxt(avalsctxt);    
}

int 
searchAvalancheInOutBuf(TPMContext *tpm, AvalancheSearchCtxt *avalsctxt)
{
	printf("begins to search avalanche between in and out buffers\n");

	TaintedBuf *lst_dstMemNodes, *itr;
	TPMNode2 *srcNode;
	u32 srcAddr;
	int count = 0;
	Addr2NodeItem *dstMemNodesHT = NULL;

	srcNode = avalsctxt->srcBuf;
	initSourceNode(&srcAddr, &srcNode);

	while(srcNode != NULL) {
		Addr2NodeItem *addrItem = createAddr2NodeItem(srcAddr, NULL, NULL, NULL);
		HASH_ADD(hh_addr2NodeItem, dstMemNodesHT, addr, 4, addrItem);	// 1st level hash: key: addr

		do {
			lst_dstMemNodes = NULL;
			memNodePropagate(tpm, srcNode, &lst_dstMemNodes);	// store result in utlist

#ifdef DEBUG
			LL_COUNT(lst_dstMemNodes, itr, count);
			printf("total item in list:%d\n", count);

			LL_FOREACH(lst_dstMemNodes, itr) {
				printf("propagate to addr:%x val:%x\n", itr->bufstart->addr, itr->bufstart->val);
			}
#endif
			Addr2NodeItem *srcNodePtr = createAddr2NodeItem(0, srcNode, NULL, lst_dstMemNodes);
			HASH_ADD(hh_addr2NodeItem, addrItem->subHash, node, 4, srcNodePtr);	// 2nd level hash: key: node ptr val: propagate dst mem nodes

			srcNode = srcNode->nextVersion;
		} while(srcNode->version != 0); // go through all versions of the src nodes

		srcNode = srcNode->rightNBR;
		initSourceNode(&srcAddr, &srcNode);
	}

	printDstMemNodesHTTotal(dstMemNodesHT);
	printDstMemNodesHT(dstMemNodesHT);
}

static Addr2NodeItem *
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

static int 
initSourceNode(u32 *srcAddr, TPMNode2 **srcNode)
// given a source node, get its 1st version, and init the srcAddr of the src node
{
	if(*srcNode == NULL) {
#ifdef DEBUG		
		fprintf(stderr, "error: init source node:%p\n", *srcNode);
#endif
		*srcAddr = 0;
		return -1;
	}

	getMemNode1stVersion(srcNode);
	*srcAddr = (*srcNode)->addr;
	return 0;
}

static void 
printDstMemNodesHTTotal(Addr2NodeItem *dstMemNodesHT)
{
	int totalItem;
	totalItem = HASH_CNT(hh_addr2NodeItem, dstMemNodesHT);
	printf("total addr item in hash table:%d\n", totalItem);
}

static void 
printDstMemNodesHT(Addr2NodeItem *dstMemNodesHT)
{
	Addr2NodeItem *item, *subitem, *temp, *subTemp;
	TaintedBuf *itr;
	int count, totalSubItem;

	HASH_ITER(hh_addr2NodeItem, dstMemNodesHT, item, temp) {
		totalSubItem = HASH_CNT(hh_addr2NodeItem, item->subHash);
		printf("total pointer item in sub hash table:%d\n", totalSubItem);
		HASH_ITER(hh_addr2NodeItem, item->subHash, subitem, subTemp) {
			TaintedBuf *dstBuf = subitem->toMemNode;
			LL_COUNT(dstBuf, itr, count);
			printf("total item in list:%d\n", count);

			// LL_FOREACH(dstBuf, itr) {
			// 	printf("propagate to addr:%x val:%x\n", itr->bufstart->addr, itr->bufstart->val);
			// }
		}
	}
}
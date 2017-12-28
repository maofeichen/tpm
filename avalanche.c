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
	printf("searching avalanche given in and out buffers\n");
	TaintedBuf *reachmemnode_list, *itr;
	TPMNode2 *srcNode;
	u32 srcAddr;
	int count = 0;

	Addr2NodeItem *item, *subitem, *temp, *subTemp;
	Addr2NodeItem *items = NULL;

	srcNode = avalsctxt->srcBuf;
	srcAddr = srcNode->addr;

	while(srcNode != NULL) {
		// srcNode = get_earliest_version(&srcNode);
		// srcAddr = srcNode->addr;

		Addr2NodeItem *i = malloc(sizeof(Addr2NodeItem) );
		i->addr = srcAddr;
		i->node = NULL;
		i->subHash = NULL;
		i->toMemNode = NULL;
		HASH_ADD(hh_addr2NodeItem, items, addr, 4, i);

		do {
			reachmemnode_list = NULL;
			memNodePropagate(tpm, srcNode, &reachmemnode_list);

			LL_COUNT(reachmemnode_list, itr, count);
			printf("total item in list:%d\n", count);

			// LL_FOREACH(reachmemnode_list, itr) {
			// 	printf("propagate to addr:%x val:%x\n", itr->bufstart->addr, itr->bufstart->val);
			// }

			Addr2NodeItem *s = malloc(sizeof(Addr2NodeItem) );
			s->addr = 0;
			s->node = srcNode;
			s->subHash = NULL;
			s->toMemNode = reachmemnode_list;
			HASH_ADD(hh_addr2NodeItem, i->subHash, node, 4, s);

			srcNode = srcNode->nextVersion;
		} while(srcNode->version != 0);

		srcNode = srcNode->rightNBR;
		if(srcNode != NULL) {
			getMemNode1stVersion(&srcNode);
			srcAddr = srcNode->addr;
		}
	}

	int totalItem, totalSubItem;
	totalItem = HASH_CNT(hh_addr2NodeItem, items);
	printf("total addr item in hash table:%d\n", totalItem);

	HASH_ITER(hh_addr2NodeItem, items, item, temp) {
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

#include "avalanche.h"
#include "utlist.h"
#include <stdbool.h>
#include "stdio.h"

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
searchAvalanche(TPMContext *tpm)
{
    AvalancheSearchCtxt *avalsctxt;
	TPMNode2 *source;

    source = mem2NodeSearch(tpm, 0xde911000);
    get_earliest_version(&source);

    init_AvalancheSearchCtxt(&avalsctxt, 8, source, NULL, 0, 0, 0, 0);
    searchAvalancheInOut(tpm, avalsctxt);
    free_AvalancheSearchCtxt(avalsctxt);    
}

int 
searchAvalancheInOut(TPMContext *tpm, AvalancheSearchCtxt *avalsctxt)
{
	printf("searching avalanche given in and out buffers\n");
	TaintedBuf *reachmemnode_list, *itr;
	TPMNode2 *srcNode;
	int count = 0;

	srcNode = avalsctxt->srcBuf;
	while(srcNode != NULL) {
		reachmemnode_list = NULL;
		memNodeReachBuf(tpm, srcNode, &reachmemnode_list);

		LL_COUNT(reachmemnode_list, itr, count);
		printf("total item in list:%d\n", count);

		// LL_FOREACH(reachmemnode_list, itr) {
		// 	printf("propagate to addr:%x val:%x\n", itr->bufstart->addr, itr->bufstart->val);
		// }

		srcNode = srcNode->rightNBR;
		if(srcNode != NULL)
			get_earliest_version(&srcNode);
	}
}

#include <stdbool.h>
#include "avalanche.h"

int
init_AvalancheSearchCtxt(struct AvalancheSearchCtxt *avalsctxt, u32 minBufferSz, struct TPMNode2 *srcBuf, 
			 struct TPMNode2 *dstBuf, u32 srcAddrStart, u32 srcAddrEnd, u32 dstAddrStart, u32 dstAddrEnd)
{
	avalsctxt = malloc(sizeof(AvalancheSearchCtxt));
	memset(avalsctxt, 0, sizeof(AvalancheSearchCtxt) );
	avalsctxt->minBufferSz 	= minBufferSz;
	avalsctxt->srcBuf 		= srcBuf;
	avalsctxt->dstBuf 		= dstBuf;
	avalsctxt->srcAddrStart = srcAddrStart;
	avalsctxt->srcAddrEnd 	= srcAddrEnd;
	avalsctxt->dstAddrStart = dstAddrStart;
	avalsctxt->dstAddrEnd 	= dstAddrEnd;
}

void
free_AvalancheSearchCtxt(struct AvalancheSearchCtxt *avalsctxt)
{
	// free(avalsctxt);	
}

int 
searchAvalancheInOut(AvalancheSearchCtxt *avalsctxt)
{
	printf("searching avalanche given in and out buffers\n");	
}
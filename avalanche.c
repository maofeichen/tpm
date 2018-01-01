#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include "utlist.h"
#include "avalanche.h"
#include "continbuf.h"

// static struct TPMNode2 * 
// memNodeReachBuf(TPMContext *tpm, struct AvalancheSearchCtxt *avalsctxt, struct TPMNode2 *srcNode, struct taintedBuf **dstBuf);
/* return:
    NULL: srcNode does not reach any node in the dstBuf
    else: pointer to the node in dstBuf that srcNode reaches
*/

// static int
// memNodePropagationSearch(struct AvalancheSearchCtxt *avalsctxt, struct TPMNode2 *srcNode, struct taintedBuf *dstBuf);

/* search propagation of in to the out buffers */
static void 
searchPropagateInOutBuf(TPMContext *tpm, AvalancheSearchCtxt *avalsctxt, Addr2NodeItem **dstMemNodesHT);

static Addr2NodeItem *
createAddr2NodeItem(u32 addr, TPMNode2 *memNode, Addr2NodeItem *subHash, TaintedBuf *toMemNode);

static int 
initSourceNode(u32 *srcAddr, TPMNode2 **srcNode);

/* detect avalanche of in buffer*/
static void 
detectAvalancheInOutBuf(TPMContext *tpm, AvalancheSearchCtxt *avalsctxt);

static void 
detectAvalancheOfSource(AvalancheSearchCtxt *avalsctxt, Addr2NodeItem *sourceNode, Addr2NodeItem *addrHashStartSearch);

static void 
storeAllAddrHashChildren(Addr2NodeItem *addrHash);

static AvalDstBufHTNode *
createAvalDstBufHTNode(TPMNode2 *dstNode, u32 hitcnt);

static int 
cmpAvalDstBufHTNode(AvalDstBufHTNode *l, AvalDstBufHTNode *r);

static void 
initDstMemNodeHT(TaintedBuf *dstMemNodesLst, u32 dstAddrStart, u32 dstAddrEnd, AvalDstBufHTNode **avalDstBufHT);

static ContinBufAry *
buildContinBufAry(AvalDstBufHTNode *dstMemNodesHT);

static bool 
isInMemRange(TPMNode2 *node, u32 addrBegin, u32 addrEnd);

static void 
t_createDstContinBuf(AvalDstBufHTNode *dstMemNodesHT);

/* Stack of Addr2NodeItem operaion */
StackAddr2NodeItem *stackAddr2NodeItemTop = NULL;
u32 stackAddr2NodeItemCount = 0;

static void 
addr2NodeItemStackPush(Addr2NodeItem *addr2NodeItem);

static Addr2NodeItem *
addr2NodeItemStackPop();

static void 
addr2NodeItemStackDisplay();

static void 
addr2NodeItemStackPopAll();

static bool 
isAddr2NodeItemStackEmpty();

/* print */
static void 
printDstMemNodesHTTotal(Addr2NodeItem *dstMemNodesHT);

static void 
printDstMemNodesHT(Addr2NodeItem *dstMemNodesHT);

static void 
printDstMemNodesListTotal(TaintedBuf *lst_dstMemNodes);

static void 
printDstMemNodesList(TaintedBuf *lst_dstMemNodes);

static void 
printAvalDstBufHTTotal(AvalDstBufHTNode *avalDstBufHT);

static void 
printAvalDstBufHT(AvalDstBufHTNode *avalDstBufHT);

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
	searchPropagateInOutBuf(tpm, avalsctxt, &(avalsctxt->addr2Node) );
#ifdef DEBUG
	printDstMemNodesHTTotal(avalsctxt->addr2Node);
	printDstMemNodesHT(avalsctxt->addr2Node);
#endif
	detectAvalancheInOutBuf(tpm, avalsctxt);
}

static void 
searchPropagateInOutBuf(TPMContext *tpm, AvalancheSearchCtxt *avalsctxt, Addr2NodeItem **dstMemNodesHT)
// Searches propagations of source buffer (all version of each node), results store in dstMemNodesHT
{
	TPMNode2 *srcNode;
	u32 srcAddr;
	int srcNodeHitcnt = 0;
	TaintedBuf *dstMemNodesLst;

	srcNode = avalsctxt->srcBuf;
	initSourceNode(&srcAddr, &srcNode);

	while(srcNode != NULL) {
		Addr2NodeItem *addrItem = createAddr2NodeItem(srcAddr, NULL, NULL, NULL);
		HASH_ADD(hh_addr2NodeItem, *dstMemNodesHT, addr, 4, addrItem);	// 1st level hash: key: addr

		do {
			dstMemNodesLst = NULL;
			srcNodeHitcnt = memNodePropagate(tpm, srcNode, &dstMemNodesLst);	// store result in utlist
			srcNode->hitcnt = srcNodeHitcnt;
#ifdef DEBUG
			printf("source node hit count:%d\n", srcNodeHitcnt);
			printDstMemNodesListTotal(dstMemNodesLst);
			printDstMemNodesList(dstMemNodesLst);
#endif
			Addr2NodeItem *srcNodePtr = createAddr2NodeItem(0, srcNode, NULL, dstMemNodesLst);
			HASH_ADD(hh_addr2NodeItem, addrItem->subHash, node, 4, srcNodePtr);	// 2nd level hash: key: node ptr val: propagate dst mem nodes

			srcNode = srcNode->nextVersion;
		} while(srcNode->version != 0); // go through all versions of the src nodes

		srcNode = srcNode->rightNBR;
		initSourceNode(&srcAddr, &srcNode);
	}
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
detectAvalancheInOutBuf(TPMContext *tpm, AvalancheSearchCtxt *avalsctxt)
{

	Addr2NodeItem *item, *subitem, *temp, *subTemp;

	HASH_ITER(hh_addr2NodeItem, avalsctxt->addr2Node, item, temp) { // for each addr
		HASH_ITER(hh_addr2NodeItem, item->subHash, subitem, subTemp) { // for each version node
			Addr2NodeItem *next = item->hh_addr2NodeItem.next;
			detectAvalancheOfSource(avalsctxt, subitem, next);
			break;
		}
		break;
	}
}

static void 
detectAvalancheOfSource(AvalancheSearchCtxt *avalsctxt, Addr2NodeItem *sourceNode, Addr2NodeItem *addrHashStartSrch)
{
	AvalDstBufHTNode *avalDstBufHT = NULL;
	TaintedBuf *dstMemNodesLst;
	ContinBufAry *contBufAry;

	dstMemNodesLst = sourceNode->toMemNode;
	initDstMemNodeHT(dstMemNodesLst, 0x804c170, 0x804c1B0, &avalDstBufHT);
	contBufAry = buildContinBufAry(avalDstBufHT);
	// t_createDstContinBuf(avalDstBufHT);

#ifdef DEBUG
	printAvalDstBufHTTotal(avalDstBufHT);
	printAvalDstBufHT(avalDstBufHT);
	printContinBufAry(contBufAry);
#endif

	stackAddr2NodeItemTop = NULL;
	u32 currSearchAddr = addrHashStartSrch->addr;
	storeAllAddrHashChildren(addrHashStartSrch);
	while(!isAddr2NodeItemStackEmpty() ) {
		Addr2NodeItem *nodeHash = addr2NodeItemStackPop();
		printf("node ptr:%p - node addr:%x - dstMemNodesLst ptr:%p\n", nodeHash->node, nodeHash->node->addr, nodeHash->toMemNode);

		if(addrHashStartSrch != NULL) {
			addrHashStartSrch = addrHashStartSrch->hh_addr2NodeItem.next;
			if(addrHashStartSrch != NULL 
			   && addrHashStartSrch->addr > currSearchAddr) { // for each addr hash, only push its sub hash nodes once (at first time)
				storeAllAddrHashChildren(addrHashStartSrch);
				currSearchAddr = addrHashStartSrch->addr;
			}
		}
	}
}

static void 
storeAllAddrHashChildren(Addr2NodeItem *addrHash)
// No need mark visited node, because for each addr hash, only need to
// push once 
{
	Addr2NodeItem *nodeHash;
	for(nodeHash = addrHash->subHash; nodeHash != NULL; nodeHash = nodeHash->hh_addr2NodeItem.next) {
		addr2NodeItemStackPush(nodeHash);	
	}
}

static AvalDstBufHTNode *
createAvalDstBufHTNode(TPMNode2 *dstNode, u32 hitcnt)
{
	AvalDstBufHTNode *i = NULL;
	i = malloc(sizeof(AvalDstBufHTNode) );
	i->dstNode = dstNode;
	i->hitcnt = hitcnt;
	return i;
}

static int 
cmpAvalDstBufHTNode(AvalDstBufHTNode *l, AvalDstBufHTNode *r)
{
	if(l->dstNode->addr < r->dstNode->addr) { return -1; }
	else if(l->dstNode->addr == r->dstNode->addr) { return 0; }
	else { return 1; }
}

static void 
initDstMemNodeHT(TaintedBuf *dstMemNodesLst, u32 dstAddrStart, u32 dstAddrEnd, AvalDstBufHTNode **avalDstBufHT)
{
	TaintedBuf *itr;

	LL_FOREACH(dstMemNodesLst, itr) {
		if(isInMemRange(itr->bufstart, dstAddrStart, dstAddrEnd) ) {
			AvalDstBufHTNode *dstMemNode = createAvalDstBufHTNode(itr->bufstart, 0);
			HASH_ADD(hh_avalDstBufHTNode, *avalDstBufHT, dstNode, 4, dstMemNode);
		}
	}
	HASH_SRT(hh_avalDstBufHTNode, *avalDstBufHT, cmpAvalDstBufHTNode);
}

static ContinBufAry *
buildContinBufAry(AvalDstBufHTNode *dstMemNodesHT)
// Returns:
//	Continuous buffers array, based on the dst mem nodes hash table
{
	ContinBufAry *contBufAry;
	ContinBuf *contBuf;
	AvalDstBufHTNode *item, *temp;

	contBufAry = initContBufAry();
	contBuf = initContinBuf();

	// init first node
	u32 bufstart = dstMemNodesHT->dstNode->addr; 
	u32 bufsz    = dstMemNodesHT->dstNode->bytesz;
	extendContinBuf(contBuf, dstMemNodesHT->dstNode);

	for(item = dstMemNodesHT->hh_avalDstBufHTNode.next; item != NULL; item = item->hh_avalDstBufHTNode.next) {
		// printf("addr:%x size:%u\n", item->dstNode->addr, item->dstNode->bytesz);

		TPMNode2 *dstNode = item->dstNode;
		u32 currNodeStart = dstNode->addr;
		u32 currBufRange = bufstart + bufsz;

		if(currBufRange > currNodeStart) {
			// TODO: propagate to multiple version of same addr, handles latter
			printf("buildContinBufAry: TODO: multiple version of same addr:%x\n", currNodeStart);
		}
		else if(currBufRange == currNodeStart) {
			extendContinBuf(contBuf, item->dstNode);
			bufsz += item->dstNode->bytesz;
		}
		else { // a new buffer
			appendContBufAry(contBufAry, contBuf);
			contBuf = initContinBuf();
			extendContinBuf(contBuf, dstNode);

			bufstart = dstNode->addr;
			bufsz = dstNode->bytesz;
		} 
	}

	appendContBufAry(contBufAry, contBuf);	// add the last continuous buffer
	return contBufAry;
}

static bool 
isInMemRange(TPMNode2 *node, u32 addrBegin, u32 addrEnd)
{
	assert(node != NULL);
	if(node->addr >= addrBegin && node->addr <= addrEnd) { return true; }
	else { return false; }
}

static void 
t_createDstContinBuf(AvalDstBufHTNode *dstMemNodesHT)
{
	ContinBuf *continBuf_l = NULL, *continBuf_r;
	ContinBufAry *contBufAry_l = NULL, *contBufAry_r = NULL, *bufAryIntersect;
	AvalDstBufHTNode *item, *temp;

	/* test cont buf*/
	continBuf_l = initContinBuf();
	// printContinBuf(continBuf_l);
	HASH_ITER(hh_avalDstBufHTNode, dstMemNodesHT, item, temp) {
		// printf("addr:0x%x - ptr:%p\n", item->dstNode->addr, item->dstNode);
		extendContinBuf(continBuf_l, item->dstNode);
		// break;
	}
	// printContinBuf(continBuf_l);

	continBuf_r = initContinBuf();
	int i = 0;
	HASH_ITER(hh_avalDstBufHTNode, dstMemNodesHT, item, temp) {
		// printf("addr:0x%x - ptr:%p\n", item->dstNode->addr, item->dstNode);
		if(i == 0) {
			i++;
			continue;
		}
		extendContinBuf(continBuf_r, item->dstNode);
		i++;
		if(i == 2)
			break;
	}

	/* test cont buf ary*/
	contBufAry_l = initContBufAry();
	// printContinBufAry(contBufAry_l);
	appendContBufAry(contBufAry_l, continBuf_l);
	printContinBufAry(contBufAry_l);

	contBufAry_r = initContBufAry();
	appendContBufAry(contBufAry_r, continBuf_r);
	printContinBufAry(contBufAry_r);

	bufAryIntersect = getBufAryIntersect(contBufAry_l, contBufAry_r);
	printf("Intersect buf ary:\n");
	printContinBufAry(bufAryIntersect);

	delContinBufAry(&contBufAry_l);
	delContinBufAry(&contBufAry_r);
	// printContinBufAry(contBufAry_l);
}

static void
addr2NodeItemStackPush(Addr2NodeItem *addr2NodeItem)
{
	StackAddr2NodeItem *n = calloc(1, sizeof(StackAddr2NodeItem) );
	n->addr2NodeItem = addr2NodeItem;
	n->next = stackAddr2NodeItemTop;
	stackAddr2NodeItemTop = n;
	stackAddr2NodeItemCount++;
}

static Addr2NodeItem *
addr2NodeItemStackPop()
{
	StackAddr2NodeItem *toDel;
	Addr2NodeItem *addr2NodeItem = NULL;

	if(stackAddr2NodeItemTop != NULL) {
		toDel = stackAddr2NodeItemTop;
		stackAddr2NodeItemTop = toDel->next;
		addr2NodeItem = toDel->addr2NodeItem;
		free(toDel);
		stackAddr2NodeItemCount--;
	}
	return addr2NodeItem;
}

static void 
addr2NodeItemStackDisplay()
{
	StackAddr2NodeItem *n = stackAddr2NodeItemTop;
	while(n != NULL) {
		printf("addr2NodeItem:%p - node ptr:%p - node addr:%x - dstMemNodesLst:%p\n", 
			n->addr2NodeItem, n->addr2NodeItem->node, n->addr2NodeItem->node->addr, n->addr2NodeItem->toMemNode);
		n = n->next;
	}
}

static void 
addr2NodeItemStackPopAll()
{
	while(stackAddr2NodeItemTop != NULL) {
		addr2NodeItemStackPop();
	}
}

static bool 
isAddr2NodeItemStackEmpty()
{
	if(stackAddr2NodeItemTop == NULL)
		return true;
	else
		return false;	
}

static void 
printDstMemNodesHTTotal(Addr2NodeItem *dstMemNodesHT)
{
	int total;
	total = HASH_CNT(hh_addr2NodeItem, dstMemNodesHT);
	printf("total addr item in hash table:%d\n", total);
}

static void 
printDstMemNodesHT(Addr2NodeItem *dstMemNodesHT)
{
	Addr2NodeItem *item, *subitem, *temp, *subTemp;
	TaintedBuf *itr;
	int count, totalSubItem;

	HASH_ITER(hh_addr2NodeItem, dstMemNodesHT, item, temp) {
		totalSubItem = HASH_CNT(hh_addr2NodeItem, item->subHash);
		printf("addr:0x%x - total pointer item in sub hash table:%d\n", item->addr, totalSubItem);
		HASH_ITER(hh_addr2NodeItem, item->subHash, subitem, subTemp) {
			TaintedBuf *dstMemNodesLst = subitem->toMemNode;
			printf("addr:%-8x version:%u - ", (subitem->node)->addr, (subitem->node)->version);
			LL_COUNT(dstMemNodesLst, itr, count);
			printf("total propagate destination mem nodes:%d\n", count);
			printDstMemNodesList(dstMemNodesLst);
		}
	}
}

static void 
printDstMemNodesListTotal(TaintedBuf *dstMemNodesLst)
{	
	int count;
	TaintedBuf *itr;

	LL_COUNT(dstMemNodesLst, itr, count);
	printf("total item in list:%d\n", count);
}

static void 
printDstMemNodesList(TaintedBuf *dstMemNodesLst)
{
	TaintedBuf *itr;

	LL_FOREACH(dstMemNodesLst, itr) {
		printf("\t-> addr:%-8x val:%-8x\n", itr->bufstart->addr, itr->bufstart->val);
	}
}

static void 
printAvalDstBufHTTotal(AvalDstBufHTNode *avalDstBufHT)
{
	int total;
	total = HASH_CNT(hh_avalDstBufHTNode, avalDstBufHT);
	printf("total nodes in destination range:%d\n", total);
}

static void 
printAvalDstBufHT(AvalDstBufHTNode *avalDstBufHT)
{
	AvalDstBufHTNode *item, *temp;
	HASH_ITER(hh_avalDstBufHTNode, avalDstBufHT, item, temp) {
		printf("addr:0x%x - ptr:%p\n", item->dstNode->addr, item->dstNode);
	}
}
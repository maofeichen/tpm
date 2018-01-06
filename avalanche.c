#include <assert.h>
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



/* avalanche context */
static void 
setSeqNo(AvalancheSearchCtxt *avalsctxt, int srcMinSeqN, int srcMaxSeqN, int dstMinSeqN, int dstMaxSeqN);

/* search propagation of in to the out buffers */
static void 
searchPropagateInOutBuf(TPMContext *tpm, AvalancheSearchCtxt *avalsctxt, Addr2NodeItem **dstMemNodesHT, PropagateStat *propaStat);

static Addr2NodeItem *
createAddr2NodeItem(u32 addr, TPMNode2 *memNode, Addr2NodeItem *subHash, TaintedBuf *toMemNode);

static int 
initSourceNode(u32 *srcAddr, TPMNode2 **srcNode);

/* detect avalanche of in buffer */
static void 
detectAvalancheInOutBuf(TPMContext *tpm, AvalancheSearchCtxt *avalsctxt);

/* detects avalanche given one source node in the in buffer */
static void 
detectAvalancheOfSource(AvalancheSearchCtxt *avalsctxt, Addr2NodeItem *sourceNode, Addr2NodeItem *addrHashStartSearch, u32 *numOfAddrAdvanced);

static void 
storeAllAddrHashChildren(Addr2NodeItem *addrHash, StackAddr2NodeItem **stackAddr2NodeItemTop, u32 *stackAddr2NodeItemCount);

static void 
initDstMemNodeHT(TaintedBuf *dstMemNodesLst, u32 dstAddrStart, u32 dstAddrEnd, AvalDstBufHTNode **avalDstBufHT);

static AvalDstBufHTNode *
createAvalDstBufHTNode(TPMNode2 *dstNode, u32 hitcnt);

static int 
cmpAvalDstBufHTNode(AvalDstBufHTNode *l, AvalDstBufHTNode *r);

static AvalDstBufHTNode *
intersectDstMemNodeHT(TaintedBuf *dstMemNodesLst, AvalDstBufHTNode *avalDstBufHT);

static void 
initDstBufHTNodeHitcnt(AvalDstBufHTNode *avalDstBufHT);

static ContinBufAry *
buildContinBufAry(AvalDstBufHTNode *dstMemNodesHT);

static bool 
isInMemRange(TPMNode2 *node, u32 addrBegin, u32 addrEnd);

static void 
test_createDstContinBuf(AvalDstBufHTNode *dstMemNodesHT);

/* Stack of Addr2NodeItem operaion */
static void 
addr2NodeItemStackPush(StackAddr2NodeItem **stackAddr2NodeItemTop, u32 *stackAddr2NodeItemCount, Addr2NodeItem *addr2NodeItem);

static Addr2NodeItem *
addr2NodeItemStackPop(StackAddr2NodeItem **stackAddr2NodeItemTop, u32 *stackAddr2NodeItemCount);

static void 
addr2NodeItemStackDisplay(StackAddr2NodeItem *stackAddr2NodeItemTop);

static void 
addr2NodeItemStackDispRange(StackAddr2NodeItem *stackAddr2NodeItemTop, char *s);

static void 
addr2NodeItemStackPopAll(StackAddr2NodeItem **stackAddr2NodeItemTop, u32 *stackAddr2NodeItemCount);

static bool 
isAddr2NodeItemStackEmpty(StackAddr2NodeItem *stackAddr2NodeItemTop);

/* Stack of destination buf hash table operation */
static void 
dstBufHTStackPush(StackDstBufHT **stackDstBufHTTop, u32 *stackDstBufHTCount, AvalDstBufHTNode *dstBufHT);

static AvalDstBufHTNode *
dstBufHTStackPop(StackDstBufHT **stackDstBufHTTop, u32 *stackDstBufHTCount);

/* Stack of buf array operations */
static void 
bufAryStackPush(StackBufAry **stackBufAryTop, u32 *stackBufAryCnt, ContinBufAry *contBufAry);

static ContinBufAry *
bufAryStackPop(StackBufAry **stackBufAryTop, u32 *stackBufAryCnt);

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
	*avalsctxt = calloc(1, sizeof(AvalancheSearchCtxt));
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
    TPMBufHashTable *tpmBufHT, *srcBuf, *dstBuf;
	// TPMNode2 *srcBuf;

	tpmBufHT = getAllTPMBuf(tpm);
	// printTPMBufHT(tpmBufHT);

	PropagateStat propaStat = {0};

	for(srcBuf = tpmBufHT; srcBuf != NULL; srcBuf = srcBuf->hh_tpmBufHT.next) {
		for(dstBuf = srcBuf->hh_tpmBufHT.next; dstBuf != NULL; dstBuf = dstBuf->hh_tpmBufHT.next) {
			if(srcBuf->baddr == 0xde911000 && dstBuf->baddr == 0x804c170){ // test signle buf
	            init_AvalancheSearchCtxt(&avalsctxt, MIN_BUF_SZ, srcBuf->headNode, dstBuf->headNode, srcBuf->baddr, srcBuf->eaddr, dstBuf->baddr, dstBuf->eaddr);
				setSeqNo(avalsctxt, srcBuf->minseq, srcBuf->maxseq, dstBuf->minseq, dstBuf->maxseq);
	    		searchAvalancheInOutBuf(tpm, avalsctxt, &propaStat);
	    		free_AvalancheSearchCtxt(avalsctxt);   
				goto OUTLOOP;
			}
#ifdef DEBUG
			init_AvalancheSearchCtxt(&avalsctxt, MIN_BUF_SZ, srcBuf->headNode, dstBuf->headNode, srcBuf->baddr, srcBuf->eaddr, dstBuf->baddr, dstBuf->eaddr);
			setSeqNo(avalsctxt, srcBuf->minseq, srcBuf->maxseq, dstBuf->minseq, dstBuf->maxseq);
	    	searchAvalancheInOutBuf(tpm, avalsctxt, &propaStat);
	    	free_AvalancheSearchCtxt(avalsctxt);     
#endif
		}
	}
OUTLOOP:
	printf("out of loop\n");
	// printf("minstep:%u maxstep:%u avgstep:%u\n", 
	// 	propaStat.minstep, propaStat.maxstep, propaStat.totalstep / propaStat.numOfSearch);

	/* test one buffer */
    // srcBuf = mem2NodeSearch(tpm, 0xde911000);
    // getMemNode1stVersion(&srcBuf);
    // init_AvalancheSearchCtxt(&avalsctxt, 8, srcBuf, NULL, 0, 0, 0, 0);
    // searchAvalancheInOutBuf(tpm, avalsctxt);
    // free_AvalancheSearchCtxt(avalsctxt);    
}

int 
searchAvalancheInOutBuf(TPMContext *tpm, AvalancheSearchCtxt *avalsctxt, PropagateStat *propaStat)
{
	printf("----------------------------------------\n");
	printf("src buf: start:%-8x end:%-8x sz:%u minseq:%d maxseq:%d diffSeq:%d\n", 
		avalsctxt->srcAddrStart, avalsctxt->srcAddrEnd, avalsctxt->srcAddrEnd - avalsctxt->srcAddrStart, 
		avalsctxt->srcMinSeqN, avalsctxt->srcMaxSeqN, avalsctxt->srcMaxSeqN - avalsctxt->srcMinSeqN);
	printf("dst buf: start:%-8x end:%-8x sz:%u minseq:%d maxseq:%d diffSeq:%d\n", 
		avalsctxt->dstAddrStart, avalsctxt->dstAddrEnd, avalsctxt->dstAddrEnd - avalsctxt->dstAddrStart, 
		avalsctxt->dstMinSeqN, avalsctxt->dstMaxSeqN, avalsctxt->dstMaxSeqN - avalsctxt->dstMinSeqN);
	searchPropagateInOutBuf(tpm, avalsctxt, &(avalsctxt->addr2Node), propaStat);
#ifdef DEBUG
	printDstMemNodesHTTotal(avalsctxt->addr2Node);
	printDstMemNodesHT(avalsctxt->addr2Node);
#endif
	detectAvalancheInOutBuf(tpm, avalsctxt);
}

static void 
setSeqNo(AvalancheSearchCtxt *avalsctxt, int srcMinSeqN, int srcMaxSeqN, int dstMinSeqN, int dstMaxSeqN)
{
	avalsctxt->srcMinSeqN = srcMinSeqN;
	avalsctxt->srcMaxSeqN = srcMaxSeqN;
	avalsctxt->dstMinSeqN = dstMinSeqN;
	avalsctxt->dstMaxSeqN = dstMaxSeqN;
}

static void 
searchPropagateInOutBuf(TPMContext *tpm, AvalancheSearchCtxt *avalsctxt, Addr2NodeItem **dstMemNodesHT, PropagateStat *propaStat)
// Searches propagations of source buffer (all version of each node), results store in dstMemNodesHT
{
	TPMNode2 *srcNode;
	u32 srcAddr;
	int srcNodeHitByte = 0;
	TaintedBuf *dstMemNodesLst;

	srcNode = avalsctxt->srcBuf;
	initSourceNode(&srcAddr, &srcNode);

	u32 stepCount;

	while(srcNode != NULL) {
		Addr2NodeItem *addrItem = createAddr2NodeItem(srcAddr, NULL, NULL, NULL);
		HASH_ADD(hh_addr2NodeItem, *dstMemNodesHT, addr, 4, addrItem);	// 1st level hash: key: addr

		do {
			dstMemNodesLst = NULL;
			// store result in utlist
			stepCount = 0;
			srcNodeHitByte = memNodePropagate(tpm, srcNode, &dstMemNodesLst, 
				avalsctxt->dstAddrStart, avalsctxt->dstAddrEnd, avalsctxt->dstMinSeqN, 
				avalsctxt->dstMaxSeqN, &stepCount);	
			srcNode->hitcnt = srcNodeHitByte;

			if(propaStat->numOfSearch == 0)
				propaStat->minstep = stepCount;

			propaStat->numOfSearch += 1;
			propaStat->totalstep += stepCount;
			if(propaStat->minstep > stepCount)
				propaStat->minstep = stepCount;
			if(propaStat->maxstep < stepCount)
				propaStat->maxstep = stepCount; 
#ifdef DEBUG
			printf("source node hit bytesz:%d\n", srcNodeHitByte);
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
	u32 maxNumOfAddrAdvanced = 0, numOfAddrAdvanced = 0;

	Addr2NodeItem *addrHash, *nodeHash;
	for(addrHash = avalsctxt->addr2Node; addrHash != NULL; addrHash = addrHash->hh_addr2NodeItem.next) {
		// printf("addr:%x\n", addrHash->addr);
		for(nodeHash = addrHash->subHash; nodeHash != NULL; nodeHash = nodeHash->hh_addr2NodeItem.next) {
			TPMNode2 *node = nodeHash->node;
			// printf("addr:%x ver:%u\n", node->addr, node->version);

			if(addrHash->hh_addr2NodeItem.next != NULL) { // if has right neighbor addr
				Addr2NodeItem *next = addrHash->hh_addr2NodeItem.next;
				detectAvalancheOfSource(avalsctxt, nodeHash, next, &numOfAddrAdvanced);

				if(numOfAddrAdvanced > maxNumOfAddrAdvanced)
					maxNumOfAddrAdvanced = numOfAddrAdvanced;
			}
		}

		while(maxNumOfAddrAdvanced-1 > 0) {
			if(addrHash->hh_addr2NodeItem.next != NULL)
				addrHash = addrHash->hh_addr2NodeItem.next;
			maxNumOfAddrAdvanced--;
		}
	}
}

static void 
detectAvalancheOfSource(AvalancheSearchCtxt *avalsctxt, Addr2NodeItem *sourceNode, Addr2NodeItem *addrHashStartSearch, u32 *numOfAddrAdvanced)
// Given a single node in the 2-level hash table, searches itself and its rest addresses nodes has avalanche effect.
// addr first version second search (dfs)
{

	StackAddr2NodeItem *stackTraverseTop = NULL; // maintains the nodes during search
	u32 stackTraverseCount = 0;

	StackAddr2NodeItem *stackSourceTop = NULL; // maintains the source nodes that has avalanche
	u32 stackSourceCount = 0;

	StackDstBufHT *stackDstBufHTTop = NULL; // maintains the accumulated buf hash table, 
	u32 stackDstBufHTCnt = 0;				// for source nodes propagate to common dst node, store in hash table

	StackBufAry *stackBufAryTop = NULL;	// maintains the accumulated buf array
	u32 stackBufAryCnt = 0;				// for source node propagate to common bufs, store in buf ary

	AvalDstBufHTNode *oldAvalDstBufHT = NULL;
	AvalDstBufHTNode *newAvalDstBufHT = NULL;

	ContinBufAry *oldContBufAry, *extendBufAry, *newContBufAry;

	TaintedBuf *dstMemNodesLst;

	dstMemNodesLst = sourceNode->toMemNode;

	if(dstMemNodesLst == NULL)
		return;

	// initDstMemNodeHT(dstMemNodesLst, 0x804c170, 0x804c1B0, &oldAvalDstBufHT); // TODO: intersect with dst buf range
	initDstMemNodeHT(dstMemNodesLst, avalsctxt->dstAddrStart, avalsctxt->dstAddrEnd, &oldAvalDstBufHT); // TODO: intersect with dst buf range
	dstBufHTStackPush(&stackDstBufHTTop, &stackDstBufHTCnt, oldAvalDstBufHT); // stores source node's propagation that common with dst buf

	if(HASH_CNT(hh_avalDstBufHTNode, oldAvalDstBufHT) == 0)
		return;

	oldContBufAry = buildContinBufAry(oldAvalDstBufHT);	// init the buf ary based on the dst buf hash table
	bufAryStackPush(&stackBufAryTop, &stackBufAryCnt, oldContBufAry);

	if(!hasMinSzContBuf(oldContBufAry, 8)) {	// if the init node doesn't has mim buf sz, no need to search
		// TODO: del all stacks; hard code 8
		return;
	}

#ifdef DEBUG
	printAvalDstBufHTTotal(oldAvalDstBufHT);
	printAvalDstBufHT(oldAvalDstBufHT);
	printContinBufAry(oldContBufAry);
#endif

	addr2NodeItemStackPush(&stackSourceTop, &stackSourceCount, sourceNode); // stores souce node 
	u32 currTraverseAddr = addrHashStartSearch->addr;	// tracks the current traverse addr
	storeAllAddrHashChildren(addrHashStartSearch, &stackTraverseTop, &stackTraverseCount); // stores all verson nodes of source' right neighbor addr

	while(!isAddr2NodeItemStackEmpty(stackTraverseTop) ) { // simulates dfs search
		Addr2NodeItem *nodeHash = addr2NodeItemStackPop(&stackTraverseTop, &stackTraverseCount);
		// printf("node ptr:%p - node addr:%x - dstMemNodesLst ptr:%p\n", nodeHash->node, nodeHash->node->addr, nodeHash->toMemNode);

		if(currTraverseAddr > nodeHash->node->addr) { // no further addr can explore, step back, already find longest posible source range, 
													  // can stop due to prefer longest input buffer
			*numOfAddrAdvanced = stackSourceCount;	// num of addr advanced
			if(stackSourceCount > 1) {
				printf("--------------------\n");		  
				addr2NodeItemStackDispRange(stackSourceTop, "avalanche found:\nsrc buf:");
				printf("aval to dst buf:\n");
				printContBufAry_lit("\t", oldContBufAry);
			}
			break;
			// TODO: clean
		}

		dstMemNodesLst = nodeHash->toMemNode;
		newAvalDstBufHT = intersectDstMemNodeHT(dstMemNodesLst, oldAvalDstBufHT);
		if(HASH_CNT(hh_avalDstBufHTNode, newAvalDstBufHT) == 0 )	// the new node doesn't has common with the current nodes, skip
			continue;

		extendBufAry = buildContinBufAry(newAvalDstBufHT);
		newContBufAry = getBufAryIntersect(oldContBufAry, extendBufAry);

		if(!hasMinSzContBuf(newContBufAry, 8)) {
			continue;
			// TODO: old will not change, free new, do sth?
		}

		// accumulates the new node
		addr2NodeItemStackPush(&stackSourceTop, &stackSourceCount, nodeHash);
		dstBufHTStackPush(&stackDstBufHTTop, &stackDstBufHTCnt, newAvalDstBufHT);
		bufAryStackPush(&stackBufAryTop, &stackBufAryCnt, newContBufAry);

		// update the old state to new
		oldAvalDstBufHT = newAvalDstBufHT;
		oldContBufAry	= newContBufAry;

		// stores all version nodes of right neighbor addr 
		if(addrHashStartSearch->hh_addr2NodeItem.next != NULL) {
			addrHashStartSearch = addrHashStartSearch->hh_addr2NodeItem.next;
			if(addrHashStartSearch->addr > currTraverseAddr) { // for each addr hash, only push its sub hash nodes once (at first time)
				storeAllAddrHashChildren(addrHashStartSearch, &stackTraverseTop, &stackTraverseCount);
				currTraverseAddr = addrHashStartSearch->addr;
			}
		}
	}
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
	// if(dstMemNodesHT == NULL)
	// 	return NULL;

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
			// printf("buildContinBufAry: TODO: multiple version of same addr:%x\n", currNodeStart);
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

static void 
storeAllAddrHashChildren(Addr2NodeItem *addrHash, StackAddr2NodeItem **stackAddr2NodeItemTop, u32 *stackAddr2NodeItemCount)
// No need mark visited node, because for each addr hash, only need to
// push once 
{
	Addr2NodeItem *nodeHash;
	for(nodeHash = addrHash->subHash; nodeHash != NULL; nodeHash = nodeHash->hh_addr2NodeItem.next) {
		addr2NodeItemStackPush(stackAddr2NodeItemTop, stackAddr2NodeItemCount, nodeHash);	
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

static AvalDstBufHTNode *
intersectDstMemNodeHT(TaintedBuf *dstMemNodesLst, AvalDstBufHTNode *avalDstBufHT)
// computes the intersected node between the dstMemNodeList and the avalDstBufHT,
// updates the avalDstBufHT accordingly 
{
	AvalDstBufHTNode *intersect = NULL, *item, *temp;
	TaintedBuf *intersectLst = NULL, *intersectItem, *itr;

	initDstBufHTNodeHitcnt(avalDstBufHT);

	LL_FOREACH(dstMemNodesLst, itr) {
		TPMNode2 *dstNode = itr->bufstart;
		// printMemNode(dstNode);
		AvalDstBufHTNode *dstMemNode;	
		HASH_FIND(hh_avalDstBufHTNode, avalDstBufHT, &dstNode, 4, dstMemNode);
		if(dstMemNode != NULL) {
			(dstMemNode->hitcnt)++;
		}
	}

	HASH_ITER(hh_avalDstBufHTNode, avalDstBufHT, item, temp) {
		if(item->hitcnt == 1) { // intersection with the dstMemNode list
			AvalDstBufHTNode *intersectNode = createAvalDstBufHTNode(item->dstNode, 0); 
			HASH_ADD(hh_avalDstBufHTNode, intersect, dstNode, 4, intersectNode);
			// HASH_DELETE(hh_avalDstBufHTNode, *avalDstBufHT, item);
			// free(item);
		}
	}
	return intersect;
}

static void 
initDstBufHTNodeHitcnt(AvalDstBufHTNode *avalDstBufHT)
// init all item's hitcnt in the hash table are 0s
{
	AvalDstBufHTNode *item, *temp;
	HASH_ITER(hh_avalDstBufHTNode, avalDstBufHT, item, temp){
		item->hitcnt = 0;
	}
}

static bool 
isInMemRange(TPMNode2 *node, u32 addrBegin, u32 addrEnd)
{
	assert(node != NULL);
	if(node->addr >= addrBegin && node->addr <= addrEnd) { return true; }
	else { return false; }
}

static void 
test_createDstContinBuf(AvalDstBufHTNode *dstMemNodesHT)
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
addr2NodeItemStackPush(StackAddr2NodeItem **stackAddr2NodeItemTop, u32 *stackAddr2NodeItemCount, Addr2NodeItem *addr2NodeItem)
{
	StackAddr2NodeItem *n = calloc(1, sizeof(StackAddr2NodeItem) );
	n->addr2NodeItem = addr2NodeItem;
	n->next = *stackAddr2NodeItemTop;
	*stackAddr2NodeItemTop = n;
	(*stackAddr2NodeItemCount)++;
}

static Addr2NodeItem *
addr2NodeItemStackPop(StackAddr2NodeItem **stackAddr2NodeItemTop, u32 *stackAddr2NodeItemCount)
{
	StackAddr2NodeItem *toDel;
	Addr2NodeItem *addr2NodeItem = NULL;

	if(*stackAddr2NodeItemTop != NULL) {
		toDel = *stackAddr2NodeItemTop;
		*stackAddr2NodeItemTop = toDel->next;
		addr2NodeItem = toDel->addr2NodeItem;
		free(toDel);
		(*stackAddr2NodeItemCount)--;
	}
	return addr2NodeItem;
}

static void 
addr2NodeItemStackDisplay(StackAddr2NodeItem *stackAddr2NodeItemTop)
{
	StackAddr2NodeItem *n = stackAddr2NodeItemTop;
	while(n != NULL) {
		TPMNode2 *node = n->addr2NodeItem->node;
		// printf("addr2NodeItem:%p - node ptr:%p - node addr:%x - dstMemNodesLst:%p\n", 
		// 	n->addr2NodeItem, n->addr2NodeItem->node, n->addr2NodeItem->node->addr, n->addr2NodeItem->toMemNode);
		printf("addr:%x - ver:%u ", node->addr, node->version);
		n = n->next;
	}
	printf("\n");
}

static void 
addr2NodeItemStackDispRange(StackAddr2NodeItem *stackAddr2NodeItemTop, char *s)
{
	if(stackAddr2NodeItemTop == NULL)
		return;

	StackAddr2NodeItem *n = stackAddr2NodeItemTop;
	u32 bufstart, bufend;
	TPMNode2 *node;

	node = n->addr2NodeItem->node;
	bufend = node->addr + node->bytesz;

	while(n != NULL && n->next != NULL) {
		node = n->addr2NodeItem->node;
		n = n->next;
	}
	bufstart = n->addr2NodeItem->node->addr;
	printf("%s\n\tbufstart:%x bufend:%x sz:%u\n", s, bufstart, bufend, bufend-bufstart);
}

static void 
addr2NodeItemStackPopAll(StackAddr2NodeItem **stackAddr2NodeItemTop, u32 *stackAddr2NodeItemCount)
{
	while(*stackAddr2NodeItemTop != NULL) {
		addr2NodeItemStackPop(stackAddr2NodeItemTop, stackAddr2NodeItemCount);
	}
}

static bool 
isAddr2NodeItemStackEmpty(StackAddr2NodeItem *stackAddr2NodeItemTop)
{
	if(stackAddr2NodeItemTop == NULL)
		return true;
	else
		return false;	
}

/* Stack of destination buf hash table operation */
static void 
dstBufHTStackPush(StackDstBufHT **stackDstBufHTTop, u32 *stackDstBufHTCount, AvalDstBufHTNode *dstBufHT)
{
	StackDstBufHT *n = calloc(1, sizeof(StackDstBufHT) );
	n->dstBufHT = dstBufHT;
	n->next = *stackDstBufHTTop;
	*stackDstBufHTTop = n;
	(*stackDstBufHTTop)++;
}

static AvalDstBufHTNode*
dstBufHTStackPop(StackDstBufHT **stackDstBufHTTop, u32 *stackDstBufHTCount)
{
	StackDstBufHT *toDel;
	AvalDstBufHTNode *dstBufHT = NULL;

	if(*stackDstBufHTTop != NULL) {
		toDel = *stackDstBufHTTop;
		*stackDstBufHTTop = toDel -> next;
		dstBufHT = toDel->dstBufHT;
		free(toDel);
		(*stackDstBufHTCount)--;
	}
	return dstBufHT;
}

/* Stack of buf array operations */
static void 
bufAryStackPush(StackBufAry **stackBufAryTop, u32 *stackBufAryCnt, ContinBufAry *contBufAry)
{
	StackBufAry *n = calloc(1, sizeof(StackBufAry) );
	n->contBufAry = contBufAry;
	n->next = *stackBufAryTop;
	*stackBufAryTop = n;
	(*stackBufAryTop)++;
}

static ContinBufAry *
bufAryStackPop(StackBufAry **stackBufAryTop, u32 *stackBufAryCnt)
{
	StackBufAry *toDel;
	ContinBufAry *contBufAry;

	if(*stackBufAryTop != NULL) {
		toDel = *stackBufAryTop;
		*stackBufAryTop = toDel->next;
		contBufAry = toDel->contBufAry;
		free(toDel);
		(*stackBufAryCnt)--;
	}
	return contBufAry;
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
		printMemNode(itr->bufstart);
		// printf("\t-> addr:%-8x val:%-8x\n", itr->bufstart->addr, itr->bufstart->val);
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
		printf("addr:0x%x - val:%x - ptr:%p hitcnt:%u\n", item->dstNode->addr, item->dstNode->val, item->dstNode, item->hitcnt);
	}
}
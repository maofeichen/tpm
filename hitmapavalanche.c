#include "continbuf.h"
#include "hitmapavalanche.h"
#include "hitmappropagate.h"
#include "hitmap_addr2nodeitem_datastruct.h"
#include "misc.h"
#include "uthash.h"
#include <assert.h>
#include <unistd.h>

static HitMapAvalSearchCtxt *
initHitMapAvalSearchCtxt(
    u32 srcBufIdx,
    TPMBufHashTable *srcTPMBuf,
    u32 dstbufIdx,
    TPMBufHashTable *dstTPMBuf);

static void
freeHitMapAvalSearchCtxt(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt);

static void
detectHitMapAvalInOut(
    HitMapAvalSearchCtxt *hitMapAvalSrchCtxt,
    HitMapContext *hitMap,
    double *totalElapse);

static void
searchHitMapPropgtInOut(
    HitMapAvalSearchCtxt *hitMapAvalSrchCtxt,
    HitMapContext *hitMap);

static u32
srchHitMapPropgtInOutReverse(
    HitMapAvalSearchCtxt *hitMapAvalSrchCtxt,
    HitMapContext *hitMap);

static void
search_bufpair_avalanche(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt);

static bool
has_enough_dstnode(HitMapAddr2NodeItem *srcnode);

static void
search_srcnode_avalanche(
    HitMapAddr2NodeItem *srcnode,
    u32 srcbuf_addridx,
    u32 *block_sz_detect,
    HitMapAvalSearchCtxt *hitMapAvalSrchCtxt);

static void
store_addr2nodeitem_rightnbr(
    HitMapAddr2NodeItem *rightnbr_b,
    StackHitMapAddr2NodeItem **stackHitMapAddr2NodeItemTop,
    u32 *stackHitMapAddr2NodeItemCount,
    int curnode_lastupdate_ts);

static RangeArray *
build_range_array(HitMapAddr2NodeItem *addrnodes);

static void
delOldNewRangeArray(RangeArray **old, RangeArray **new);

/* Public functions */
void
detectHitMapAvalanche(HitMapContext *hitMap, TPMContext *tpm)
{
  u32 numOfBuf, srcBufIdx, dstBufIdx;
  TPMBufHashTable *srcTPMBuf;
  TPMBufHashTable *dstTPMBuf;
  HitMapAvalSearchCtxt *hitMapAvalSrchCtxt;

  double totalElapse = 0;
  u32 searchCnt = 0;

  numOfBuf = hitMap->numOfBuf;
  for(srcBufIdx = 0; srcBufIdx < numOfBuf-1; srcBufIdx++) {
    for(dstBufIdx = srcBufIdx + 1; dstBufIdx < numOfBuf; dstBufIdx++) {

      // if((srcBufIdx >= 265 && srcBufIdx <= 270)
      //     || (srcBufIdx >= 925 && srcBufIdx <= 930) ) {
      //     if(dstBufIdx == srcBufIdx+1 || dstBufIdx == numOfBuf-1) {
      //         srcTPMBuf = getTPMBuf(hitMap->tpmBuf, srcBufIdx);
      //         dstTPMBuf = getTPMBuf(hitMap->tpmBuf, dstBufIdx);
      //         hitMapAvalSrchCtxt = initHitMapAvalSearchCtxt(srcBufIdx, srcTPMBuf, dstBufIdx, dstTPMBuf);
      //         detectHitMapAvalInOut(hitMapAvalSrchCtxt, hitMap, &totalElapse);
      //         freeHitMapAvalSearchCtxt(hitMapAvalSrchCtxt);

      //         searchCnt++;
      //     }
      // }

      srcTPMBuf = getTPMBuf(hitMap->tpmBuf, srcBufIdx);
      dstTPMBuf = getTPMBuf(hitMap->tpmBuf, dstBufIdx);
      hitMapAvalSrchCtxt = initHitMapAvalSearchCtxt(srcBufIdx, srcTPMBuf, dstBufIdx, dstTPMBuf);
      detectHitMapAvalInOut(hitMapAvalSrchCtxt, hitMap, &totalElapse);
      freeHitMapAvalSearchCtxt(hitMapAvalSrchCtxt);

      searchCnt++;
    }
    break;
  }
  if(searchCnt > 0) {
    printf("---------------\navg build 2-level hash table time:%.1f microseconds\n", totalElapse/searchCnt);
  }
  // OutOfLoop:
  // printf("");
}

void
printHitMapAvalSrchCtxt(HitMapAvalSearchCtxt *hmAvalSrchCtxt)
{
  if(hmAvalSrchCtxt == NULL)
    return;

}


static HitMapAvalSearchCtxt *
initHitMapAvalSearchCtxt(
    u32 srcBufIdx,
    TPMBufHashTable *srcTPMBuf,
    u32 dstbufIdx,
    TPMBufHashTable *dstTPMBuf)
{
  HitMapAvalSearchCtxt *h = calloc(1, sizeof(HitMapAvalSearchCtxt) );
  assert(h != NULL);

  h->srcTPMBuf = srcTPMBuf;
  h->dstTPMBuf = dstTPMBuf;
  h->srcBufID = srcBufIdx;
  h->dstBufID = dstbufIdx;
  h->srcAddrStart = srcTPMBuf->baddr;
  h->srcAddrEnd = srcTPMBuf->eaddr;
  h->dstAddrStart = dstTPMBuf->baddr;
  h->dstAddrEnd = dstTPMBuf->eaddr;
  h->srcMinSeqN = srcTPMBuf->minseq;
  h->srcMaxSeqN = srcTPMBuf->maxseq;
  h->dstMinSeqN= dstTPMBuf->minseq;
  h->dstMaxSeqN = dstTPMBuf->maxseq;
  h->numOfSrcAddr = srcTPMBuf->numOfAddr;
  h->numOfDstAddr = dstTPMBuf->numOfAddr;
  h->hitMapAddr2NodeAry = calloc(1, srcTPMBuf->numOfAddr * sizeof(HitMapAddr2NodeItem) );
  assert(h->hitMapAddr2NodeAry != NULL);

  return h;
}

static void
freeHitMapAvalSearchCtxt(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt)
{
  for(int addrIdx = 0; addrIdx < hitMapAvalSrchCtxt->numOfSrcAddr; addrIdx++) {
    freeHitMapAddr2NodeItem(hitMapAvalSrchCtxt->hitMapAddr2NodeAry[addrIdx]);
  }

  free(hitMapAvalSrchCtxt->hitMapAddr2NodeAry);
  hitMapAvalSrchCtxt->hitMapAddr2NodeAry = NULL;
  free(hitMapAvalSrchCtxt);
  hitMapAvalSrchCtxt = NULL;
  // printf("del hitMapAvalSrchCtxt\n");
}

static void
detectHitMapAvalInOut(
    HitMapAvalSearchCtxt *hitMapAvalSrchCtxt,
    HitMapContext *hitMap,
    double *totalElapse)
{
  u32 srcBufNodeTotal, dstBufNodeTotal;
  u32 numOfTrans, srcAddrIdx, srcBufID;
  u32 totalTraverse = 0;

  srcBufNodeTotal = getTPMBufNodeTotal(hitMapAvalSrchCtxt->srcTPMBuf);
  dstBufNodeTotal = getTPMBufNodeTotal(hitMapAvalSrchCtxt->dstTPMBuf);

  printf("----------------------------------------\n");
  print1TPMBufHashTable("src buf: ", hitMapAvalSrchCtxt->srcTPMBuf);
  print1TPMBufHashTable("dst buf: ", hitMapAvalSrchCtxt->dstTPMBuf);
  printf("total src buf node:%u - total dst buf node:%u\n", srcBufNodeTotal, dstBufNodeTotal);

  if(hitMapAvalSrchCtxt->dstTPMBuf->headNode->bufid == 7)
    printf("dbg\n");

  // printTime("before search propagation");
  printTimeMicroStart();

  searchHitMapPropgtInOut(hitMapAvalSrchCtxt, hitMap);
  search_bufpair_avalanche(hitMapAvalSrchCtxt);
  // totalTraverse = srchHitMapPropgtInOutReverse(hitMapAvalSrchCtxt, hitMap);

  // printTime("after search propagation");
  printTimeMicroEnd(totalElapse);

  numOfTrans = 0;
  srcBufID = hitMapAvalSrchCtxt->srcBufID;
  for(srcAddrIdx = 0; srcAddrIdx < hitMap->bufArray[srcBufID]->numOfAddr; srcAddrIdx++) {
    numOfTrans += getHitMap2LAddr2NodeItemTotal(hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx]);
  }
  printf("number of transition of 2-level hash table:%u\n", numOfTrans);
  printf("total number of traverse steps:%u\n", totalTraverse);
}

static void
searchHitMapPropgtInOut(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt, HitMapContext *hitMap)
// Searches propagations of source buffer (all version of each node) to dst buf,
// results store in dstMemNodesHT
// 1. Search propagation
// For each version node of each addr of input buffer as source
// 1.1 searches the source node propagations to destination buffers (within addr/seqNo range)
{
  u32 srcAddrIdx, srcBufID;

  srcBufID = hitMapAvalSrchCtxt->srcBufID;
  if(hitMapAvalSrchCtxt->srcBufID >= hitMap->numOfBuf) {
    fprintf(stderr, "searchHitMapPropgtInOut error: invalid src buf ID\n");
    return;
  }

  for(srcAddrIdx = 0; srcAddrIdx < hitMap->bufArray[srcBufID]->numOfAddr; srcAddrIdx++) {
    HitMapNode *head = hitMap->bufArray[srcBufID]->addrArray[srcAddrIdx];
    if(head == NULL)
      continue;   // TODO: Debug

    u32 ver = head->version;

    do {
      // printHitMapNodeLit(head);
      HitMapAddr2NodeItem *hmAddr2NodeItem = createHitMapAddr2NodeItem(head->addr, head, NULL, NULL);
      HASH_ADD(hh_hmAddr2NodeItem, hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx], node, 4, hmAddr2NodeItem);

      hitMapNodePropagate(head, hitMap, hmAddr2NodeItem, hitMapAvalSrchCtxt->dstAddrStart, hitMapAvalSrchCtxt->dstAddrEnd,
          hitMapAvalSrchCtxt->dstMinSeqN, hitMapAvalSrchCtxt->dstMaxSeqN);
      // printHitMapAddr2NodeItemSubhash(hmAddr2NodeItem);
      head = head->nextVersion;
    } while(ver != head->version);

    HASH_SRT(hh_hmAddr2NodeItem, hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx], cmpHitMapAddr2NodeItem);
    // printHitMap2LAddr2NodeItem(hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx]);
    // assert(head->leftNBR == NULL);
  }
}

static u32
srchHitMapPropgtInOutReverse(
    HitMapAvalSearchCtxt *hitMapAvalSrchCtxt,
    HitMapContext *hitMap)
// Instead of searching from src to dst, searching from dst to src via taintedBy
// Hit Transition. But result still store as <src dst> in 2Level hash
{
  u32 srcBufId, dstBufId;
  u32 srcAddrIdx, dstAddrIdx;
  u32 totalTraverse = 0;

  srcBufId = hitMapAvalSrchCtxt->srcBufID;
  dstBufId = hitMapAvalSrchCtxt->dstBufID;

  if(srcBufId >= hitMap->numOfBuf ||
      dstBufId >= hitMap->numOfBuf) {
    fprintf(stderr, "searchHitMapPropgtInOutReverse error: invalid src/dst buf ID\n");
    return 0;
  }

  // Adds all nodes of src buf in 1stLevel hash
  for(srcAddrIdx = 0; srcAddrIdx < hitMap->bufArray[srcBufId]->numOfAddr; srcAddrIdx++) {
    HitMapNode *head = hitMap->bufArray[srcBufId]->addrArray[srcAddrIdx];
    if(head == NULL)
      continue;   // TODO: Debug

    u32 ver = head->version;
    do {
      HitMapAddr2NodeItem *hmAddr2NodeItem = createHitMapAddr2NodeItem(head->addr, head, NULL, NULL);
      HASH_ADD(hh_hmAddr2NodeItem, hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx], node, 4, hmAddr2NodeItem);

      head = head->nextVersion;
    } while(ver != head->version);
  }

  // Search reverse taint propagation and build 2Level hash
  for(dstAddrIdx = 0; dstAddrIdx < hitMap->bufArray[dstBufId]->numOfAddr; dstAddrIdx++) {
    HitMapNode *head = hitMap->bufArray[dstBufId]->addrArray[dstAddrIdx];
    if(head == NULL)
      continue;
    u32 ver = head->version;
    u32 traverse = 0;
    do {
      traverse = hitMapNodePropagateReverse(head, hitMap, hitMapAvalSrchCtxt->hitMapAddr2NodeAry,
          hitMapAvalSrchCtxt->srcAddrStart, hitMapAvalSrchCtxt->srcAddrEnd,
          hitMapAvalSrchCtxt->srcMinSeqN, hitMapAvalSrchCtxt->srcMaxSeqN);
      totalTraverse += traverse;
      head = head->nextVersion;
    } while (ver != head->version);
  }

  for(srcAddrIdx = 0; srcAddrIdx < hitMap->bufArray[srcBufId]->numOfAddr; srcAddrIdx++) {
    HASH_SRT(hh_hmAddr2NodeItem, hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx], cmpHitMapAddr2NodeItem);

    HitMapAddr2NodeItem *hmAddr2NodeItem = hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx];
    for(; hmAddr2NodeItem != NULL; hmAddr2NodeItem = hmAddr2NodeItem->hh_hmAddr2NodeItem.next) {
      HASH_SRT(hh_hmAddr2NodeItem, hmAddr2NodeItem->subHash, cmpHitMapAddr2NodeItem);
    }
    // printHitMap2LAddr2NodeItem(hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcAddrIdx]);
  }
  return totalTraverse;
}

static void
search_bufpair_avalanche(HitMapAvalSearchCtxt *hitMapAvalSrchCtxt)
{
  u32 srcbuf_addridx = 0;
  for(; srcbuf_addridx < (hitMapAvalSrchCtxt->numOfSrcAddr-1); /* srcbuf_addridx++ */) {
    // No need to search last addr
    HitMapAddr2NodeItem *srcnode = hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcbuf_addridx];
    u32 block_sz = 1;      // block sz s.t. continuous src nodes propagate to same destinations (considered blocks)
    u32 max_block_sz = 1;  // max block sz found for all version nodes of same address

    for(; srcnode != NULL; srcnode = srcnode->hh_hmAddr2NodeItem.next) {
      if(has_enough_dstnode(srcnode) ) {
        printf("--------------------detect avalanche\n");
        printf("begin node:addr:%x version:%u\n", srcnode->node->addr, srcnode->node->version);
        printTime("");
        search_srcnode_avalanche(srcnode, srcbuf_addridx+1, &block_sz, hitMapAvalSrchCtxt);

        if(block_sz > max_block_sz)
          max_block_sz = block_sz;
      }
    }

    srcbuf_addridx += max_block_sz;
  }
}

static bool
has_enough_dstnode(HitMapAddr2NodeItem *srcnode)
{
  if(srcnode != NULL) {
    HitMapAddr2NodeItem *propgt_to_dstnode = srcnode->subHash;
    u32 num_of_dstnode = HASH_CNT(hh_hmAddr2NodeItem, propgt_to_dstnode);
    if(num_of_dstnode > 1)
      return true;
  }
  return false;
}

static void
search_srcnode_avalanche(
    HitMapAddr2NodeItem *srcnode,
    u32 srcbuf_addridx,
    u32 *block_sz_detect,
    HitMapAvalSearchCtxt *hitMapAvalSrchCtxt)
{
  HitMapAddr2NodeItem *old_srcnode, *new_srcnode;
  RangeArray *old_ra = NULL, *new_ra = NULL;
  RangeArray *oldintersect_ra = NULL, *newintersect_ra = NULL;

  StackHitMapAddr2NodeItem *stack_traverse_top = NULL;  // maintains traverse nodes during search
  u32 stack_traverse_cnt = 0;

  StackHitMapAddr2NodeItem *stack_srcnode_top = NULL;   // maintains src nodes have avalanche
  u32 stack_srcnode_cnt = 0;

  bool has_print_rslt = false;

  if(srcnode == NULL || hitMapAvalSrchCtxt == NULL) {
    return;
  }

  // printHitMapAddr2NodeItemSubhash(srcnode);
  hitMapAddr2NodeItemPush(srcnode, &stack_srcnode_top, &stack_srcnode_cnt);
  old_srcnode = srcnode;
  old_ra = build_range_array(old_srcnode->subHash);
  // printRangeArray(old_ra, "");

  store_addr2nodeitem_rightnbr(hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcbuf_addridx],
      &stack_traverse_top, &stack_traverse_cnt, old_srcnode->node->lastUpdateTS);

  while(!isHitMapAddr2NodeItemStackEmpty(stack_traverse_top, stack_traverse_cnt) ) {
    new_srcnode = hitMapAddr2NodeItemPop(&stack_traverse_top, &stack_traverse_cnt);
    // TODO: add comment
    // newnode's addr <= oldnode's addr, indicates the stack is bouncing back
    if(new_srcnode->node->addr <= old_srcnode->node->addr) {
      if(!has_print_rslt){
        if(stack_srcnode_cnt >= 2 && stack_srcnode_cnt >= *block_sz_detect) {
          printf("--------------------\n");
          hitMapAddr2NodeItemDispRange(stack_srcnode_top, "avalanche found:\nsrc buf:");
          printf("-> dst buf:\n");
          printRangeArray(oldintersect_ra, "\t");

          *block_sz_detect = stack_srcnode_cnt;  // set to max num src node has avalanche
        }
      }

      // Bounces back source stack accordingly
      while(new_srcnode->node->addr <= stack_srcnode_top->hitMapAddr2NodeItem->node->addr) {
        hitMapAddr2NodeItemPop(&stack_srcnode_top, &stack_srcnode_cnt);
        srcbuf_addridx--;
      }

      delOldNewRangeArray(&old_ra, &new_ra);
      delOldNewRangeArray(&oldintersect_ra, &newintersect_ra);

      old_srcnode = stack_srcnode_top->hitMapAddr2NodeItem;
      old_ra = build_range_array(old_srcnode->subHash);
      // printRangeArray(old_ra, "");
    }

    // can't delete here, due to in the yes case below, newra is assigned to oldra,
    // if delete newra, then oldra will be deleted also. Now I set new to NULL if the case.
    new_ra = build_range_array(new_srcnode->subHash);
    newintersect_ra = get_common_rangearray(old_srcnode, old_ra, new_srcnode, new_ra);
    // printRangeArray(newintersect_ra, "");

    if(newintersect_ra->rangeAryUsed > 0) { // valid intersection range array
      old_srcnode = new_srcnode;
      hitMapAddr2NodeItemPush(old_srcnode, &stack_srcnode_top, &stack_srcnode_cnt);

      delRangeArray(&old_ra);
      delRangeArray(&oldintersect_ra);

      old_ra = new_ra;
      oldintersect_ra = newintersect_ra;

      new_ra = NULL;    // since newra assigns to oldra, set it to NULL after
      newintersect_ra = NULL;

      has_print_rslt = false;   // only has new src aval node, indicating new avalanche
    }
    else {  // no valid intersection ranges
      if(!has_print_rslt){
        if(stack_srcnode_cnt >= 2 && stack_srcnode_cnt >= *block_sz_detect) {
          printf("--------------------\n");
          hitMapAddr2NodeItemDispRange(stack_srcnode_top, "avalanche found:\nsrc buf:");
          printf("-> dst buf:\n");
          printRangeArray(oldintersect_ra, "\t");

          *block_sz_detect = stack_srcnode_cnt;  // set to max num src node has avalanche
        }
        has_print_rslt = true;
      }

      delRangeArray(&new_ra);  // only del new ones due to invalid
      delRangeArray(&newintersect_ra);
      continue;   // no valid intersect propagation, no need to go further (as dfs)
    }

    if(srcbuf_addridx < hitMapAvalSrchCtxt->numOfSrcAddr) {
      srcbuf_addridx++;
      if(srcbuf_addridx < hitMapAvalSrchCtxt->numOfSrcAddr) {
        store_addr2nodeitem_rightnbr(hitMapAvalSrchCtxt->hitMapAddr2NodeAry[srcbuf_addridx],
            &stack_traverse_top, &stack_traverse_cnt, old_srcnode->node->lastUpdateTS);
      }
    }
  }
  delOldNewRangeArray(&old_ra, &new_ra);
  delOldNewRangeArray(&oldintersect_ra, &newintersect_ra);
}

static void
store_addr2nodeitem_rightnbr(
    HitMapAddr2NodeItem *rightnbr_b,
    StackHitMapAddr2NodeItem **stackHitMapAddr2NodeItemTop,
    u32 *stackHitMapAddr2NodeItemCount,
    int curnode_lastupdate_ts)
// Enforces the increasing last update ts policy.
{
  if(rightnbr_b != NULL) {
    for(; rightnbr_b != NULL; rightnbr_b = rightnbr_b->hh_hmAddr2NodeItem.next) {
      if(has_enough_dstnode(rightnbr_b) ) { // TODO: uses minBufSz later
        if(curnode_lastupdate_ts < 0 && rightnbr_b->node->lastUpdateTS < 0) {
          // if both are negative, smaller is later
          if(rightnbr_b->node->lastUpdateTS < curnode_lastupdate_ts)
            hitMapAddr2NodeItemPush(rightnbr_b, stackHitMapAddr2NodeItemTop, stackHitMapAddr2NodeItemCount);
        }
        else {
          if(rightnbr_b->node->lastUpdateTS > curnode_lastupdate_ts)
             hitMapAddr2NodeItemPush(rightnbr_b, stackHitMapAddr2NodeItemTop, stackHitMapAddr2NodeItemCount);
        }
      }
    }
  }
}

static RangeArray *
build_range_array(HitMapAddr2NodeItem *addrnodes)
{
  RangeArray *ra;
  Range *r;
  u32 cur_rstart, cur_rend;

  if(addrnodes != NULL) {
    ra = initRangeArray();

    r = initRange();
    r->start = addrnodes->node->addr;
    r->end = addrnodes->node->addr + addrnodes->node->bytesz;

    cur_rstart = r->start;
    cur_rend = r->end;

    HitMapAddr2NodeItem *addrnode = addrnodes->hh_hmAddr2NodeItem.next; // starts from next node
    for(; addrnode != NULL; addrnode = addrnode->hh_hmAddr2NodeItem.next) {
      HitMapNode *node = addrnode->node;
      u32 cur_node_start = node->addr;

      if(cur_rend > cur_node_start) {
        // TODO: propagate to multiple version of same addr, handles latter
        // printf("buildRangeAry: TODO: multiple version of same addr:%x\n", cur_node_start);
      }
      else if(cur_rend == cur_node_start) {
        r->end += node->bytesz;
        cur_rend += node->bytesz;
      }
      else {    // new range
        add2Range(ra, r);

        r = initRange();
        r->start = node->addr;
        r->end = node->addr + node->bytesz;

        cur_rstart = r->start;
        cur_rend = r->end;
      }
    }
    add2Range(ra, r);   // adds last range
    return ra;
  }
  else { return NULL; }
}

static void
delOldNewRangeArray(RangeArray **old, RangeArray **new)
{
  if(*old == *new) { delRangeArray(old); }
  else {
    delRangeArray(old);
    delRangeArray(new);
  }
}

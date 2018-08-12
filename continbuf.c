#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "utlist.h"
#include "continbuf.h"

static void 
growContBufNodeAry(ContinBuf *contBuf);

static void 
growContBufAry(ContinBufAry *contBufAry);

static int 
addContBuf(ContinBufAry *contBufAry, ContinBuf *contBuf, int pos);

static u32 
getMaxAddr(u32 addr_l, u32 addr_r);

static u32 
getMinAddr(u32 addr_l, u32 addr_r);

static void
addRange(RangeArray *ra, Range *r, int pos);

static void
growRangeArray(RangeArray *ra);

ContinBuf *
initContinBuf()
{
  ContinBuf *contBuf = calloc(1, sizeof(ContinBuf) );
  contBuf->nodeArySz = INIT_CONTBUFNODEARY_SZ;
  contBuf->nodeAryUsed = 0;

  contBuf->contBufNodeAry = malloc(INIT_CONTBUFNODEARY_SZ * sizeof(TaintedBuf *) );
  memset(contBuf->contBufNodeAry, 0, sizeof(TaintedBuf *) * INIT_CONTBUFNODEARY_SZ);

  return contBuf;
}

int 
extendContinBuf(ContinBuf *contBuf, TPMNode2 *nodeptr)
{
  TaintedBuf *nodeHead = NULL, *node;

  node = createTaintedBuf(nodeptr);
  LL_APPEND(nodeHead, node);

  if(contBuf->nodeAryUsed == 0) {
    contBuf->bufStart = nodeptr->addr;
    contBuf->bufEnd = contBuf->bufStart + nodeptr->bytesz;
    contBuf->contBufNodeAry[contBuf->nodeAryUsed] = nodeHead;
    (contBuf->nodeAryUsed)++;
  }
  else {
    if(contBuf->nodeAryUsed == contBuf->nodeArySz) {
      growContBufNodeAry(contBuf);
    }

    contBuf->bufEnd = nodeptr->addr + nodeptr->bytesz;
    contBuf->contBufNodeAry[contBuf->nodeAryUsed] = nodeHead;
    (contBuf->nodeAryUsed)++;
  }
  return 0;
}

ContinBuf *
getContBufIntersect(ContinBuf *l, u32 intersectStart, u32 intersectEnd)
{
  TaintedBuf *head;
  ContinBuf *contBuf = initContinBuf();
  int i;

  for(i = 0; i < l->nodeAryUsed; i++) {
    head = l->contBufNodeAry[i];

    if( (head->bufstart->addr + head->bufstart->bytesz) > intersectEnd) {
      break;
    }

    if(head->bufstart->addr >= intersectStart) {
      extendContinBuf(contBuf, head->bufstart);
    }
  }
  return contBuf;
}

void 
delContinBuf(ContinBuf *contBuf)
{
  int i;
  TaintedBuf *head, *elt, *tmp;
  for(i = 0; i < contBuf->nodeAryUsed; i++) {
    head = contBuf->contBufNodeAry[i];
    LL_FOREACH_SAFE(head, elt, tmp) {
      LL_DELETE(head, elt);
      free(elt);
    }
  }
  free(contBuf->contBufNodeAry);
  free(contBuf);
}

ContinBufAry *
initContBufAry()
{
  ContinBuf **contBufAryHead;
  ContinBufAry *bufAry;

  bufAry = calloc(1, sizeof(ContinBufAry) );
  bufAry->bufArySz = INIT_CONTBUFARY_SZ;
  bufAry->bufAryUsed = 0;
  contBufAryHead = calloc(1, sizeof(ContinBuf) * INIT_CONTBUFARY_SZ);
  bufAry->contBufAryHead = contBufAryHead;

  return bufAry;
}

int 
appendContBufAry(ContinBufAry *contBufAry, ContinBuf *contBuf)
{

  if(contBufAry->bufAryUsed == contBufAry->bufArySz) {
    growContBufAry(contBufAry);
  }

  contBufAry->contBufAryHead[contBufAry->bufAryUsed] = contBuf;
  (contBufAry->bufAryUsed)++;

  return 0;
}

int 
add2BufAry(ContinBufAry *contBufAry, ContinBuf *contBuf)
{
  int lo = 0, mid = lo, hi = contBufAry->bufAryUsed;
  while(lo < hi) {
    mid = lo + (hi - lo) / 2;
    if(contBufAry->contBufAryHead[mid]->bufStart < contBuf->bufStart) {
      lo = mid + 1;
    }
    else { hi = mid; }
  }
  addContBuf(contBufAry, contBuf, lo);
  return 0;
}

static int 
addContBuf(ContinBufAry *contBufAry, ContinBuf *contBuf, int pos)
{
  if(pos > contBufAry->bufAryUsed) {
    fprintf(stderr, "addContBuf: pos is larger than used\n");
    return -1;
  }

  if(contBufAry->bufAryUsed == contBufAry->bufArySz) {
    growContBufAry(contBufAry);
  }

  for(int i = (contBufAry->bufAryUsed - 1); i >= pos; i--) {
    contBufAry->contBufAryHead[i+1] = contBufAry->contBufAryHead[i];
  }
  contBufAry->contBufAryHead[pos] = contBuf;
  (contBufAry->bufAryUsed)++;

  return 0;
}

// ContinBufAry *
// getBufAryIntersect(ContinBufAry *l, ContinBufAry *r)
// // TODO: comment out
// {
//   ContinBufAry *bufAryIntrsct = NULL;
//   u32 idx_l = 0, idx_r = 0;
//   u32 aryUsed_l = l->bufAryUsed, aryUsed_r = r->bufAryUsed;
//   ContinBuf *buf_l, *buf_r, *bufIntrsct;

//   bufAryIntrsct = initContBufAry();

//   while(true) {
//     if(idx_l >= aryUsed_l || idx_r >= aryUsed_r)
//       break;

//     buf_l = l->contBufAryHead[idx_l];
//     buf_r = r->contBufAryHead[idx_r];

//     // choose the larger buf start addr, choose the smaller buf end addr
//     u32 intrsctAddrStart = getMaxAddr(buf_l->bufStart, buf_r->bufStart);
//     u32 intrsctAddrEnd 	 = getMinAddr(buf_l->bufEnd, buf_r->bufEnd);

//     if(intrsctAddrStart < intrsctAddrEnd) { // gets the intersection buf
//       // printf("intersection: addr start:%x - addr end:%x\n", intrsctAddrStart, intrsctAddrEnd);
//       bufIntrsct = getContBufIntersect(buf_l, intrsctAddrStart, intrsctAddrEnd);
//       // appendContBufAry(bufAryIntrsct, bufIntrsct);
//       add2BufAry(bufAryIntrsct, bufIntrsct);
//     }

//     // if left buf range is smaller than right buf range, increases it
//     // notices all bufs in buf ary are in increasing order
//     if(buf_l->bufEnd < buf_r->bufEnd) { idx_l++; }
//     else if(buf_l->bufEnd > buf_r->bufEnd) { idx_r++; }
//     else { idx_l++, idx_r++; }
//   }


//   return bufAryIntrsct;
// }


bool 
hasMinSzContBuf(ContinBufAry *contBufAry, u32 minBufSz)
{
  assert(contBufAry != NULL);

  int i;
  for(i = 0; i < contBufAry->bufAryUsed; i++) {
    ContinBuf *contBuf = contBufAry->contBufAryHead[i];
    u32 bufsz = contBuf->bufEnd - contBuf->bufStart;
    if(bufsz >= minBufSz)
      return true;
  }
  return false;
}

void 
delContinBufAry(ContinBufAry **contBufAry)
{
  int i;
  for(i = 0; i < (*contBufAry)->bufAryUsed; i++) {
    delContinBuf( (*contBufAry)->contBufAryHead[i]);
  }
  free( (*contBufAry)->contBufAryHead);
  free(*contBufAry);
  *contBufAry = NULL;
}

static void 
growContBufNodeAry(ContinBuf *contBuf)
// doubles the contNodeBufSz 
{
  TaintedBuf **newBufNodeAry;
  u32 newNodeArySz = contBuf->nodeArySz * 2;
  int i;

  newBufNodeAry = malloc(sizeof(TaintedBuf *) * newNodeArySz );
  memset(newBufNodeAry, 0, sizeof(TaintedBuf *) * newNodeArySz );

  for(i = 0; i < contBuf->nodeAryUsed; i++) {
    newBufNodeAry[i] = contBuf->contBufNodeAry[i];
  }
  contBuf->nodeArySz = newNodeArySz;
  free(contBuf->contBufNodeAry);
  contBuf->contBufNodeAry = newBufNodeAry;
}

static void 
growContBufAry(ContinBufAry *contBufAry)
// doubles the bufArySz
{
  ContinBuf **newContBufAryHead;
  u32 newBufArySz = contBufAry->bufArySz * 2;
  int i;

  newContBufAryHead = calloc(1, sizeof(ContinBuf) * newBufArySz);
  for(i = 0; i < contBufAry->bufAryUsed; i++) {
    newContBufAryHead[i] = contBufAry->contBufAryHead[i];
  }
  contBufAry->bufArySz = newBufArySz;

  free(contBufAry->contBufAryHead);
  contBufAry->contBufAryHead = newContBufAryHead;
}

static u32 
getMaxAddr(u32 addr_l, u32 addr_r)
{
  if(addr_l > addr_r)
    return addr_l;
  else
    return addr_r;
}

static u32 
getMinAddr(u32 addr_l, u32 addr_r)
{
  if(addr_l < addr_r)
    return addr_l;
  else
    return addr_r;
}

void 
printContinBuf(ContinBuf *contBuf)
{
  TaintedBuf *nodeHead, *elt;
  int i;

  printf("cont bufstart:%x - bufend:%x - node ary sz:%u - total buf nodes:%u\n",
      contBuf->bufStart, contBuf->bufEnd, contBuf->nodeArySz, contBuf->nodeAryUsed);

  for(i = 0; i < contBuf->nodeArySz; i++) {
    if(contBuf->contBufNodeAry[i] != NULL) {
      nodeHead = contBuf->contBufNodeAry[i];
      printf("node head:%p addr:%x next:%p\n", nodeHead, nodeHead->bufstart->addr, nodeHead->next);
      LL_FOREACH(nodeHead, elt) {
        printf("TaintedBuf:%p - addr:%x\n", elt, elt->bufstart->addr);
      }

    }
    else { printf("node head:%p\n", contBuf->contBufNodeAry[i]); }
  }
}

void 
printContinBufAry(ContinBufAry *contBufAry)
{
  if(contBufAry == NULL){
    fprintf(stderr, "error: continuous buf ary is empty:%p\n", contBufAry);
    return;
  }

  int i;
  printf("cont buf ary: sz:%u - total cont buf:%u\n",
      contBufAry->bufArySz, contBufAry->bufAryUsed);
  for(i = 0; i < contBufAry->bufArySz; i++) {
    if(contBufAry->contBufAryHead[i] != NULL) {
      printContinBuf(contBufAry->contBufAryHead[i]);
    }
  }
}

void 
printContBufAry_lit(char *s, ContinBufAry *contBufAry)
{
  for(int i = 0; i < contBufAry->bufAryUsed; i++) {
    ContinBuf *contBuf = contBufAry->contBufAryHead[i];
    if(contBuf != NULL) {
      printf("%sbufstart:%x bufend:%x sz:%u\n",
          s, contBuf->bufStart, contBuf->bufEnd, contBuf->bufEnd - contBuf->bufStart);
    }
  }
}

Range *
initRange()
{
  Range *r = calloc(1, sizeof(Range));
  r->start = 0;
  r->end = 0;
  return r;
}

Range *
getIntersectRange(Addr2NodeItem *l, Addr2NodeItem *r, u32 start, u32 end)
{
  Range *intersect_r = NULL;
  Addr2NodeItem *lnode, *rnode;
  u32 intersectStart = 0, intersectEnd = 0;

  // print2ndLevelHash(l);
  // print2ndLevelHash(r);

  for(lnode = l->subHash; lnode != NULL; lnode = lnode->hh_addr2NodeItem.next) {
    if(lnode->addr == start)
      break;
  }
  for(rnode = r->subHash; rnode != NULL; rnode = rnode->hh_addr2NodeItem.next) {
    if(rnode->addr == start)
      break;
  }
  if(lnode == NULL || rnode == NULL)
    return NULL;

  u32 currend = start + lnode->node->bytesz;
  while(currend <= end){
    if(lnode == NULL || rnode == NULL)
      break;

    if(lnode->node == rnode->node){
      if(intersectStart == 0){
        intersectStart = lnode->node->addr;
        intersectEnd = intersectStart + lnode->node->bytesz;
        // printf("start: %x end: %x\n", intersectStart, intersectEnd);
      }
      else {
        intersectEnd = intersectEnd + lnode->node->bytesz;
      }
    }

    u32 lend = lnode->node->addr + lnode->node->bytesz;
    u32 rend = rnode->node->addr + rnode->node->bytesz;
    // printf("lend:%x\n", lend);
    // printf("rend:%x\n", rend);
    if(lend < rend) {
      lnode = lnode->hh_addr2NodeItem.next;
      currend = lend;
    }
    else if(lend > rend) {
      rnode = rnode->hh_addr2NodeItem.next;
      currend = rend;
    }
    else{
      lnode = lnode->hh_addr2NodeItem.next;
      rnode = rnode->hh_addr2NodeItem.next;
      currend = lend;
    }
  }

  // printf("common start:%x end:%x\n", intersectStart, intersectEnd);
  if(intersectStart != 0){
    intersect_r = initRange();
    intersect_r->start = intersectStart;
    if(intersectEnd > end)
      intersectEnd = end;
    intersect_r->end = intersectEnd;
  }

  return intersect_r;
}

Range *
get_common_range(
    HitMapAddr2NodeItem *l,
    HitMapAddr2NodeItem *r,
    u32 start,
    u32 end)
{
  Range *intersect_r = NULL;
  HitMapAddr2NodeItem *lnode, *rnode;
  u32 intersectStart = 0, intersectEnd = 0;

  // print2ndLevelHash(l);
  // print2ndLevelHash(r);

  for(lnode = l->subHash; lnode != NULL; lnode = lnode->hh_hmAddr2NodeItem.next) {
    if(lnode->addr == start)
      break;
  }
  for(rnode = r->subHash; rnode != NULL; rnode = rnode->hh_hmAddr2NodeItem.next) {
    if(rnode->addr == start)
      break;
  }
  if(lnode == NULL || rnode == NULL)
    return NULL;

  u32 currend = start + lnode->node->bytesz;
  while(currend <= end){
    if(lnode == NULL || rnode == NULL)
      break;

    if(lnode->node == rnode->node){
      if(intersectStart == 0){
        intersectStart = lnode->node->addr;
        // intersectEnd = intersectStart + lnode->node->bytesz;
      }
      else {
        // intersectEnd = intersectEnd + lnode->node->bytesz;
      }
    }

    u32 lend = lnode->node->addr + lnode->node->bytesz;
    u32 rend = rnode->node->addr + rnode->node->bytesz;
    if(lend < rend) {
      lnode = lnode->hh_hmAddr2NodeItem.next;
      currend = lend;
    }
    else if(lend > rend) {
      rnode = rnode->hh_hmAddr2NodeItem.next;
      currend = rend;
    }
    else{
      lnode = lnode->hh_hmAddr2NodeItem.next;
      rnode = rnode->hh_hmAddr2NodeItem.next;
      currend = lend;
    }
  }
  intersectEnd = currend;

  // printf("common start:%x end:%x\n", intersectStart, intersectEnd);
  if(intersectStart != 0){
    intersect_r = initRange();
    intersect_r->start = intersectStart;
    intersect_r->end = intersectEnd;
  }

  return intersect_r;

}

void
delRange(Range **r)
{
  if(*r == NULL)
    return;

  free(*r);
  *r = NULL;
}


void
printRange(Range *r, char *s)
{
  if(r == NULL){
    fprintf(stderr, "printRange: %s r:%p\n", s, r);
    return;
  }

  printf("%sstart:%x end:%x sz:%u\n", s, r->start, r->end, r->end - r->start);
}


RangeArray *
initRangeArray()
{
  RangeArray *ra;

  ra = calloc(1, sizeof(RangeArray));
  ra->rangeArySz = INIT_CONTBUFARY_SZ;
  ra->rangeAryUsed = 0;
  ra->rangeAry = calloc(1, sizeof(Range) * INIT_CONTBUFARY_SZ);
  return ra;
}

void
add2Range(RangeArray *ra, Range *r)
{
  int lo = 0, mid = lo, hi = ra->rangeAryUsed;
  while(lo < hi) {
    mid = lo + (hi - lo) / 2;
    if(ra->rangeAry[mid]->start < r->start) {
      lo = mid + 1;
    }
    else { hi = mid; }
  }
  addRange(ra, r, lo);
}

RangeArray *
getIntersectRangeArray(Addr2NodeItem *l, RangeArray *lra, Addr2NodeItem *r, RangeArray *rra)
{
  u32 idx_l = 0, idx_r = 0;
  u32 aryUsed_l = lra->rangeAryUsed, aryUsed_r = rra->rangeAryUsed;
  RangeArray *intersect_ra;
  Range *rl, *rr, *intersect_r;

  intersect_ra = initRangeArray();
  while(true) {
    if(idx_l >= aryUsed_l || idx_r >= aryUsed_r)
      break;

    rl = lra->rangeAry[idx_l];
    rr = rra->rangeAry[idx_r];

    u32 intersectStart = getMaxAddr(rl->start, rr->start);
    u32 intersectEnd = getMinAddr(rl->end, rr->end);

    if(intersectStart < intersectEnd) { // there is intersected range
      intersect_r = getIntersectRange(l, r, intersectStart, intersectEnd);
      if(intersect_r != NULL) {
        // printRange(intersect_r, "intersect range ");
        add2Range(intersect_ra, intersect_r);
      }
    }

    // if left buf range is smaller than right buf range, increases it
    // notices all bufs in buf ary are in increasing order
    if(rl->end < rr->end) { idx_l++; }
    else if(rl->end > rr->end) { idx_r++; }
    else { idx_l++; idx_r++; }
  }
  // TODO: if there is no common range, return NULL
  return intersect_ra;
}

RangeArray *
get_common_rangearray(
    HitMapAddr2NodeItem *l,
    RangeArray *lra,
    HitMapAddr2NodeItem *r,
    RangeArray *rra)
{
  u32 idx_l = 0, idx_r = 0;
  u32 aryUsed_l = lra->rangeAryUsed, aryUsed_r = rra->rangeAryUsed;
  RangeArray *intersect_ra;
  Range *rl, *rr, *intersect_r;

  intersect_ra = initRangeArray();
  while(true) {
    if(idx_l >= aryUsed_l || idx_r >= aryUsed_r)
      break;

    rl = lra->rangeAry[idx_l];
    rr = rra->rangeAry[idx_r];

    u32 intersectStart = getMaxAddr(rl->start, rr->start);
    u32 intersectEnd = getMinAddr(rl->end, rr->end);

    if(intersectStart < intersectEnd) { // there is intersected range
      intersect_r = get_common_range(l, r, intersectStart, intersectEnd);
      if(intersect_r != NULL) {
        add2Range(intersect_ra, intersect_r);
      }
    }

    // if left buf range is smaller than right buf range, increases it
    // notices all bufs in buf ary are in increasing order
    if(rl->end < rr->end) { idx_l++; }
    else if(rl->end > rr->end) { idx_r++; }
    else { idx_l++; idx_r++; }
  }
  // TODO: if there is no common range, return NULL
  return intersect_ra;
}

bool
is_rangearray_same(
    RangeArray *l,
    RangeArray *r)
{
  if(l == NULL || r == NULL) {
    return false;
  }
  else {
    if(l->rangeAryUsed != r->rangeAryUsed) {
      return false;
    }
    else {
      for(int ridx = 0; ridx < l->rangeAryUsed; ridx++) {
        Range *lr = l->rangeAry[ridx];
        Range *rr = r->rangeAry[ridx];
        if(lr->start != rr->start || lr->end != rr->end)
          return false;
      }
    }
  }
  return true;
}


void
delRangeArray(RangeArray **ra)
{
  if(*ra == NULL)
    return;

  for(int i = 0; i < (*ra)->rangeAryUsed; i++) {
    if((*ra)->rangeAry[i] != NULL) {
      delRange(&((*ra)->rangeAry[i]) );
    }
  }

  free((*ra)->rangeAry);
  (*ra)->rangeAry = NULL;

  free(*ra);
  *ra = NULL;
}

static void
addRange(RangeArray *ra, Range *r, int pos)
{
  if(pos > ra->rangeAryUsed) {
    fprintf(stderr, "addRange: pos is larger than used\n");
    return;
  }

  if(ra->rangeAryUsed == ra->rangeArySz){
    growRangeArray(ra);
  }

  for(int i = (ra->rangeAryUsed - 1); i >= pos; i--){
    ra->rangeAry[i+1] = ra->rangeAry[i];
  }
  ra->rangeAry[pos] = r;
  (ra->rangeAryUsed)++;
}

static void
growRangeArray(RangeArray *ra)
{
  Range **newRangeArray;
  u32 newRangeArySz = ra->rangeArySz * 2;

  newRangeArray = calloc(1, sizeof(Range) * newRangeArySz);
  for(int i = 0; i < ra->rangeAryUsed; i++){
    newRangeArray[i] = ra->rangeAry[i];
  }
  ra->rangeArySz = newRangeArySz;

  free(ra->rangeAry);
  ra->rangeAry = newRangeArray;
}

void
printRangeArray(RangeArray *ra, char *s)
{
  if(ra == NULL){
    fprintf(stderr, "printRangeArray: %s ra:%p\n", s, ra);
    return;
  }

  // printf("range array: total ranges:%u\n", ra->rangeAryUsed);
  for(int i = 0; i < ra->rangeAryUsed; i++) {
    printRange(ra->rangeAry[i], s);
  }
}

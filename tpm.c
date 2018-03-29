/*
 * tpm.c
 * 
 * created on 12/8/2017
 * 
 * */

#include "misc.h"
#include "tpm.h"
#include "record.h"
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


static int initSeqNo = INIT_SEQNO;  // init seqNo

/* TPMContext related */
static void 
init_tpmcontext(struct TPMContext *tpm);

/* handles different cases of source and destination when processing a record */
// u32 
// processOneXTaintRecord(struct TPMContext *tpm, u32 seqNo, u32 size, u32 srcflg, u32 srcaddr, u32 dstflag, u32 dstaddr);
static int 
processOneXTaintRecord(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], struct TPMNode1 *tempCntxt[]);

static int 
isPropagationOverwriting(u32 flag, Record *rec);

static int 
handle_src_mem(struct TPMContext *tpm, struct Record *rec, union TPMNode **src);

static int 
handle_src_reg(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], union TPMNode **src);

static int  
handle_src_temp(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *tempCntxt[], union TPMNode **src);

static int 
handle_dst_mem(struct TPMContext *tpm, struct Record *rec, union TPMNode **dst);

static int 
handle_dst_reg(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], union TPMNode **dst);

static int 
handle_dst_temp(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *tempCntxt[], union TPMNode **dst);

static void 
decreaseInitSeqNoByOne();

/* transition node */
static struct Transition *
create_trans_node(u32 ts, u32 s_type, union TPMNode* src, union TPMNode* dst);

/* validate taint propagation */
static bool 
is_equal_value(u32 val, union TPMNode *store);

/* handles adjacent memory nodes */
static int 
update_adjacent(struct TPMContext *tpm, union TPMNode *n, struct Mem2NodeHT **l, struct Mem2NodeHT **r, u32 addr, u32 bytesz);

static bool 
has_adjacent(struct TPMContext *tpm, struct Mem2NodeHT **l, struct Mem2NodeHT **r, u32 addr, u32 bytesz);

static bool 
has_left_adjacent(struct TPMContext *tpm, struct Mem2NodeHT **item, u32 addr);

static bool  
has_right_adjacent(struct TPMContext *tpm,struct Mem2NodeHT **item, u32 addr, u32 bytesz);

static bool 
link_adjacent(struct TPMNode2 *linker, struct TPMNode2 *linkee, bool is_left);

/* temp or register nodes */
static void 
clear_tempcontext(struct TPMNode1 *tempCntxt[] );

static int 
get_regcntxt_idx(u32 reg);

/* mem addr hash table */
// Returns:
//  0: success
//  <0: error
static int
add_mem_ht(struct Mem2NodeHT **mem2NodeHT, u32 addr, struct TPMNode2 *toMem);

static struct Mem2NodeHT *
find_mem_ht(struct Mem2NodeHT **mem2NodeHT, u32 addr);

static void
del_mem_ht(struct Mem2NodeHT **mem2NodeHT);

static void 
count_mem_ht(struct Mem2NodeHT **mem2NodeHT);

static void 
print_mem_ht(struct Mem2NodeHT **mem2NodeHT);

/* mem addr hash table */
static bool  
is_addr_in_ht(struct TPMContext *tpm, struct Mem2NodeHT **item, u32 addr);

/* computes all buffers in tpm */
static void 
compBufStat(
    TPMNode2 *memNode,
    u32 *baddr,
    u32 *eaddr,
    int *minseq,
    int *maxseq,
    u32 *numOfAddr,
    TPMNode2 **firstnode,
    u32 *totalNode);

static TPMNode2 *
getLeftMost(TPMNode2 *node);

static bool
isAllVersionNodeLeftMost(TPMNode2 *node);

static TPMBufHashTable *
initTPMBufHTNode(
    u32 baddr,
    u32 eaddr,
    int minseq,
    int maxseq,
    u32 numOfAddr,
    TPMNode2 *firstnode,
    u32 totalNode);

static int 
cmpTPMBufHTNode(TPMBufHashTable *l, TPMBufHashTable *r);

static void
assignNodeID(TPMNode2 *headNode, u32 bufID);

int 
buildTPM(FILE *taintfp, struct TPMContext *tpm)
/* return:
 * 	>=0: number of TPM nodes created;
 *     <0: error
 */
{
  int numOfNewNodePerRec = 0, linecnt = 0, dataRecCnt = 0, totalnode = 0;
  struct TPMNode1 *regCntxt[NUM_REG]      = {0};  // points to the latest register node
  struct TPMNode1 *tempCntxt[MAX_TEMPIDX] = {0};  // points to the latest temp node

  init_tpmcontext(tpm);

  char line[MAX_REC_SZ] = {0};
  while(fgets(line, sizeof(line), taintfp) ) { // iterates each line (record)
#ifdef DEBUG
    printf("%s", line);
#endif 
    char flag[REC_FLAG_SZ] = {0};
    if(getRecordFlag(flag, line) ) {
      if(isControlRecord(flag) ) { // contol record, simply skip except for insn mark
        if(equalRecordMark(flag, INSN_MARK) ) {
          clear_tempcontext(tempCntxt); /* clear current context of temp, due to temp are
                                                    only alive within instruction, if encounter an insn mark  
                                                    it crosses insn boundary */ 
        } 
      }
      else { // data record, creates nodes
        struct Record rec = {0};
        if(analyzeRecord(line, '\t', &rec) == 0) {
          if((numOfNewNodePerRec = processOneXTaintRecord(tpm, &rec, regCntxt, tempCntxt) ) >= 0)
          { totalnode += numOfNewNodePerRec; }
          else { return -1; }
          dataRecCnt++;
        }
        else { return -1; }
      }
    }
    else { fprintf(stderr, "error: get flag\n"); return -1; }
    linecnt++;
  }
  printf("total lines:\t%d - total data records:\t%d - total nodes: %u\n", linecnt, dataRecCnt, totalnode);
  return totalnode;
}

struct TPMNode2 *
mem2NodeSearch(struct TPMContext *tpm, u32 memaddr)
/* return:
 * 	NULL: no node founded with the memaddr
 *  non-NULL: points to the latest version of the TPM node that has the memaddr
 */
{
  struct Mem2NodeHT *item        = NULL;
  struct TPMNode2 *tpmnode2 = NULL;

  item = find_mem_ht(&(tpm->mem2NodeHT), memaddr);
  if(item == NULL) { return NULL; }
  else {
    tpmnode2 = item->toMem;
    return tpmnode2;
  }
}

union TPMNode *
seqNo2NodeSearch(struct TPMContext *tpm, u32 seqNo)
{
  union TPMNode *tpmnode = NULL;

  if(seqNo >= seqNo2NodeHashSize) {
    fprintf(stderr, "error: seqNo2NodeSearch: seqNo exceeds hash table size\n");
    return NULL;
  }
  else {
    tpmnode = tpm->seqNo2NodeHash[seqNo];
    return tpmnode;
  }
}

TPMBufContext *
initTPMBufContext(TPMContext *tpm)
{
  TPMBufContext *tpmBufCtxt   = NULL;
  TPMBufHashTable *tpmBufHash = NULL;
  int numOfBuf = 0;

  tpmBufCtxt = calloc(sizeof(TPMBufContext), 1);
  assert(tpmBufCtxt != NULL);

  tpmBufHash = analyzeTPMBuf(tpm);
  assignTPMBufID(tpmBufHash);
  numOfBuf = HASH_CNT(hh_tpmBufHT, tpmBufHash);

  tpmBufCtxt->tpmBufHash = tpmBufHash;
  tpmBufCtxt->numOfBuf = numOfBuf;

  return tpmBufCtxt;
}

void
delTPMBufContext(TPMBufContext *tpmBufCtxt)
{
  delAllTPMBuf(tpmBufCtxt->tpmBufHash);
  free(tpmBufCtxt);
  printf("del TPM buffers context.\n");
}


TPMBufHashTable *
analyzeTPMBuf(TPMContext *tpm)
{
  Mem2NodeHT *memNodeHT;
  TPMBufHashTable *tpmBufHT = NULL, *tpmBufNode, *tpmBufFound;

  TPMNode2 *memNode, *firstMemNode;
  u32 baddr, eaddr, numOfAddr, totalNode = 0;
  int minseq, maxseq;

  for(memNodeHT = tpm->mem2NodeHT; memNodeHT != NULL; memNodeHT = memNodeHT->hh_mem.next) {
    memNode = memNodeHT->toMem;
    compBufStat(memNode, &baddr, &eaddr, &minseq, &maxseq,
        &numOfAddr, &firstMemNode, &totalNode);
    if(eaddr - baddr >= tpm->minBufferSz){ // only consider bufs with sz satisfies the min requirement
      // printf("-----\nbaddr:%x eaddr:%x minSeqN:%d maxSeqN:%d numOfAddr:%u firstMemNode:%p\n",
      //         baddr, eaddr, minseq, maxseq, numOfAddr, firstMemNode);
      // printMemNode(firstMemNode);
      assert(firstMemNode->version == 0);
      assert(firstMemNode->leftNBR == NULL);
      tpmBufNode = initTPMBufHTNode(baddr, eaddr, minseq, maxseq,
          numOfAddr, firstMemNode, totalNode);

      HASH_FIND(hh_tpmBufHT, tpmBufHT, &firstMemNode, 4, tpmBufFound);
      if(tpmBufFound == NULL) {
        HASH_ADD(hh_tpmBufHT, tpmBufHT, headNode, 4, tpmBufNode);
      }
      else { free(tpmBufNode); }
    }
  }
  HASH_SRT(hh_tpmBufHT, tpmBufHT, cmpTPMBufHTNode);
  // printTPMBufHashTable(tpmBufHT);
  return tpmBufHT;
}

void
assignTPMBufID(TPMBufHashTable *tpmBuf)
{
  TPMBufHashTable *node, *temp;
  u32 bufid = 1;

  HASH_ITER(hh_tpmBufHT, tpmBuf, node, temp) {
    TPMNode2 *headNode = node->headNode;
    assignNodeID(headNode, bufid);
    // printBufNode(headNode);
    bufid++;
  }
  printTPMBufHashTable(tpmBuf);
}

TPMBufHashTable *
getTPMBuf(TPMBufHashTable *bufHead, u32 bufIdx)
{
  u32 idx = 0;
  while(bufHead != NULL && idx < bufIdx) {
    bufHead = bufHead->hh_tpmBufHT.next;
    idx++;
  }
  return bufHead;
}


int
getTPMBufTotal(TPMBufHashTable *tpmBuf)
{
  int bufcnt = 0;
  bufcnt = HASH_CNT(hh_tpmBufHT, tpmBuf);
  return bufcnt;
}

u32
getTPMBufNodeTotal(TPMBufHashTable *tpmBuf)
{
  u32 nodeCnt = 0;
  TPMNode2 *head = tpmBuf->headNode;
  while(head != NULL) {
    u32 ver = head->version;
    do{
      nodeCnt++;
      head = head->nextVersion;
    } while(ver != head->version);

    head = head->rightNBR;
  }
  return nodeCnt;
}


u32
getTPMBufMaxSeqN(TPMBufHashTable *tpmBuf)
// Returns:
//  max seqNo of the last buffer in tpm
//  0: error
{
  u32 maxSeqN = 0;
  TPMBufHashTable *buf;

  if(tpmBuf == NULL)
    return 0;

  buf = tpmBuf;
  while(buf != NULL) {
    if(buf->maxseq > 0 && buf->maxseq > maxSeqN)
      maxSeqN = buf->maxseq;

    buf = buf->hh_tpmBufHT.next;
  }
  // maxSeqN = buf->maxseq;
  return maxSeqN;
}

int
getTPMBufAddrIdx(
    u32 bufID,
    u32 addr,
    TPMBufHashTable *tpmBuf)
{
  int addrIdx = 0;
  TPMNode2 *headNode;
  TPMBufHashTable *buf;

  if(bufID == 0 || addr == 0 || tpmBuf == NULL) {
    fprintf(stderr, "bufID:%u addr:%x tpmBuf:%p\n", bufID, addr, tpmBuf);
    return -1;
  }
  // printTPMBufHashTable(tpmBuf);
  // printf("getTPMBufAddrIdx: bufID:%u addr:%x\n", bufID, addr);

  buf = tpmBuf;
  while(buf->hh_tpmBufHT.next != NULL) {
    // printMemNodeLit(buf->headNode);
    if(buf ->headNode->bufid == bufID)
      break;

    buf = buf->hh_tpmBufHT.next;
  }

  headNode = buf->headNode;
  while(headNode != NULL) {
    if(headNode->addr == addr)
      break;

    // printMemNode(headNode);
    headNode = headNode->rightNBR;
    addrIdx++;
  }
  // printf("addrIdx:%d\n", addrIdx);
  return addrIdx;
}


void
delAllTPMBuf(TPMBufHashTable *tpmBuf)
{
  TPMBufHashTable *curr, *tmp;

  if(tpmBuf == NULL)
    return;

  HASH_ITER(hh_tpmBufHT, tpmBuf, curr, tmp){
    HASH_DELETE(hh_tpmBufHT, tpmBuf, curr);
    free(curr);
  }
  // printf("del tpm buffers\n");
}


void delTPM(struct TPMContext *tpm)
{
  del_mem_ht(&(tpm->mem2NodeHT) ); // clear mem addr hash table
  free(tpm);                       // TODO: merge in delTPM()

  printf("del TPM\n");
  // TODO:
  // - free TPMBufHashTable
}

TPMNode *
getTransitionDst(Transition *transition)
{
  if(transition != NULL)
    return transition->child;
  else
    return NULL;
}

u32
getTransitionChildrenNum(Transition *firstChild)
{
  u32 num = 0;
  while(firstChild != NULL) {
    num++;
    firstChild = firstChild->next;
  }
  return num;
}

void
printTrans1stChild(union TPMNode *head)
{
  struct Transition *t = head->tpmnode1.firstChild;

  while(t != NULL) {
    if(t->child->tpmnode1.type == TPM_Type_Memory) {
      printMemNode(&(t->child->tpmnode2) );
    }
    else if(t->child->tpmnode1.type == TPM_Type_Register
        || t->child->tpmnode1.type == TPM_Type_Temprary){
      printNonmemNode(&(t->child->tpmnode1) );
    }
    else { fprintf(stderr, "error: print trans: unkown type\n"); break; }

    t = t->next;
  }
}

void
print1Trans(Transition *transition)
{
  if(transition == NULL)
    return;

  printf("Transition: seqN:%u hasVisit:%d\n", transition->seqNo, transition->hasVisit);
}


void
printTransAllChildren(Transition *transition)
{
  u32 numOfTrans = 0;

  while(transition != NULL) {
    printf("----------\nTransition:%p\n seqNo:%u\n", transition, transition->seqNo);
    printf("Child:\n");
    printNode(transition->child);

    numOfTrans++;
    transition = transition->next;
  }
  printf("total number of children transitions:%u\n", numOfTrans);
}

void 
print1TPMBufHashTable(char *s, TPMBufHashTable *tpmBufHT)
{
  TPMBufHashTable *buf = tpmBufHT;
  printf("%sstart:%-8x end:%-8x sz:%u minseq:%-d maxseq:%-d diffSeq:%-d bufID:%u\n",
      s, buf->baddr, buf->eaddr, buf->eaddr - buf->baddr,
      buf->minseq, buf->maxseq, (buf->maxseq - buf->minseq), buf->headNode->bufid);
}

void
printTPMBufHashTable(TPMBufHashTable *tpmBufHT)
{
  TPMBufHashTable *buf, *temp;
  int bufcnt;
  u32 avg_node, minNode, maxNode, totalNode;

  bufcnt = HASH_CNT(hh_tpmBufHT, tpmBufHT);
  printf("---------------------\ntotal buf:%d - min buf sz:%u\n",bufcnt, MIN_BUF_SZ);

  totalNode = 0;
  minNode = tpmBufHT->totalNode;
  maxNode = tpmBufHT->totalNode;

  HASH_ITER(hh_tpmBufHT, tpmBufHT, buf, temp) {
    printf("begin:0x%-8x end:0x%-8x sz:%-4u numofaddr:%-4u minseq:%-7d maxseq:%-7d diffseq:%-7d bufID:%-4u total nodes:%u\n",
        buf->baddr, buf->eaddr, buf->eaddr - buf->baddr,
        buf->numOfAddr, buf->minseq, buf->maxseq, (buf->maxseq - buf->minseq),
        buf->headNode->bufid, buf->totalNode);
    // printBufNode(buf->headNode);

    if(buf->totalNode < minNode)
      minNode = buf->totalNode;
    if(buf->totalNode > maxNode)
      maxNode = buf->totalNode;
    totalNode += buf->totalNode;
  }
  printf("minimum num of node:%u - maximum num of node:%u - total num of node:%u "
      "- total buf:%u - avg num of node:%u\n",
      minNode, maxNode, totalNode, bufcnt, totalNode / bufcnt);
}

static void 
init_tpmcontext(struct TPMContext *tpm)
{
  tpm->nodeNum        = 0;
  tpm->memAddrNum     = 0;
  tpm->tempVarNum     = 0;
  tpm->mem2NodeHT     = NULL;
  // tpm->seqNo2NodeHT   = NULL;
  tpm->minBufferSz    = MIN_BUF_SZ;
  tpm->taintedBufNum  = 0;
  tpm->taintedbuf     = NULL;
}

static int 
processOneXTaintRecord(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], struct TPMNode1 *tempCntxt[])
/* return:
 *  >=0 : success and num of nodes creates
 *     <0: error
 *  1. handle source
 *  2. handle destination
 *  3. creates transition between source to destination
 */
{
  int type, srctype, newsrc = 0, newdst = 0;
  union TPMNode *src = NULL, *dst = NULL;

#ifdef DEBUG
  printf("--------------------\nprocessing record:\n");
  printRecord(rec);
#endif

  //  handle source node
  if(rec->is_load) { // src is mem addr
    if( (newsrc = handle_src_mem(tpm, rec, &src) ) >= 0 ) {}
    else { return -1; }
    srctype = TPM_Type_Memory;
  }
  else { // src is either reg or temp
    type = getNodeType(rec->s_addr);
    if (type == TPM_Type_Register) {
      if( (newsrc = handle_src_reg(tpm, rec, regCntxt, &src) ) >= 0 ) {}
      else { return -1; }
      srctype = type;
    }
    else if (type == TPM_Type_Temprary) {
      if((newsrc = handle_src_temp(tpm, rec, tempCntxt, &src)) >= 0) {}
      else { return -1; }
      srctype = type;
    }
    else { return -1; }
  }

  //  hanlde destination node
  if(rec->is_store || rec->is_storeptr) { // dst is mem addr (include store ptr)
    if((newdst =  handle_dst_mem(tpm, rec, &dst) ) >= 0) {}
    else { return -1; }
  }
  else { // dst is either reg or temp
    type = getNodeType(rec->d_addr);
    if(type == TPM_Type_Register) {
      if((newdst = handle_dst_reg(tpm, rec, regCntxt, &dst) ) >= 0) {}
      else { return -1; }
    }
    else if(type == TPM_Type_Temprary) {
      if((newdst = handle_dst_temp(tpm, rec, tempCntxt, &dst) ) >= 0) {}
      else { return -1; }
    }
    else { return -1; }
  }

  //  creates transition node, binds the transition node pointer to src
  if( (create_trans_node(rec->ts, srctype, src, dst) ) != NULL) {}
  else { return -1; }

  return newsrc+newdst;
}

static int 
isPropagationOverwriting(u32 flag, Record *rec)
/* return:
 *  0: not overwriting
 *  1: overwriting
 *  <0: error
 */
{
  // Due to allow source and destination are same. always overwrite
  if(flag == TCG_XOR_i32 && rec->s_addr != rec->d_addr)
    return 0;
  else
    return 1;
  /* to be added */
  switch(flag) {
    case TCG_LD_i32:
    case TCG_ST_i32:
    case TCG_LD_POINTER_i32:
    case TCG_ST_POINTER_i32: 
    case TCG_NOT_i32:
    case TCG_NEG_i32:
    case TCG_EXT8S_i32:
    case TCG_EXT16S_i32:
    case TCG_EXT8U_i32:
    case TCG_EXT16U_i32:
    case TCG_BSWAP16_i32:
    case TCG_BSWAP32_i32:
    case TCG_SHL_i32:
    case TCG_SHR_i32:
    case TCG_SAR_i32:
    case TCG_ROTL_i32:
    case TCG_ROTR_i32:
    case TCG_MOV_i32:
    case TCG_DEPOSIT_i32:
      return 1;
    case TCG_ADD_i32:
    case TCG_SUB_i32:
    case TCG_MUL_i32:
    case TCG_DIV_i32:
    case TCG_DIVU_i32:
    case TCG_REM_i32:
    case TCG_REMU_i32:
    case TCG_MUL2_i32:
    case TCG_DIV2_i32:
    case TCG_DIVU2_i32:
    case TCG_AND_i32:
    case TCG_OR_i32:
    case TCG_XOR_i32:
    case TCG_SETCOND_i32:
      return 0;
    default:
      fprintf(stderr, "unkown Qemu IR enode:%-2u\n", flag);
      return 1;
  }
}

static int 
handle_src_mem(struct TPMContext *tpm, struct Record *rec, union TPMNode **src)
// Returns
//  >=0: num of new nodes creates 
//  <0: error 
//  stores the created or found node pointer in src 
// 
//  1. detects if src's addr is in mem hash table (tpm->Mem2NodeHT)
//  1.1 not found: new addr
//      a) creates new node
//         1) init "version" to 0 (the earliest)
//         2) init seqNo (lastUpdatTS) to -1
//      b) updates:
//         1) the mem hash table (tpm->Mem2NodeHT): hash(addr) -> it
//         2) !(not use)seqNo hash table (tpm->seqNo2NodeHash): hash(seqNo) -> it
//  1.2 found
//      !!! detects if the value of the mem equals the val of the latest version 
//      of the same addr, due to if same, it's a valid taint propagation. (shoudl be)
//  1.2.1 the values are same
//      a) it's valid propagation, do nothing
//  1.2.2 the values are different (!!! this case should not happen, due to its source)
//      a) creates a new node
//         1) init version as previous version plus one
//         2) init seqNo (lastUpdatTS) to -1
//      b) updates its previous version pointer (prev->nextversion points to it)
//      b) updates same as 1.1 b)
//  2. updates neighbours: 
//  2.1 detects if its left neighbour exists (could be 4, 2, 1 bytes)
//      a) yes, updates its leftNBR points to the earliest version of its left adjcent mem node 
//      b) no, do nothing
//  2.2 detects if its right neighbour exist, similar to 2.1, and updates it's rightNBR accordingly
{
  int numNewNode = 0;
  struct Mem2NodeHT *src_hn = NULL, *left = NULL, *right = NULL;

  if(is_addr_in_ht(tpm, &src_hn, rec->s_addr) ) { // in TPM
    /* temporarily disable the sanity check */
    // if(is_equal_value(rec->s_val, src_hn->toMem ) ) {
    //     *src = src_hn->toMem;
    // }
    // else {
    //     fprintf(stderr, "error: handle src memory: values are not matched\n");
    //     return -1;
    // }
    *src = (union TPMNode*)src_hn->toMem;
#ifdef DEBUG
    printf("\thandle src mem: addr:0x%-8x found in hash table\n", rec->s_addr);
    printMemNode(*src);
#endif       
  }
  else { // not found
    *src = create1stVersionMemNode(rec->s_addr, rec->s_val, initSeqNo, rec->bytesz);
    decreaseInitSeqNoByOne();
#ifdef DEBUG
    printf("\taddr:0x%-8x not found in hash table, creates new mem node\n", rec->s_addr);
    printMemNode(&( (*src)->tpmnode2) );
#endif       
    // updates hash table
    if(add_mem_ht( &(tpm->mem2NodeHT), rec->s_addr, &( (*src)->tpmnode2) ) >= 0 ){}
    else { fprintf(stderr, "error: handle source mem: add_mem_ht\n"); return -1; }
#ifdef DEBUG
    count_mem_ht(&(tpm->mem2NodeHT) );
    print_mem_ht(&(tpm->mem2NodeHT) );
#endif       
    tpm->seqNo2NodeHash[rec->s_ts] = *src; // updates seqNo hash table
    numNewNode++;
  }
  // updates adjacent mem node if any
  if(update_adjacent(tpm, *src, &left, &right, rec->s_addr, rec->bytesz) >= 0) {}
  else { return -1; }

  return numNewNode;
}

static int 
handle_src_reg(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], union TPMNode **src)
// Returns
//  >=0: num of new nodes creates 
//  <0: error 
//  stores the created or found node pointer in src 
//
//  1. detects if register is in the register context array (regCntxt)
//  1.1 not found: new register
//      a) creates new register node (lastUpdateTS -1)
//      b) updates:
//         1) reg context array: regCntxt[reg id] -> it
//         2) seqNo hash table (tpm->seqNo2NodeHash): hash(seqNo) -> it
//  1.2 found
//      !!! verifies if the value of the reg equals to the one stored in reg context [reg id] 
//      due to if same, it's a valid taint propagation. (shoudl be)
{
  int regid = -1, numNewNode = 0;

  if((regid = get_regcntxt_idx(rec->s_addr) ) >= 0) {
    if(regCntxt[regid] == NULL) { // not found
      *src = createTPMNode(TPM_Type_Register, rec->s_addr, rec->s_val, -1, 0);
      regCntxt[regid] = &((*src)->tpmnode1);  // updates reg context
      tpm->seqNo2NodeHash[rec->s_ts] = *src;  // updates seqNo hash table
      numNewNode++;
#ifdef DEBUG
      printf("reg: %x not found in regCntxt, creates new reg node\n", rec->s_addr);
      printNonmemNode(&( (*src)->tpmnode1) );
      printf("reg: %x - id: %d - addr of the node: %p\n", rec->s_addr, regid, regCntxt[regid]);
#endif                  
    }
    else { // found
      // disable the sanity check first
      // if(is_equal_value(rec->s_val, regCntxt[regid] ) ) {
      //     *src = regCntxt[regid];
      // }
      // else {
      //     fprintf(stderr, "error: handle src reg: values are not matched\n");
      //     return -1;
      // }
      *src = (union TPMNode*)regCntxt[regid];
#ifdef DEBUG
      printf("\thandle src reg: found reg in regCntxt\n");
      printNonmemNode(regCntxt[regid]);
#endif      
    }
  }
  else { return -1; } // error

  return numNewNode;
}

static int  
handle_src_temp(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *tempCntxt[], union TPMNode **src)
// Returns
//  >=0: num of new nodes creates 
//  <0: error 
//  stores the created or found node pointer in src 
//
//  1. detects if temp is in the temp context array (tempCntxt)
//  1.1 not found: new temp
//      a) creates new temp node (set lastUpdateTS to -1)
//      b) updates:
//         1) temp context array: tempCntxt[temp id] -> it
//         2) seqNo hash table (tpm->seqNo2NodeHash): hash(seqNo) -> it
//  1.2 found
//      !!! verifies if the value of the temp equals to the one stored in temp context [temp id] 
//      due to if same, it's a valid taint propagation. (shoudl be)
{   int numNewNode = 0;

if(rec->s_addr >= 0xfff0 || rec->s_addr >= MAX_TEMPIDX) {
  fprintf(stderr, "error: temp idx larger than register idx or max temp idx\n");
  return -1;
}

if(tempCntxt[rec->s_addr] == NULL) { // not found, creates new node
  *src = createTPMNode(TPM_Type_Temprary, rec->s_addr, rec->s_val, -1, 0);
  tempCntxt[rec->s_addr] = &((*src)->tpmnode1);  // updates temp context
  tpm->seqNo2NodeHash[rec->s_ts] = *src;         // updates seqNo hash table
  numNewNode++;
#ifdef DEBUG
  printf("\ttemp: %u not found in tempCntxt, creates new temp node\n", rec->s_addr);
  printNonmemNode(&((*src)->tpmnode1));
  printf("\ttemp: %u - addr of the node: %p\n", rec->s_addr, tempCntxt[rec->s_addr]);
#endif      
}
else {  // found
  // disable the sanity check
  // if(is_equal_value(rec->s_val, tempCntxt[rec->s_addr] ) ) {
  //     *src = tempCntxt[rec->s_addr];
  // }
  // else {
  //     fprintf(stderr, "error: handle src temp: values are not matched\n");
  //     return -1;
  // }
  *src = (union TPMNode*)tempCntxt[rec->s_addr];
#ifdef DEBUG
  printf("\thandle src temp: found temp in tempCntxt\n");
  printNonmemNode(tempCntxt[rec->s_addr]);
#endif      
}
return numNewNode;
}

static int 
handle_dst_mem(struct TPMContext *tpm, struct Record *rec, union TPMNode **dst)
// Returns
//  >=0: num of new nodes creates 
//  <0: error 
//  stores the created or found node pointer in dst 
//
//  1. detects if it's a overwrite or "addition" operation
//  1.1 overwrite operation (mov)
//      1) detects if its addr is in mem hash table
//         a) yes
//            - creates a new node (set the lastUpdateTS to rec #)
//            - set the version accordingly
//            - attach it to the version list 
//         b) no: a new addr
//            - creates a new node
//            - init version to 0
//      2) updates the mem hash table: hash(addr) -> it
//  1.2 "addition" operation (add, xor...)
//      1) detects if its addr is in the mem hash table
//         a) yes
//            !!! verifies if the value equals the val of the latest version
//            updates the lastUpdateTS to rec #
//         b) no
//            - creates a new node
//            - init version number
//            - updates the mem hash table: hash(addr) -> it
//            - updates seqNo hash table
//  2. updates neighbours: 
//  2.1 detects if its left neighbour exists (could be 4, 2, 1 bytes)
//      a) yes, updates its leftNBR points to the earliest version of its left adjcent mem node 
//      b) no, do nothing
//  2.2 detects if its right neighbour exist, similar to 2.1, and updates it's rightNBR accordingly
{
  int numNewNode = 0;
  u32 version = 0;
  struct Mem2NodeHT *dst_hn = NULL, *left = NULL, *right = NULL;

  if(isPropagationOverwriting(rec->flag, rec) ) { // overwrite
    if( is_addr_in_ht(tpm, &dst_hn, rec->d_addr) ) { // in TPM
      *dst = createTPMNode(TPM_Type_Memory, rec->d_addr, rec->d_val, rec->ts, rec->bytesz);
      version = getMemNodeVersion(dst_hn->toMem);
      setMemNodeVersion(*dst, version+1); // set version accordingly
      addNextVerMemNode(dst_hn->toMem, &( (*dst)->tpmnode2) );
#ifdef DEBUG
      printMemNode(dst_hn->toMem);
      printMemNode(&( (*dst)->tpmnode2) );
      printf("\tversion:\n");
      printMemNodeAllVersion(dst_hn->toMem);
#endif      
    }
    else { // not in TPM
      *dst = create1stVersionMemNode(rec->d_addr, rec->d_val, rec->ts, rec->bytesz);
    }

    // updates mem hash table
    if(add_mem_ht( &(tpm->mem2NodeHT), rec->d_addr, &( (*dst)->tpmnode2) ) >= 0) {}
    else { fprintf(stderr, "error: handle destination mem: add_mem_ht\n"); return -1; }

    tpm->seqNo2NodeHash[rec->d_ts] = *dst;   // updates seqNo hash table
    numNewNode++;
  }
  else {  // non overwring
    if(is_addr_in_ht(tpm, &dst_hn, rec->d_addr) ) {
      printf("handle dst mem - non overwriting - TODO: verifies if values are same\n");
      return -1;  // TODO
    }
    else { // not found
      *dst = create1stVersionMemNode(rec->d_addr, rec->d_val, rec->ts, rec->bytesz);
      tpm->seqNo2NodeHash[rec->d_ts] = *dst;   // updates seqNo hash table
      numNewNode++;
    }
    // both cases, updates mem hash table
    if(add_mem_ht( &(tpm->mem2NodeHT), rec->d_addr, &( (*dst)->tpmnode2) ) >= 0) {}
    else { return -1; }
  }

  // updates adjacent mem node if any
  if(update_adjacent(tpm, *dst, &left, &right, rec->d_addr, rec->bytesz) >= 0) {}
  else { return -1; }

  return numNewNode;
}

static int 
handle_dst_reg(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], union TPMNode **dst)
// Returns
//  >=0 success, and number of new nodes creates
//  <-0 error
//  the created node stores in dst
//  1 determines if it's in TPM: regCntxt has its register id
//  1.1 No
//      a) creates a new node (lastUpdateTS -1)
//      b) updates the register context: regCntxt[reg_id] -> created node
//      c) updates the seqNo hash table
//  1.2 Yes: determines if its overwrite or "addition" operation
//  1.2.1 overwrite (mov)
//      a) creates a new node (lastUpdateTS -1)
//      b) updates the register context: regCntxt[reg_id] -> created node
//      c) updates the seqNo hash table
//  1.2.2 "addtion" (add, xor, etc)
//      a) verifies that the value of register and the one found in the regCntxt should be same
{
  int id = -1, numNewNode = 0;

  if((id = get_regcntxt_idx(rec->d_addr) ) >= 0) {
    if(regCntxt[id] == NULL){ // not in tpm
      *dst = createTPMNode(TPM_Type_Register, rec->d_addr, rec->d_val, -1, 0);
      regCntxt[id] = &( (*dst)->tpmnode1);
      tpm->seqNo2NodeHash[rec->d_ts] = *dst;   // updates seqNo hash table
      numNewNode++;
    }
    else { // in tpm
      if(isPropagationOverwriting(rec->flag, rec) ) { // overwrite
        *dst = createTPMNode(TPM_Type_Register, rec->d_addr, rec->d_val, -1, 0);
        regCntxt[id] = &( (*dst)->tpmnode1);
        tpm->seqNo2NodeHash[rec->d_ts] = *dst;   // updates seqNo hash table
        numNewNode++;
      }
      else { // non overwrite
#ifdef DEBUG
        printf("\thandle dst reg: non overwrite hit\n");
#endif         
        /* disable the sanity check */
        // if(is_equal_value(rec->d_val, regCntxt[id]) ) {
        //     *dst = regCntxt[id];
        // }
        // else {
        //     fprintf(stderr, "error: values are not equal\n");
        //     print_nonmem_node(regCntxt[id]);
        //     return -1;
        // }
        *dst = (union TPMNode*)regCntxt[id];
        // TODO: update the seqNo hash table
      }
    }
  }
  else { return -1; }

  return numNewNode;
}

static int 
handle_dst_temp(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *tempCntxt[], union TPMNode **dst)
// Returns
//  >=0 success, and number of new nodes creates
//  <-0 error
//  the created node stores in dst
//  1 determines if it's in TPM: tempCntxt has its temp id
//  1.1 No
//      a) creates a new node (lastUpdateTS -1)
//      b) updates the temp context: tempCntxt[temp_id] -> created node
//      c) updates the seqNo hash table
//  1.2 Yes: determines if its overwrite or "addition" operation
//  1.2.1 overwrite (mov)
//      a) creates a new node (lastUpdateTS -1)
//      b) updates the temp context: tempCntxt[temp_id] -> created node
//      c) updates the seqNo hash table
//  1.2.2 "addtion" (add, xor, etc)
//      a) verifies that the value of temp and the one found in the tempCntxt should be same
{
  int numNewNode = 0;

  if(rec->d_addr >= 0xfff0 || rec->d_addr >= MAX_TEMPIDX) {
    fprintf(stderr, "error: temp idx larger than register idx or max temp idx\n");
    return -1;
  }

  if(tempCntxt[rec->d_addr] == NULL) { // Not in TPM
    *dst = createTPMNode(TPM_Type_Temprary, rec->d_addr, rec->d_val, -1, 0);
    tempCntxt[rec->d_addr] = &( (*dst)->tpmnode1);
    tpm->seqNo2NodeHash[rec->d_ts] = *dst;   // updates seqNo hash table
    numNewNode++;
  }
  else { // in TPM
    if(isPropagationOverwriting(rec->flag, rec) ) { // overwrite
      *dst = createTPMNode(TPM_Type_Temprary, rec->d_addr, rec->d_val, -1, 0);
      tempCntxt[rec->d_addr] = &( (*dst)->tpmnode1);
      tpm->seqNo2NodeHash[rec->d_ts] = *dst;   // updates seqNo hash table
      numNewNode++;
    }
    else { // non overwrite
#ifdef DEBUG
      printf("\thandle dst temp: non overwrite hit\n");
#endif                             
      /* disable the sanity check */
      // if(is_equal_value(rec->d_val, tempCntxt[rec->d_addr]) ) {
      //     *dst = tempCntxt[rec->d_addr];
      // }
      // else {
      //     fprintf(stderr, "error: values are not equal\n");
      //     print_nonmem_node(tempCntxt[rec->d_addr]);
      //     return -1;
      // }
      *dst = (union TPMNode*)tempCntxt[rec->d_addr];
      // TODO: update the seqNo hash table
    }
  }
  return numNewNode;
}

static void 
decreaseInitSeqNoByOne()
{
  initSeqNo--;
}

static struct Transition *
create_trans_node(u32 ts, u32 s_type, union TPMNode *src, union TPMNode *dst)
// Returns
//  pointer of the created transition node 
//  NULL : error 
{
  if(src == NULL || dst == NULL) {
    fprintf(stderr, "error: create trans node: src: %p - dst: %p\n", src, dst);
    return NULL;
  }

  struct Transition *t, *tmp;

  t = (struct Transition*)calloc(1, sizeof(struct Transition) );
  t->seqNo = ts; // timestamp
  t->child = dst;
  t->next = NULL;
  t->hasVisit = 0;

  if(s_type & TPM_Type_Memory) {
    if(src->tpmnode2.firstChild == NULL) { // no trans node
      src->tpmnode2.firstChild = t;
      return t;
    }
    else { tmp = src->tpmnode2.firstChild; }
  }
  else if(s_type & TPM_Type_Temprary || s_type & TPM_Type_Register) {
    if(src->tpmnode1.firstChild == NULL) {
      src->tpmnode1.firstChild = t;
      return t;
    }
    else { tmp = src->tpmnode1.firstChild; }
  }
  else {
    fprintf(stderr, "error: create trans node: unkown src type\n");
    return NULL;
  }

  while(tmp->next != NULL) { tmp = tmp->next; }   // reaches last child
  tmp->next = t;  // links t to list end

  return t;
}

static bool 
is_equal_value(u32 val, union TPMNode *store)
// Returns 
//  t: if values equal
//  f: otherwise
{
  if( store == NULL)
    return false;

  if(val == store->tpmnode1.val) { return true; }
  else { return false; }
}

static int 
update_adjacent(struct TPMContext *tpm, union TPMNode *n, struct Mem2NodeHT **l, struct Mem2NodeHT **r, u32 addr, u32 bytesz)
// Returns:
//  >0: if has any update
//  0: no update
//  <0: error
{
  if(tpm == NULL || n == NULL) {
    fprintf(stderr, "error: update adjacent - tpm: %p - n: %p\n", tpm, n);
    return -1;
  }

  bool is_left = false;
  struct TPMNode2 *self = NULL;

  if(has_adjacent(tpm, l, r, addr, bytesz) ) {
    struct TPMNode2 *earliest = NULL;
    if(*l != NULL){
      earliest = (*l)->toMem;
      if(getMemNode1stVersion(&earliest) == 0) {
        is_left = true;
        link_adjacent(&(n->tpmnode2), earliest, is_left);   // update the self leftNBR

        self = &(n->tpmnode2);
        if(getMemNode1stVersion(&self) == 0) {
          is_left = false;
          link_adjacent(earliest, self, is_left); // updates the target rightNBR
        }
        else { return -1; }
      }
      else { return -1; }


    }

    if(*r != NULL){
      earliest = (*r)->toMem;
      if(getMemNode1stVersion(&earliest) == 0) {
        is_left = false;
        link_adjacent(&(n->tpmnode2), earliest, is_left); // updates the self rightNBR

        self = &(n->tpmnode2);
        if(getMemNode1stVersion(&self) == 0) {
          is_left = true;
          link_adjacent(earliest, self, is_left); // updates the target leftNBR
        }
      }
      else { return -1; }
    }
    return 1;
  }
  else { return 0; }
}

static bool 
has_adjacent(struct TPMContext *tpm, struct Mem2NodeHT **l, struct Mem2NodeHT **r, u32 addr, u32 bytesz)
// Returns:
//  1: if has either left or right adjacent mem node
//  0: otherwise
{
  bool rl = false, rr = false;

  rl = has_left_adjacent(tpm, l, addr);
  rr = has_right_adjacent(tpm, r, addr, bytesz);

  if( rl || rr ) {
    return true;
  }
  else { return false; }
}

static bool 
has_left_adjacent(struct TPMContext *tpm, struct Mem2NodeHT **item, u32 addr)
// Returns:
//  t: if has left adjacent mem node
//  f: otherwise
{
  *item = NULL;
  u32 l_adjcnt;

  l_adjcnt = addr - DWORD;    // try 4 bytes first
  *item = find_mem_ht( &(tpm->mem2NodeHT), l_adjcnt);
  if(*item != NULL) {
#ifdef DEBUG
    printf("has left adjacent: addr: 0x%x\n", (*item)->toMem->addr);
#endif
    return true;
  }else { // doesn't find 4 bytes left adjacent
    l_adjcnt = addr - WORD; // try 2 bytes
    *item = find_mem_ht( &(tpm->mem2NodeHT), l_adjcnt);
    if(*item != NULL) {
#ifdef DEBUG
      printf("has left adjacent: addr: 0x%x\n", (*item)->toMem->addr);
#endif                                
      return true;
    }
    else {
      l_adjcnt = addr - BYTE; // try 1 byte
      *item = find_mem_ht( &(tpm->mem2NodeHT), l_adjcnt);
      if(*item != NULL) {
#ifdef DEBUG
        printf("has left adjacent: addr: 0x%x\n", (*item)->toMem->addr);
#endif                                               
        return true;
      }
      else { return false; }
    }
  }
}

static bool 
has_right_adjacent(struct TPMContext *tpm, struct Mem2NodeHT **item,  u32 addr, u32 bytesz)
// Returns:
//  t: if has right adjacent mem node
//  f: otherwise
{
  u32 r_adjcnt = addr + bytesz;
  *item = NULL;

  *item = find_mem_ht( &(tpm->mem2NodeHT), r_adjcnt);
  if(*item != NULL) {
#ifdef DEBUG
    printf("has right adjacent: addr: 0x%x\n", (*item)->toMem->addr);
#endif                                                   
    return true;
  }
  else { return false; }
}

static bool 
link_adjacent(struct TPMNode2 *linker, struct TPMNode2 *linkee, bool is_left)
// Returns:
//  true: success
//  false: error
//  links the linkee to the linker's leftNBR or rightNBR based on is_left
{
  if(linker == NULL || linkee == NULL) {
    fprintf(stderr, "error: link adjacent: linker:%p linkee:%p\n", linker, linkee);
    return false;
  }

  if(is_left) { linker->leftNBR = linkee; }
  else { linker->rightNBR = linkee; }

  return true;
}

static void 
clear_tempcontext(struct TPMNode1 *tempCntxt[] )
{
  for(int i = 0; i < MAX_TEMPIDX; i++) {
    tempCntxt[i] = NULL;
  }
}

static int 
get_regcntxt_idx(u32 reg)
// Returns:
//  idx of the register in regCntxt
//  <0: error
{
  if(reg >= 0xfff0 && reg <= 0xfffd) { return (reg & REG_IDX_MASK); }
  else {
    fprintf(stderr, "error: get regcntxt idx: wrong reg\n");
    return -1;
  }
}

int
add_mem_ht(struct Mem2NodeHT **mem2NodeHT, u32 addr, struct TPMNode2 *toMem)
{
  struct Mem2NodeHT *s;

  if(mem2NodeHT == NULL || toMem == NULL)
    return -1;

  s = find_mem_ht(mem2NodeHT, addr);
  if(s == NULL) { // if not found, creates new
    s = (struct Mem2NodeHT*)malloc(sizeof(struct Mem2NodeHT) );
    s->addr = addr;
    HASH_ADD(hh_mem, *mem2NodeHT, addr, 4, s);
    s->toMem = toMem;
  } else {    // if found, updates
    s->toMem = toMem;
  }

  return 0;
}

/* mem addr hash table */
static struct Mem2NodeHT *
find_mem_ht(struct Mem2NodeHT **mem2NodeHT, u32 addr)
{
  struct Mem2NodeHT *s;
  HASH_FIND(hh_mem, *mem2NodeHT, &addr, 4, s);
  return s;
}

static void
del_mem_ht(struct Mem2NodeHT **mem2NodeHT)
{
  struct Mem2NodeHT *curr, *tmp;
  HASH_ITER(hh_mem, *mem2NodeHT, curr, tmp) {
    HASH_DELETE(hh_mem, *mem2NodeHT, curr);
    free(curr);
  }
}

static void 
count_mem_ht(struct Mem2NodeHT **mem2NodeHT)
{
  u32 num;
  num = HASH_CNT(hh_mem, *mem2NodeHT);
  printf("total: %u mem addr in hash table\n", num);
}

static void 
print_mem_ht(struct Mem2NodeHT **mem2NodeHT)
{
  struct Mem2NodeHT *s;
  for(s = *mem2NodeHT; s != NULL; s = s->hh_mem.next) {
    printf("mem - addr: %x - to mem node: %p\n", s->addr, s->toMem);
  }
}

static bool  
is_addr_in_ht(struct TPMContext *tpm, struct Mem2NodeHT **item, u32 addr)
// Returns:
//  t: if has mem node
//  f: if not found 
//      found item stored in *item
{   
  *item = NULL;
  *item = find_mem_ht( &(tpm->mem2NodeHT), addr);
  if( (*item) != NULL) { return 1; }
  else { return 0; }
}

static void 
compBufStat(
    TPMNode2 *memNode,
    u32 *baddr,
    u32 *eaddr,
    int *minseq,
    int *maxseq,
    u32 *numOfAddr,
    TPMNode2 **firstnode,
    u32 *totalNode)
// retruns the begin/end addresses, minseq(>0) maxseq of a given buffer(mem node)
{
  TPMNode2 *b, *e, *lastend;

  *numOfAddr = 0;
  b = e = memNode;
  *totalNode = 0;

  // while(b->leftNBR != NULL) { b = b->leftNBR; }; // traverse to left most
  b = getLeftMost(memNode);
  *baddr = b->addr;
  *firstnode = b;
  getMemNode1stVersion(firstnode);

  *minseq = (*firstnode)->lastUpdateTS;
  *maxseq = (*firstnode)->lastUpdateTS;

  e = *firstnode;
  while(e != NULL) { // traverse to right most
    u32 currVersion = e->version;
    TPMNode2 *rightNBR = NULL;
    do{
      int seqNo = e->lastUpdateTS;
      if(/* seqNo > 0 && */ *minseq > seqNo)
        *minseq = seqNo;

      if(*maxseq < seqNo)
        *maxseq = seqNo;

      if(rightNBR == NULL && e->rightNBR != NULL)
        rightNBR = e->rightNBR;
      *totalNode += 1;
      e = e->nextVersion;
    } while(e->version != currVersion); // go through each version

    lastend = e;
    if(e->rightNBR == NULL && rightNBR != NULL)
      e = rightNBR;
    else
      e = e->rightNBR;
    (*numOfAddr)++;
  }
  *eaddr = lastend->addr + lastend->bytesz;
}

static TPMNode2 *
getLeftMost(TPMNode2 *node)
{
  TPMNode2 *leftMost = node;

  while (true) {
    if (isAllVersionNodeLeftMost(leftMost))
      break;

    if (leftMost->leftNBR != NULL) {
      leftMost = leftMost->leftNBR;
    } else {
      leftMost = leftMost->nextVersion;
    }
  }
  // printMemNodeAllVersion(leftMost);
  return leftMost;
}

static bool
isAllVersionNodeLeftMost(TPMNode2 *node)
{
  u32 ver = node->version;
  do {
    if(node->leftNBR != NULL) {
      return false;
    }
    else {
      node = node->nextVersion;
    }
  } while(ver != node->version);
  return true;
}

static TPMBufHashTable *
initTPMBufHTNode(
    u32 baddr,
    u32 eaddr,
    int minseq,
    int maxseq,
    u32 numOfAddr,
    TPMNode2 *firstnode,
    u32 totalNode)
{
  TPMBufHashTable *node = calloc(1, sizeof(TPMBufHashTable));
  assert(node != NULL);

  node->baddr = baddr;
  node->eaddr = eaddr;
  node->minseq = minseq;
  node->maxseq = maxseq;
  node->numOfAddr = numOfAddr;
  node->headNode= firstnode;
  node->totalNode = totalNode;
  return node;
}

static int 
cmpTPMBufHTNode(TPMBufHashTable *l, TPMBufHashTable *r)
{
  if(l->minseq < r->minseq) { return -1; }
  else if(l->minseq == r->minseq) { return 0; }
  else { return 1; }
}

static void
assignNodeID(TPMNode2 *headNode, u32 bufID)
// for each node (including neighbor) each version, assigns the bufID to it
{
  // assert(headNode->leftNBR == NULL);    // headnode should be first node, version 0
  // assert(headNode->version == 0);

  while(headNode != NULL){
    u32 currVer = headNode->version;

    do {
      headNode->bufid = bufID;
      headNode = headNode->nextVersion;
    } while(headNode->version != currVer);

    headNode = headNode->rightNBR;
  }
}


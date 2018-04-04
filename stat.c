#include "misc.h"
#include "stat.h"
// #include "avalanche.h"
#include "propagate.h"

/* version hash table */
static int
add_ver_ht(struct AddrHT **addrHT, u32 addr);

static struct AddrHT *
find_ver_ht(struct AddrHT **addrHT, u32 addr);

static void
del_ver_ht(struct AddrHT **addrHT);

static void 
count_ver_ht(struct AddrHT **addrHT);

static void 
print_ver_ht(struct AddrHT **addrHT);

/* Continuous Buf hash table */
static struct ContBufHT
{
  u32 baddr;
  u32 eaddr;
  u32 minseq;
  u32 maxseq;
  TPMNode2 *firstNode;
  UT_hash_handle hh_cont;
};

static int
add_buf_ht(struct ContBufHT **contbufHT, u32 baddr, u32 eaddr, u32 minseq, u32 maxseq, TPMNode2 *firstNode);

static struct ContBufHT *
find_buf_ht(struct ContBufHT **contbufHT, u32 baddr);

static void
del_buf_ht(struct ContBufHT **contbufHT);

static void 
count_buf_ht(struct ContBufHT **contbufHT);

static void 
print_buf_ht(struct ContBufHT **contbufHT);

/* stat */
static u32 
get_out_degree(union TPMNode *t);

static union TPMNode *
get_firstnode_in_ht(struct TPMContext *tpm, u32 type);

void 
get_cont_buf(struct TPMNode2 *node, u32 *baddr, u32 *eaddr, int *minseq, int *maxseq, TPMNode2 **firstnode)
// Computes 
//	- baddr
//	- eaddr
//	- minseq
//	- maxseq
//	given a memory node
{
  struct TPMNode2 *b, *e;
  *minseq = node->lastUpdateTS;
  *maxseq = 0;

  b = e = node;

  while(b->leftNBR != NULL) { b = b->leftNBR; }; // traverse to left most
  *baddr = b->addr;
  *firstnode = b;
  getMemNode1stVersion(firstnode);

  e = *firstnode;
  while(e->rightNBR != NULL) { // traverse to right most
    u32 currVersion = e->version;
    do{
      int seqNo = e->lastUpdateTS;
      if(*minseq > seqNo)
        *minseq = seqNo;

      if(*maxseq < seqNo)
        *maxseq = seqNo;

      e = e->nextVersion;
    } while(e->version != currVersion); // go through each version

    e = e->rightNBR;
  }
  *eaddr = e->addr + e->bytesz;

  // print_mem_node(*firstnode);
  // if((*eaddr - *baddr) >= 8)
  // 	printf("begin addr:0x%-8x end addr:0x%-8x minseq:%u maxseq:%u\n", *baddr, *eaddr, *minseq, *maxseq);
}

void 
compute_cont_buf(struct TPMContext *tpm)
{
  struct ContBufHT *bufHT = NULL, *s;
  u32 baddr, eaddr;
  int minseq, maxseq;
  TPMNode2 *firstnode = NULL;

  for(int i = 0; i < seqNo2NodeHashSize; i++) {
    if(tpm->seqNo2NodeHash[i] != NULL) {
      union TPMNode *t = tpm->seqNo2NodeHash[i];
      if(t->tpmnode1.type == TPM_Type_Memory) {
        get_cont_buf(&(t->tpmnode2), &baddr, &eaddr, &minseq, &maxseq, &firstnode);
        if( (eaddr - baddr) >= MIN_BUF_SZ) {
          s = find_buf_ht(&bufHT, baddr);
          if(s == NULL) {
            if(add_buf_ht(&bufHT, baddr, eaddr, minseq, maxseq, firstnode) >= 0) {}
            else { fprintf(stderr, "error: add buf ht\n"); return; }
          }
          else {
            if(s->eaddr < eaddr) {
              s->eaddr = eaddr;
              s->minseq = minseq;
              s->maxseq = maxseq;
            }
          }
        }
      }
    }
  }

  u32 minsz, maxsz = 0, totalsz = 0;
  u32 num = HASH_CNT(hh_cont, bufHT);
  printf("total continuous buffers(>=8):%u\n", num);

  minsz = bufHT->eaddr - bufHT->baddr;
  struct ContBufHT *t;
  for(t = bufHT; t != NULL; t = t->hh_cont.next) {
    u32 sz = t->eaddr - t->baddr;
    if(minsz > sz)
      minsz = sz;

    if(maxsz < sz)
      maxsz = sz;

    totalsz += sz;
  }
  printf("continuous buffers: min sz:%-2u bytes avg sz:%-2u bytes max sz:%-2u bytes\n", minsz, totalsz/num, maxsz);
  // count_buf_ht(&bufHT);
  printf("--------------------\n");


  u32 minstep = 100, maxstep = 0, totalstep = 0;
  s = bufHT;
  for(; s != NULL; s = s->hh_cont.next) {
    u32 step = printMemNodePropagate(tpm, s->firstNode);
    if(minstep > step)
      minstep = step;

    if(maxstep < step)
      maxstep = step;

    totalstep += step;
  }
  printf("traverse numbers (begin node first version): min step:%u avg step:%u max step:%u\n", minstep, totalstep/num, maxstep);

  print_buf_ht(&bufHT);
  del_buf_ht(&bufHT);
}

void compute_version(struct TPMContext *tpm, u32 type)
{
  struct AddrHT *addrHT = NULL;
  struct AddrHT *s;

  u32 min, max = 0, total = 0;
  int i = 0, n = 0;

  for(; i < seqNo2NodeHashSize; i++) {
    if(tpm->seqNo2NodeHash[i] != NULL) {
      union TPMNode *t = tpm->seqNo2NodeHash[i];
      if(t->tpmnode1.type == type) {
        u32 addr = t->tpmnode1.addr;

        s = find_ver_ht(&addrHT, addr);
        if(s == NULL) { // not in hash table
          if(add_ver_ht(&addrHT, addr) >= 0) {}
          else {
            fprintf(stderr, "error: add ver ht\n");
            return;
          }
        }
        else {
          s->ver = s->ver+1;
        }
      }
    }
  }

  min = addrHT->ver;
  for(s = addrHT; s != NULL; s = s->hh_ver.next) {
    // printf("mem: addr:%-8x ver:%u\n", s->addr, s->ver);
    if(min > s->ver)
      min = s->ver;

    if(max < s->ver)
      max = s->ver;

    total += s->ver;
  }
  n = HASH_CNT(hh_ver, addrHT);
  // print_ver_ht(&addrHT);

  switch(type){
    case TPM_Type_Memory:
      printf("mem  version: min:%-8u avg:%-8u max:%-8u\n", min, total/n, max);
      break;
    case TPM_Type_Register:
      printf("reg  version: min:%-8u avg:%-8u max:%-8u\n", min, total/n, max);
      break;
    case TPM_Type_Temprary:
      printf("temp version: min:%-8u avg:%-8u max:%-8u\n", min, total/n, max);
      break;
    default:
      fprintf(stderr, "unkown type\n");
      break;
  }
  del_ver_ht(&addrHT);
}

void compute_version_all(struct TPMContext *tpm)
{
  struct AddrHT *addrHT = NULL;
  struct AddrHT *s;

  u32 min, max = 0, total = 0;
  int i = 0, n = 0;

  // search all nodes and get versions
  for(; i < seqNo2NodeHashSize; i++) {
    if(tpm->seqNo2NodeHash[i] != NULL) {
      union TPMNode *t = tpm->seqNo2NodeHash[i];
      u32 addr = t->tpmnode1.addr;

      s = find_ver_ht(&addrHT, addr);
      if(s == NULL) { // not in hash table
        if(add_ver_ht(&addrHT, addr) >= 0) {}
        else {
          fprintf(stderr, "error: add ver ht\n");
          return;
        }
      }
      else {
        s->ver = s->ver+1;
      }
    }
  }

  min = addrHT->ver;
  for(s = addrHT; s != NULL; s = s->hh_ver.next) {
    // printf("mem: addr:%-8x ver:%u\n", s->addr, s->ver);
    if(min > s->ver)
      min = s->ver;

    if(max < s->ver)
      max = s->ver;

    total += s->ver;
  }
  n = HASH_CNT(hh_ver, addrHT);
  // print_ver_ht(&addrHT);
  printf("all  version: min:%-8u avg:%-8u max:%-8u\n", min, total/n, max);
  del_ver_ht(&addrHT);
}

void 
compute_outd(struct TPMContext *tpm, u32 type)
{
  u32 num = 0, min, max = 0, total = 0;
  int i = 0;

  union TPMNode *n = (union TPMNode*)get_firstnode_in_ht(tpm, type);
  min = get_out_degree(n);

  for(; i < seqNo2NodeHashSize; i++) {
    if(tpm->seqNo2NodeHash[i] != NULL) {
      union TPMNode *n = tpm->seqNo2NodeHash[i];
      if(n->tpmnode1.type == type) {
        int outd = get_out_degree(tpm->seqNo2NodeHash[i]);

        if(min > outd)
          min = outd;

        if(max < outd)
          max = outd;

        total += outd;
        num++;
      }
    }
  }

  switch(type){
    case TPM_Type_Memory:
      printf("mem  outdegree: min:%-4u avg:%-4u max:%-4u\n", min, total/num, max);
      break;
    case TPM_Type_Register:
      printf("reg  outdegree: min:%-4u avg:%-4u max:%-4u\n", min, total/num, max);
      break;
    case TPM_Type_Temprary:
      printf("temp outdegree: min:%-4u avg:%-4u max:%-4u\n", min, total/num, max);
      break;
    default:
      fprintf(stderr, "unkown type\n");
      break;
  }
}

void 
compute_outd_all(struct TPMContext *tpm)
{
  u32 num = 0, min, max = 0, total = 0;
  int i = 0;

  union TPMNode *n = (union TPMNode*)get_firstnode_in_ht(tpm, 0);
  min = get_out_degree(n);

  for(; i < seqNo2NodeHashSize; i++) {
    if(tpm->seqNo2NodeHash[i] != NULL) {
      int outd = get_out_degree(tpm->seqNo2NodeHash[i]);

      if(min > outd)
        min = outd;

      if(max < outd)
        max = outd;

      total += outd;
      num++;
    }
  }
  printf("all  outdegree: min:%-4u avg:%-4u max:%-4u\n", min, total/num, max);
}

void 
compute_total_node(struct TPMContext *tpm)
{
  int i = 0, n = 0;
  for(; i < seqNo2NodeHashSize; i++) {
    if(tpm->seqNo2NodeHash[i] != NULL)
      n++;
  }
  printf("total nodes:%d\n", n);
}

void 
stat(struct TPMContext *tpm)
{
  compute_outd_all(tpm);
  compute_outd(tpm, TPM_Type_Memory);
  compute_outd(tpm, TPM_Type_Register);
  compute_outd(tpm, TPM_Type_Temprary);
  printf("--------------------\n");
  compute_version_all(tpm);
  compute_version(tpm, TPM_Type_Memory);
  compute_version(tpm, TPM_Type_Register);
  compute_version(tpm, TPM_Type_Temprary);
  printf("--------------------\n");
  compute_cont_buf(tpm);
}

void
benchTPMDFS(TPMContext *tpm)
{
  TPMBufHashTable *tpmBuf, *buf;
  int numOfBuf, i;
  TPMNode2 *headNode;

  tpmBuf = analyzeTPMBuf(tpm);
  assignTPMBufID(tpmBuf);
  // numOfBuf= HASH_CNT(hh_tpmBufHT, tpmBuf);
  // printTPMBufHashTable(tpmBuf);
  printTime("Finish analyzing buffers");

  i = 0;
  for(buf = tpmBuf; buf != NULL; buf = buf->hh_tpmBufHT.next) {
    if(i >= 10)
      break;

    printf("----------\nbegin addr:0x%-8x end addr:0x%-8x sz:%-3u numofaddr:%-3u minseq:%-6d maxseq:%-6d diffseq:%-6d bufID:%u\n",
        buf->baddr, buf->eaddr, buf->eaddr - buf->baddr,
        buf->numOfAddr, buf->minseq, buf->maxseq, (buf->maxseq - buf->minseq), buf->headNode->bufid);

    headNode = buf->headNode;

    while(headNode != NULL) {
      u32 version = headNode->version;
      // printMemNodeLit(headNode);
      do {
        if(headNode->lastUpdateTS < 0) {
          // printMemNodeLit(headNode);
          printMemNodePropagate(tpm, headNode);
        }
        headNode = headNode->nextVersion;
      } while (version != headNode->version);
      headNode = headNode->rightNBR;
    }
    i++;
  }
  printTime("Finish dfs of source buffer");
}


static u32  
get_out_degree(union TPMNode *t)
{
  u32 n = 0;
  struct Transition *tran = t->tpmnode1.firstChild;
  while (tran != 0) {
    n++;
    tran = tran->next;
  }
  // printf("outdegree:%-2u\n", n);
  return n;
}

static union TPMNode *
get_firstnode_in_ht(struct TPMContext *tpm, u32 type)
// Returns:
//	first node in hashtalbe based on type, if type is 0, then all types
{
  union TPMNode *n = NULL;

  if(type != 0) {
    for(int i = 0; i < seqNo2NodeHashSize; i++) {
      if(tpm->seqNo2NodeHash[i] != NULL) {
        n = tpm->seqNo2NodeHash[i];
        if(n->tpmnode1.type == type) {
          return n;
        }
      }
    }
  }
  else {
    for(int i = 0; i < seqNo2NodeHashSize; i++) {
      if(tpm->seqNo2NodeHash[i] != NULL) {
        return tpm->seqNo2NodeHash[i];
      }
    }
  }

  return n;
}

int
add_ver_ht(struct AddrHT **addrHT, u32 addr)
{
  struct AddrHT *s;

  if(addrHT == NULL)
    return -1;

  s = find_ver_ht(addrHT, addr);
  if(s == NULL) {	// if not found, creates new
    s = (struct AddrHT*)malloc(sizeof(struct AddrHT) );
    s->addr = addr;
    HASH_ADD(hh_ver, *addrHT, addr, 4, s);
    s->ver = 1;
  } else {	// if found, updates
    s->ver = s->ver+1;
  }

  return 0;
}

/* version hash table */
static struct AddrHT *
find_ver_ht(struct AddrHT **addrHT, u32 addr)
{
  struct AddrHT *s;
  HASH_FIND(hh_ver, *addrHT, &addr, 4, s);
  return s;
}

static void
del_ver_ht(struct AddrHT **addrHT)
{
  struct AddrHT *curr, *tmp;
  HASH_ITER(hh_ver, *addrHT, curr, tmp) {
    HASH_DELETE(hh_ver, *addrHT, curr);
    free(curr);
  }
}

static void 
count_ver_ht(struct AddrHT **addrHT)
{
  u32 num;
  num = HASH_CNT(hh_ver, *addrHT);
  printf("total: %u mem addr in hash table\n", num);
}

static void 
print_ver_ht(struct AddrHT **addrHT)
{
  struct AddrHT *s;
  for(s = *addrHT; s != NULL; s = s->hh_ver.next) {
    printf("addr:%-8x ver:%u\n", s->addr, s->ver);
  }
}

/* Continuous Buf hash table */
static int
add_buf_ht(struct ContBufHT **contbufHT, u32 baddr, u32 eaddr, u32 minseq, u32 maxseq, TPMNode2 *firstNode)
{
  struct ContBufHT *s;

  if(contbufHT == NULL)
    return -1;

  s = find_buf_ht(contbufHT, baddr);
  if(s == NULL) {	// if not found, creates new
    s = (struct ContBufHT*)malloc(sizeof(struct ContBufHT) );
    s->baddr = baddr;
    HASH_ADD(hh_cont, *contbufHT, baddr, 4, s);
    s->eaddr = eaddr;
    s->minseq = minseq;
    s->maxseq = maxseq;
    s->firstNode = firstNode;
  } else {	// if found, updates
    if(s->eaddr < eaddr) {
      s->eaddr = eaddr;
      s->minseq = minseq;
      s->maxseq = maxseq;
      s->firstNode = firstNode;
    }
  }
  return 0;
}

static struct ContBufHT *
find_buf_ht(struct ContBufHT **contbufHT, u32 baddr)
{
  struct ContBufHT *s;
  HASH_FIND(hh_cont, *contbufHT, &baddr, 4, s);
  return s;
}

static void
del_buf_ht(struct ContBufHT **contbufHT)
{
  struct ContBufHT *curr, *tmp;
  HASH_ITER(hh_cont, *contbufHT, curr, tmp) {
    HASH_DELETE(hh_cont, *contbufHT, curr);
    free(curr);
  }
}

static void 
count_buf_ht(struct ContBufHT **contbufHT)
{
  u32 num;
  num = HASH_CNT(hh_cont, *contbufHT);
  printf("total continuous buffers(>=8):%u\n", num);
}

static void 
print_buf_ht(struct ContBufHT **contbufHT)
{
  struct ContBufHT *s;
  for(s = *contbufHT; s != NULL; s = s->hh_cont.next) {
    // printf("--------------------\n");
    printf("begin:0x%-8x end:0x%-8x sz:%-4u minseq:%-6d maxseq:%-6d diffseq:%d\n",
        s->baddr, s->eaddr, s->eaddr-s->baddr, s->minseq, s->maxseq, s->maxseq-s->minseq);
    // printf("firt node first version:\n");
    // print_mem_node(s->firstNode);
  }
}

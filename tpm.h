/*
 * tpm.h
 * 
 * header file of Taint Propagation Map
 * 
 * created on 12/8/2017
 */

#include <stdio.h>

#ifndef TPM_H
#define TPM_H

#include "uthash.h"
#include "flag.h"   // XTaint record flag
#include "record.h"
#include "tpmnode.h"
#include "type.h"

/* need to add all the XTaint record flag definition here */

/* TPM related constants */
#define MIN_BUF_SZ          8   // minimum buffer size
#define INIT_SEQNO          -1  // seqNo initialize to -1

#define MAX_REC_SZ          128 // assume max record size to 128 chars
#define REC_FLAG_SZ         3   // flag size of each record

#define NUM_REG             14  // num of register (global temps)  
#define REG_IDX_MASK        0xf
#define MAX_TEMPIDX         128 // the max temp index that Qemu uses
// need to be adjuested based on XTaint log:

#define BYTE                1
#define WORD                2
#define DWORD               4

/* the following 2 constants need to be adjuested based on statistics of the XTaint log */
#define mem2NodeHashSize	90000
#define seqNo2NodeHashSize	120000000

struct Mem2NodeHT;

struct Transition
{
  u32 seqNo;		// sequence number of corresponding XTaint record
  union TPMNode *child;
  struct Transition *next;
  char hasVisit;  // if the transition (edge) had been visited already in building HitMap
  // 0: unvisit 1: visit
};
typedef struct Transition Transition;

struct TPMContext
{
  u32 nodeNum;	// total number of TPM node
  u32 memAddrNum;	// number of different memory addresses encountered
  u32 tempVarNum;	// number of different temporary variables encounted

  // struct TPMNode2 *mem2NodeHash[mem2NodeHashSize];	// maps mem addr to TPMNode2 of the latest version of a mem addr
  struct Mem2NodeHT *mem2NodeHT;          // uses uthash, maps mem addr to TPMNode2 of the latest version of a mem addr
  union TPMNode *seqNo2NodeHash[seqNo2NodeHashSize];	// maps seq no. to TPMNode of the source of the transision

  u32 minBufferSz;	// minimum buffer size (such as 8) considered for avalanche effect search
  u32 taintedBufNum;	// number of tainted buffers in the TPM.
  struct taintedBuf *taintedbuf;	// point to the tainted buffers in TPM
};
typedef struct TPMContext TPMContext;

/* mem to node hash tables, according to uthash */
struct Mem2NodeHT
{
  u32 addr;               // key
  struct TPMNode2 *toMem; // val, latest version node of the addr
  UT_hash_handle hh_mem;  // hash table head, required by uthash
};
typedef struct Mem2NodeHT Mem2NodeHT;

struct TPMBufHashTable
{
  u32 baddr;      // start addr: uses as key in hash
  u32 eaddr;      // end addr
  int minseq;     // minimum seqNo
  int maxseq;     // maximum seqNo
  u32 numOfAddr;  // num of diff addr in the buf
  u32 totalNode;  // num of total nodes in buffer
  TPMNode2 *headNode;
  UT_hash_handle hh_tpmBufHT;
};
typedef struct TPMBufHashTable TPMBufHashTable;
// Stores all different bufs in a tpm in hash table

typedef struct TPMBufContext
{
  struct TPMBufHashTable *tpmBufHash;
  u32 numOfBuf;
} TPMBufContext;

/* TPM function prototypes */
int
buildTPM(FILE *taintfp, struct TPMContext *tpm);

struct TPMNode2 *
mem2NodeSearch(struct TPMContext *tpm, u32 memaddr);

union TPMNode *
seqNo2NodeSearch(struct TPMContext *tpm, u32 seqNo);

void
delTPM(struct TPMContext *tpm);

/* Transition operation */
TPMNode *
getTransitionDst(Transition *transition);

u32
getTransitionChildrenNum(Transition *firstChild);

/* TPM buffers */

TPMBufContext *
initTPMBufContext(TPMContext *tpm);

void
delTPMBufContext(TPMBufContext *tpmBufCtxt);

/* Computes all the bufs in tpm. */
TPMBufHashTable *
analyzeTPMBuf(TPMContext *tpm);

void 
assignTPMBufID(TPMBufHashTable *tpmBuf);
// assignes id to each buffer, starts with 1

TPMBufHashTable *
getTPMBuf(TPMBufHashTable *bufHead, u32 bufIdx);

int
getTPMBufTotal(TPMBufHashTable *tpmBuf);

u32
getTPMBufNodeTotal(TPMBufHashTable *tpmBuf);

u32
getTPMBufMaxSeqN(TPMBufHashTable *tpmBuf);

int
getTPMBufAddrIdx(
    u32 bufID,
    u32 addr,
    TPMBufHashTable *tpmBuf);

void
delAllTPMBuf(TPMBufHashTable *tpmBuf);

/* print function */
void 
printTrans1stChild(union TPMNode *head);

void 
print1Trans(Transition *transition);

void
printTransAllChildren(Transition *transition);

void 
print1TPMBufHashTable(char *s, TPMBufHashTable *tpmBufHT);

void
printTPMBufHashTable(TPMBufHashTable *tpmBufHT);

void
print_tpm_source(TPMContext *tpm);
#endif

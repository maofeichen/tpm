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

// #include "avalanche.h"
#include "flag.h"   // XTaint record flag
#include "record.h"
#include "tpmnode.h"

#define u32	unsigned int

/* need to add all the XTaint record flag definition here */

/* TPM related constants */
#define MIN_BUF_SZ          8

#define NUM_REG             14  // num of register (global temps)  
#define REG_IDX_MASK        0xf
#define MAX_TEMPIDX         128 // the max temp index that Qemu uses
                                // need to be adjuested based on XTaint log: 


#define BYTE                1
#define WORD                2
#define DWORD               4

/* the following 2 constants need to be adjuested based on statistics of the XTaint log */
#define mem2NodeHashSize	90000
#define seqNo2NodeHashSize	50000000

struct MemHT;

struct Transition
{
    u32 seqNo;		// sequence number of corresponding XTaint record
    union TPMNode *child;
    struct Transition *next;
};
typedef struct Transition Transition;

struct TPMContext
{
    u32 nodeNum;	// total number of TPM node
    u32 memAddrNum;	// number of different memory addresses encountered
    u32 tempVarNum;	// number of different temporary variables encounted

    // struct TPMNode2 *mem2NodeHash[mem2NodeHashSize];	// maps mem addr to TPMNode2 of the latest version of a mem addr
    struct MemHT *mem2NodeHT;          // uses uthash, maps mem addr to TPMNode2 of the latest version of a mem addr
    union TPMNode *seqNo2NodeHash[seqNo2NodeHashSize];	// maps seq no. to TPMNode of the source of the transision

    u32 minBufferSz;	// minimum buffer size (such as 8) considered for avalanche effect search
    u32 taintedBufNum;	// number of tainted buffers in the TPM.
    struct taintedBuf *taintedbuf;	// point to the tainted buffers in TPM
};
typedef struct TPMContext TPMContext;

/* mem hash tables, according to uthash */
struct MemHT
{
    u32 addr;               // key
    struct TPMNode2 *toMem; // val, latest version node of the addr
    UT_hash_handle hh_mem;  // hash table head, required by uthash
};
typedef struct MemHT MemHT;

struct TPMBufHashTable
{
    u32 baddr;
    u32 eaddr;
    u32 minseq;
    u32 maxseq;
    TPMNode2 *headNode;
    UT_hash_handle hh_tpmBufHT;   
};
typedef struct TPMBufHashTable TPMBufHashTable; // stores all different bufs in a tpm in hash table

/* TPM function prototypes */
int 
isPropagationOverwriting(u32 flag, Record *rec);

// u32 
// processOneXTaintRecord(struct TPMContext *tpm, u32 seqNo, u32 size, u32 srcflg, u32 srcaddr, u32 dstflag, u32 dstaddr);
int 
processOneXTaintRecord(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], struct TPMNode1 *tempCntxt[]);

int
buildTPM(FILE *taintfp, struct TPMContext *tpm);

struct TPMNode2 *
mem2NodeSearch(struct TPMContext *tpm, u32 memaddr);

union TPMNode *
seqNo2NodeSearch(struct TPMContext *tpm, u32 seqNo);

TPMBufHashTable *
getAllTPMBuf(TPMContext *tpm);

void 
delTPM(struct TPMContext *tpm);

/* Transition operation */
TPMNode *
getTransitionDst(Transition *transition);

u32
getTransitionChildrenNum(Transition *firstChild);

/* print function */
void 
printTrans1stChild(union TPMNode *head);

void 
printTransAllChildren(Transition *transition);

void 
printTPMBufHT(TPMBufHashTable *tpmBufHT);
#endif

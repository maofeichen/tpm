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

#include "avalanche.h"
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

// struct taintedBuf
// {
//     struct TPMNode2 *bufstart;	// point to the TMPNode2 of the start addr of some tainted buffer in TPM;
//     struct taintedBuf *next;	// point to the taintedBuf structure of the next tainted buffer; null if no more
// };

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

/* mem hash tables, according to uthash */
struct MemHT
{
    u32 addr;               // key
    struct TPMNode2 *toMem; // val, latest version node of the addr
    UT_hash_handle hh_mem;  // hash table head, required by uthash
};

// typedef struct TPMNode1 TPMNode1;
// typedef struct TPMNode2 TPMNode2;
// typedef union TPMNode TPMNode;
typedef struct Transition Transition;
typedef struct TPMContext TPMContext;
typedef struct MemHT MemHT;

/* TPM function prototypes */

int 
isPropagationOverwriting(u32 flag, Record *rec);

// union TPMNode*
// createTPMNode(u32 type, u32 addr, u32 val, u32 TS);

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

void 
delTPM(struct TPMContext *tpm);

void 
searchAvalanche(TPMContext *tpm);

/* misc operation */
int 
get_earliest_version(struct TPMNode2 **earliest);

/* print function */
void 
print_tpmnode(TPMNode *tpmnode);

void 
print_mem_node(struct TPMNode2 *n);

void 
print_version(struct TPMNode2 *head);

void 
print_transition(union TPMNode *head);

void 
print_single_transition(Transition *transition);
#endif
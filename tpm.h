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

#include "flag.h"   // XTaint record flag
#include "tpmht.h"  // hash tables

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

#define TPM_Type_Register	0x00000001
#define TPM_Type_Temprary	0x00000002
#define TPM_Type_Memory		0x00000004

struct Transition;

struct TPMNode1		// for temp, register addresses
{
    u32	type;		// indicating the type of the node
    u32	addr;		// mem addr, id of temp or register
    u32 val;        
    u32	lastUpdateTS;	// the TS (seq#) of last update of the node
    struct Transition *firstChild;  // points to structure that points to the first child
};

struct TPMNode2		// for memory address
{
    u32	type;		// indicating the type of the node
    u32	addr;		// mem addr, id of temp or register
    u32 val;
    u32	lastUpdateTS;	// the TS (seq#) of last update of the node
    struct Transition *firstChild;  // points to structure that points to the first child
/* the following fields are only for TPMNode for memory */
    struct TPMNode2 *leftNBR;	// point to node of adjacent, smaller memory address 
    struct TPMNode2 *rightNBR;	// point to node of adjacent, bigger memory address 
    struct TPMNode2 *nextVersion;// point to node of the same addr buf of different version or age. Forms circular link
    u32 version;	// the version of current node, monotonically increasing from 0.
    u32	hitcnt;		/* as source, the number of TMPNode2 in destination buffer this node propagates to; or
			   as detination, the number of TMPNode2 in source buffer that propagates to this node	*/
};

union TPMNode
{
    struct TPMNode1 tpmnode1;
    struct TPMNode2 tpmnode2;
};

struct Transition
{
    u32 seqNo;		// sequence number of corresponding XTaint record
    union TPMNode *child;
    struct Transition *next;
};

struct taintedBuf
{
    struct TPMNode2 *bufstart;	// point to the TMPNode2 of the start addr of some tainted buffer in TPM;
    struct taintedBuf *next;	// point to the taintedBuf structure of the next tainted buffer; null if no more
};

struct TPMContext
{
    u32 nodeNum;	// total number of TPM node
    u32 memAddrNum;	// number of different memory addresses encountered
    u32 tempVarNum;	// number of different temporary variables encounted

    // struct TPMNode2 *mem2NodeHash[mem2NodeHashSize];	// maps mem addr to TPMNode2 of the latest version of a mem addr
    union TPMNode *seqNo2NodeHash[seqNo2NodeHashSize];	// maps seq no. to TPMNode of the source of the transision

    struct MemHT *mem2NodeHT;          // uses uthash, maps mem addr to TPMNode2 of the latest version of a mem addr
    // struct SeqNoHT *seqNo2NodeHT;   // uses uthash, maps seq no. to TPMNode of the source of the transision

    u32 minBufferSz;	// minimum buffer size (such as 8) considered for avalanche effect search
    u32 taintedBufNum;	// number of tainted buffers in the TPM.
    struct taintedBuf *taintedbuf;	// point to the tainted buffers in TPM
};

/* single record */
struct Record
{
    u32 flag;   // src and dst flags are same
    u32 s_addr;
    u32 s_val;
    u32 d_addr;
    u32 d_val;
    u32 bytesz;
    u32 ts;     // time stamp (seqNo)
    u32 s_ts;   // src time stamp
    u32 d_ts;   // dst time stamp
    u32 is_load;
    u32 is_loadptr;
    u32 is_store;
    u32 is_storeptr;
};

typedef struct TPMNode1 TPMNode1;
typedef struct TPMNode2 TPMNode2;
typedef union TPMNode TPMNode;
typedef struct Transition Transition;
typedef struct TPMContext TPMContext;
typedef struct Record Record;
/* TPM function prototypes */

int 
isPropagationOverwriting(u32 flag);

union TPMNode*
createTPMNode(u32 type, u32 addr, u32 val, u32 TS);

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

/* print function */
void 
print_mem_node(struct TPMNode2 *n);

#endif
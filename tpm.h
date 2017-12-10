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

#define u32	unsigned int

/* need to add all the XTaint record flag definition here */


/* TPM related constants */

/* the following 2 constants need to be adjuested based on statistics of the XTaint log */
#define mem2NodeHashSize	90000
#define seqNo2NodeHashSize	20000000

#define TPM_Type_Register	0x00000001
#define TPM_Type_Temprary	0x00000002
#define TPM_Type_Memory		0x00000004

struct Transition;

struct TPMNode1		// for temp, register addresses
{
    u32	type;		// indicating the type of the node
    u32	addr;		// mem addr, id of temp or register
    u32	lastUpdateTS;	// the TS (seq#) of last update of the node
    struct Transition *firstChild;  // points to structure that points to the first child
};

struct TPMNode2		// for memory address
{
    u32	type;		// indicating the type of the node
    u32	addr;		// mem addr, id of temp or register
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
    struct TPMNode2 *mem2NodeHash[mem2NodeHashSize];	// maps mem addr to TPMNode2 of the latest version of a mem addr
    union TMPNode *seqNo2NodeHash[seqNo2NodeHashSize];	// maps seq no. to TPMNode of the source of the transision
    u32 minBufferSz;	// minimum buffer size (such as 8) considered for avalanche effect search
    u32 taintedBufNum;	// number of tainted buffers in the TPM.
    struct taintedBuf *taintedbuf;	// point to the tainted buffers in TPM
};

/* TPM function prototypes */

u32 
isPropagationOverwriting(u32 flag);

union TPMNode *
createTPMNode(u32 type, u32 addr, u32 TS);

u32 
processOneXTaintRecord(struct TPMContext *tpm, u32 seqNo, u32 size, u32 srcflg, u32 srcaddr, u32 dstflag, u32 dstaddr);

u32 
buildTPM(FILE *taintfp, struct TPMContext *tpm);

struct TPMNode2 *
mem2NodeSearch(struct TPMContext *tpm, u32 memaddr);

union TPMNode *
seqNo2NodeSearch(struct TPMContext *tpm, u32 seqNo);






#endif
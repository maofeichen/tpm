#ifndef TPMNODE_H
#define TPMNODE_H 

#include "type.h"
#include <stdbool.h>

#define TPM_Type_Register	0x00000001
#define TPM_Type_Temprary	0x00000002
#define TPM_Type_Memory		0x00000004

struct Transition;

struct TPMNode1		// for temp, register addresses
{
    u32	type;		  // indicating the type of the node
    u32	addr;		  // mem addr, id of temp or register
    u32 val;        
    u32	lastUpdateTS;	// the TS (seq#) of last update of the node
    struct Transition *firstChild;  // points to structure that points to the first child
};
typedef struct TPMNode1 TPMNode1;

struct TPMNode2		// for memory address
{
    u32	type;		  // indicating the type of the node
    u32	addr;		  // mem addr, id of temp or register
    u32 val;
    u32	lastUpdateTS;	// the TS (seq#) of last update of the node
    struct Transition *firstChild;  // points to structure that points to the first child
    /* the following fields are only for TPMNode for memory */
    struct TPMNode2 *leftNBR;	    // point to node of adjacent, smaller memory address
    struct TPMNode2 *rightNBR;	  // point to node of adjacent, bigger memory address
    struct TPMNode2 *nextVersion; // point to node of the same addr buf of different version or age. Forms circular link
    u32 version;	// the version of current node, monotonically increasing from 0.
    u32	hitcnt;		/* as source, the number of TMPNode2 in destination buffer this node propagates to; or
			   as detination, the number of TMPNode2 in source buffer that propagates to this node	*/
};
typedef struct TPMNode2 TPMNode2;

union TPMNode
{
    struct TPMNode1 tpmnode1;
    struct TPMNode2 tpmnode2;
};
typedef union TPMNode TPMNode;

struct taintedBuf
{
    struct TPMNode2 *bufstart;	// point to the TMPNode2 of the start addr of some tainted buffer in TPM;
    struct taintedBuf *next;	  // point to the taintedBuf structure of the next tainted buffer; null if no more
};
typedef struct taintedBuf TaintedBuf;

union TPMNode*
createTPMNode(u32 type, u32 addr, u32 val, u32 TS);

union TPMNode *
create1stVersionMemNode(u32 addr, u32 val, u32 ts);

/* mem node version */
bool 
addNextVerMemNode(struct TPMNode2 *front, struct TPMNode2 *next);

int 
setMemNodeVersion(union TPMNode *tpmnode, u32 ver);

u32 
getMemNodeVersion(struct TPMNode2 *node);

int 
getMemNode1stVersion(struct TPMNode2 **earliest);

int 
getNodeType(u32 flag);

/* TaintedBuf */
TaintedBuf *createTaintedBuf(TPMNode2 *bufstart);

/* print function */
void 
printNode(TPMNode *tpmnode);

void 
printMemNode(struct TPMNode2 *n);

void 
printNonmemNode(struct TPMNode1 *n);

void 
printMemNodeAllVersion(struct TPMNode2 *head);

#endif

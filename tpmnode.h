#ifndef TPMNODE_H
#define TPMNODE_H 

#include "env.h"
#include "type.h"
#include "uthash.h"
#include <stdbool.h>

#define TPM_Type_Register	0x00000001
#define TPM_Type_Temprary	0x00000002
#define TPM_Type_Memory		0x00000004

struct Transition;
struct HitcntHashTable;

struct TPMNode1		  // for temp, register addresses
{
  u32	type;		  // indicating the type of the node
  u32	addr;		  // mem addr, id of temp or register
  u32   val;
  int   lastUpdateTS; // the TS (seq#) of last update of the node
  struct Transition *firstChild;    // points to structure that points to the first child
#if TPM_RE_TRANSITON
  struct Transition *first_farther; // points to its first father
#endif
  char hasVisit;  // determines if the node had been visited during building HitMap, not used any more
  u32 visitNodeIdx; // During build hitMap, given a source node, assigns the
  // source node ptr, to mark it had been visited during the traversing. To replace
  // hash table, which has a bug during large xtaint log test.
};
typedef struct TPMNode1 TPMNode1;

struct TPMNode2		  // for memory address
{
  u32	type;		  // indicating the type of the node
  u32	addr;		  // mem addr, id of temp or register
  u32   val;
  int lastUpdateTS;	  // the TS (seq#) of last update of the node
  struct Transition *firstChild;    // points to structure that points to the first child
#if TPM_RE_TRANSITON
  struct Transition *first_farther; // points to its first father
#endif
  char hasVisit;  // determines if the node had been visited during building HitMap, not used any more
  u32 visitNodeIdx;  // Same as TPMNode1
  /* the following fields are only for TPMNode for memory */
  u32 bytesz;                   // byte sz
  struct TPMNode2 *leftNBR;	    // point to node of adjacent, smaller memory address
  struct TPMNode2 *rightNBR;	// point to node of adjacent, bigger memory address
  struct TPMNode2 *nextVersion; // point to node of the same addr buf of different version or age. Forms circular link
  struct TPMNode2 *siblingNBR;  // points to possible multiple nodes that all left neighbor
  // of a same right node. Siblings forms a singly linked list
  u32 version;	// the version of current node, monotonically increasing from 0.
  u32	hitcnt;	/* as source, the number of TMPNode2 in destination buffer this node propagates to; or
			   as detination, the number of TMPNode2 in source buffer that propagates to this node	*/
  u32 bufid;    // bufid the node belongs to, init to 0 (belongs to no buf), will be assigned after tpm is build
  struct HitcntHashTable *hitcntHT; // Not use right now
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
  struct TPMNode2 *bufstart;  // point to the TMPNode2 of the start addr of some tainted buffer in TPM;
  struct taintedBuf *next;	  // point to the taintedBuf structure of the next tainted buffer; null if no more
};
typedef struct taintedBuf TaintedBuf;

typedef struct HitcntHashTable
{
  u32 bufId;  // when the node is src, it indictates which buffer it can propagate to have the hitcnt;
  // when it is as destination, it indicates which src buffer
  u32 hitcnt; /* as source, the number of TMPNode2 in destination buffer this node propagates to; or
			   as detination, the number of TMPNode2 in source buffer that propagates to this node	*/
  UT_hash_handle hh_hitcnt;
} HitcntHashTable;


/* Generic node prototype */
union TPMNode*
createTPMNode(u32 type, u32 addr, u32 val, int TS, u32 bytesz);

int
getNodeType(u32 flag);

void 
setLastUpdateTS(TPMNode *tpmnode, int lastUpdateTS);

/* Mem node operation*/
union TPMNode *
create1stVersionMemNode(u32 addr, u32 val, int ts, u32 bytesz);

bool 
addNextVerMemNode(struct TPMNode2 *front, struct TPMNode2 *next);

int 
setMemNodeVersion(union TPMNode *tpmnode, u32 ver);

u32 
getMemNodeVersion(struct TPMNode2 *node);

int 
getMemNode1stVersion(struct TPMNode2 **earliest);

/* Tainted buffer operation */
TaintedBuf *
createTaintedBuf(TPMNode2 *bufstart);

/* print function */
void 
printNode(TPMNode *tpmnode);

void 
printMemNode(struct TPMNode2 *n);

void 
printMemNodeLit(TPMNode2 *node);

void
printNonmemNode(struct TPMNode1 *n);

void 
printMemNodeAllVersion(struct TPMNode2 *head);

void 
printBufNode(TPMNode2 *head);

void 
printTaintedBuf(TaintedBuf *head);

#endif

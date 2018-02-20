#ifndef HITMAPNODE_H
#define HITMAPNODE_H

// #include "tpmnode.h" // included in tpm.h
#include "tpm.h"
#include "type.h"
#include "uthash.h"

struct HitTransition;

struct HitMapNode {
    u32 bufId;   // ID of the buffer this node belongs to
    u32 addr;    // mem addr
    u32 version; // the version of current node, monotonically increasing from 0. Copy from TPMNode2
    u32 val;
    u32 bytesz;
    int lastUpdateTS; // the TS (seq#) of last update of the node. Copy from TPMNode2
    struct HitTransition *firstChild; // points to structure that points to the first child
    struct HitMapNode *leftNBR;       // point to node of adjacent, smaller memory address
    struct HitMapNode *rightNBR;      // point to node of adjacent, bigger memory address
    struct HitMapNode *nextVersion;   // point to node of the same addr buf of different version or age. Forms circular link
    u32 hitcnt; /* only used when checking avalanche effect between given source buffer & destination buffer.
     need to be initialized to be 0 for each pair of source & destination buffers checking.
     as source, the number of HitMapNode in the destination buffer this node hits; or
     as destination, the number of HitMapNode in the source buffer that hits this node    */
    u32 type;   // used to distinguish buffer node or non-buffer node (reg/temp)
};
typedef struct HitMapNode HitMapNode;

struct HitTransition // aggregate (potentially) multiple taint propagation steps from given source buf to destination buf
{
    u32 minSeqNo; // the minimum sequence number of all the propagation steps this hit transition aggregates
    u32 maxSeqNo; // the maximum sequence number of all the propagation steps this hit transition aggregates
    /* when search along the hit transisions, the next hit transition's minSeqNo must > the current
     * hit transition's maxSeqNo. Otherwise, we stop.
     * If current hit transition's maxSeqNo > destination buffer's maxSeqNo, we stop going any further
     * and try another branch of hit transition.
     */
    struct HitMapNode *child;    // the HitMapNode current node hits
    struct HitTransition *next;
};
typedef struct HitTransition HitTransition;

typedef struct HitMapBufNodePtr2NodeHashTable
{
    // u32 addr;                // key: addr of in each node in hitmap
    TPMNode2 *srcnode;          // key: pointers of TPMNode2
    HitMapNode *toHitMapNode;   // val: pointes to first version of node in HitMap
    UT_hash_handle hh_hitMapBufNode2NodeHT;
} HitMapBufNodePtr2NodeHashTable;  // stores nodes that has correspond hitmap node in the hitmap

typedef struct IntrtmdtNode2HitMapNodeHashTalbe
{
    TPMNode1 *srcnode;          // key: pointer of TPMNode2
    HitMapNode *toHitMapNode;    // val: pointer to the particular HitMap Node
    UT_hash_handle hh_intrtmdtNode2HitMapNodeHT;
} IntrtmdtNode2HitMapNodeHashTalbe;

typedef struct BufContext
{
    u32 numOfAddr;          // num of addr of the buffer
    HitMapNode **addrArray; // addr array of the buffer,
                            // each points to the earliest version node in the hitmap
} BufContext;

typedef struct HitMapContext
{
    TPMBufHashTable *tpmBuf;// points to TPMBuf
    HitMapBufNodePtr2NodeHashTable *hitMapNodeHT; // hash table head
    IntrtmdtNode2HitMapNodeHashTalbe *intrtmdt2HitMapNodeHT;
    u32 maxBufSeqN;         // max seqN of all buffers in TPM
    u32 numOfBuf;           // num of buffers in TPM
    BufContext **bufArray;  // buf array, each points to a buffer context
} HitMapContext;

HitMapNode *
createHitMapNode(
        u32 bufId,
        u32 addr,
        u32 version,
        u32 val,
        u32 bytesz,
        int lastUpdateTS,
        u32 type);

int
compareHitMapHTItem(HitMapBufNodePtr2NodeHashTable *l, HitMapBufNodePtr2NodeHashTable *r);

// TODO: delHitMapNode

bool
isHitMapNodeExist(TPMNode2 *node, HitMapContext *hitMap);

bool
isIntermediateNodeExist(TPMNode1 *node, HitMapContext *hitMap);

void
sortHitMapHashTable(HitMapBufNodePtr2NodeHashTable **hitMapHT);

void
createHitMapRecord(
        TPMNode2 *src,
        u32 srcLvl,
        TPMNode2 *dst,
        u32 dstLvl,
        HitMapContext *hitMapCtxt);

void
createHitMapRecord_IntrmdtNode(
        TPMNode *src,
        TPMNode *dst,
        HitMapContext *hitMapCtxt);

HitTransition *
createHitTransition(
        u32 minSeqN,
        u32 maxSeqN,
        HitMapNode *child);

HitMapBufNodePtr2NodeHashTable *
createHitMapBufNode2NodeHT(TPMNode2 *srcnode, HitMapNode *hitMapNode);

IntrtmdtNode2HitMapNodeHashTalbe *
createIntermediateHitMapNode2HT(TPMNode1 *srcnode, HitMapNode *hitMapNode);

void
printHitMapNode(HitMapNode *node);

void
printHitMapNodeLit(HitMapNode *node);

void
printHitMapNodeAllVersion(HitMapNode *node);

void
printHitMapTransition(HitTransition *hTrans);

#endif

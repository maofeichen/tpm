#ifndef HITMAPNODE_H
#define HITMAPNODE_H

#include "type.h"

struct HitTransition;

struct HitMapNode {
    u32 bufId;   // ID of the buffer this node belongs to
    u32 addr;    // mem addr
    u32 version; // the version of current node, monotonically increasing from 0. Copy from TPMNode2
    u32 val;
    u32 bytesz;
    u32 lastUpdateTS; // the TS (seq#) of last update of the node. Copy from TPMNode2
    struct HitTransition *firstChild; // points to structure that points to the first child
    struct HitMapNode *leftNBR;       // point to node of adjacent, smaller memory address
    struct HitMapNode *rightNBR;      // point to node of adjacent, bigger memory address
    struct HitMapNode *nextVersion;   // point to node of the same addr buf of different version or age. Forms circular link
    u32 hitcnt; /* only used when checking avalanche effect between given source buffer & destination buffer.
     need to be initialized to be 0 for each pair of source & destination buffers checking.
     as source, the number of HitMapNode in the destination buffer this node hits; or
     as destination, the number of HitMapNode in the source buffer that hits this node    */
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

HitMapNode *
createHitMapNode(
        u32 bufId,
        u32 addr,
        u32 version,
        u32 val,
        u32 bytesz,
        u32 lastUpdateTS);

// TODO: delHitMapNode
#endif

#ifndef AVALANCHETYPE_H
#define AVALANCHETYPE_H

#include "tpmnode.h"
#include "uthash.h"


struct addr2NodeItem
{
    u32 addr;				/* 32-bit address: src addr in 1st level hash; dst addr in 2nd level hash */
    struct TPMNode2 *node;	/* used as key to hash: src node in 1st level hash; dst node in 2nd level hash */
    struct addr2NodeItem *subHash;	  /* next level hash */
    TaintedBuf *toMemNode; 			  // the mem node that the source node can propagate
    UT_hash_handle hh_addr2NodeItem;  /* makes this structure hashable */
};
typedef struct addr2NodeItem Addr2NodeItem;

#endif

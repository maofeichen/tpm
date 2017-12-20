/* 
 * tpmhash.h
 * 	all hash tables used by tpm
 */

#ifndef TPMHT_H
#define TPMHT_H

#include "uthash.h"

#define u32	unsigned int

/* hash tables, according to uthash */
struct SeqNoHT
{
    u32 seqNo;                  // key
    union TPMNode *toSeqNo;     // val
    UT_hash_handle hh_seqNo;    // hash table head
};

struct MemHT
{
    u32 addr;               // key
    struct TPMNode2 *toMem; // val
    UT_hash_handle hh_mem;  // hash table head, required by uthash
};

typedef struct MemHT MemHT;

// Returns:
//	0: success
//	<0: error
int
add_mem_ht(struct MemHT **mem2NodeHT, u32 addr, struct TPMNode2 *toMem);

struct MemHT* 
find_mem_ht(struct MemHT **mem2NodeHT, u32 addr);

void
del_mem_ht(struct MemHT **mem2NodeHT);

void 
count_mem_ht(struct MemHT **mem2NodeHT);

void 
print_mem_ht(struct MemHT **mem2NodeHT);
#endif
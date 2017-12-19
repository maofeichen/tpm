#ifndef CONTBUFHT_H
#define CONTBUFHT_H 

#include "uthash.h"

#define u32 unsigned int

struct ContBufHT
{
	u32 baddr;
	u32 eaddr;
	u32 minseq;
	u32 maxseq;
	UT_hash_handle hh_cont;
};

/* version hash table */
int
add_buf_ht(struct ContBufHT **contbufHT, u32 baddr, u32 eaddr, u32 minseq, u32 maxseq);

struct ContBufHT *
find_buf_ht(struct ContBufHT **contbufHT, u32 baddr);

void
del_buf_ht(struct ContBufHT **contbufHT);

void 
count_buf_ht(struct ContBufHT **contbufHT);

void 
print_buf_ht(struct ContBufHT **contbufHT);

#endif
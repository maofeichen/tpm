#include "tpmht.h"
#include <stdio.h>

int
add_mem(struct MemHT **mem2NodeHT, u32 addr, struct TPMNode2 *toMem)
{
	if(mem2NodeHT == NULL || toMem == NULL)
		return -1;

	struct MemHT *s;

	s = find_mem(mem2NodeHT, addr);
	if(s == NULL) 
	{	// if not found, creates new 
		s = (struct MemHT*)malloc(sizeof(struct MemHT) );
		s->addr = addr;
		HASH_ADD(hh_mem, *mem2NodeHT, addr, 4, s);
		s->toMem = toMem;
	} else 
	{	// if found, updates 
		s->toMem = toMem;
	}

	return 0;
}

struct MemHT* 
find_mem(struct MemHT **mem2NodeHT, u32 addr)
{
	struct MemHT *s;
	HASH_FIND(hh_mem, *mem2NodeHT, &addr, 4, s);
	return s;	
}

void
del_all_mem(struct MemHT **mem2NodeHT)
{
	struct MemHT *curr, *tmp;
	HASH_ITER(hh_mem, *mem2NodeHT, curr, tmp) {
		HASH_DELETE(hh_mem, *mem2NodeHT, curr);
		free(curr);
	}
}

void 
count_mem(struct MemHT **mem2NodeHT)
{
	u32 num;
	num = HASH_CNT(hh_mem, *mem2NodeHT);
	printf("total: %u mem addr in hash table\n", num);
}

void 
prnt_mem_ht(struct MemHT **mem2NodeHT)
{
	struct MemHT *s;
	for(s = *mem2NodeHT; s != NULL; s = s->hh_mem.next) {
		printf("mem - addr: %x - to mem node: %p\n", s->addr, s->toMem);
	}
}
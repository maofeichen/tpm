#include "contbufht.h"
#include <stdio.h>

int
add_buf_ht(struct ContBufHT **contbufHT, u32 baddr, u32 eaddr, u32 minseq, u32 maxseq)
{
	struct ContBufHT *s;

	if(contbufHT == NULL)
		return -1;

	s = find_buf_ht(contbufHT, baddr);
	if(s == NULL) {	// if not found, creates new 
		s = (struct ContBufHT*)malloc(sizeof(struct ContBufHT) );
		s->baddr = baddr;
		HASH_ADD(hh_cont, *contbufHT, baddr, 4, s);
		s->eaddr = eaddr;
		s->minseq = minseq;
		s->maxseq = maxseq;
	} else {	// if found, updates 
		if(s->eaddr < eaddr) {
			s->eaddr = eaddr;
			s->minseq = minseq;
			s->maxseq = maxseq;		
		}
	}

	return 0;
}

struct ContBufHT *
find_buf_ht(struct ContBufHT **contbufHT, u32 baddr)
{
	struct ContBufHT *s;
	HASH_FIND(hh_cont, *contbufHT, &baddr, 4, s);
	return s;	
}

void
del_buf_ht(struct ContBufHT **contbufHT)
{
	struct ContBufHT *curr, *tmp;
	HASH_ITER(hh_cont, *contbufHT, curr, tmp) {
		HASH_DELETE(hh_cont, *contbufHT, curr);
		free(curr);
	}
}

void 
count_buf_ht(struct ContBufHT **contbufHT)
{
	u32 num;
	num = HASH_CNT(hh_cont, *contbufHT);
	printf("total continuous buffers(>=8):%u\n", num);
}

void 
print_buf_ht(struct ContBufHT **contbufHT)
{
	struct ContBufHT *s;
	for(s = *contbufHT; s != NULL; s = s->hh_cont.next) {
		printf("begin:0x%-8x end:0x%-8x sz:%-4u minseq:%-6u maxseq:%-6u diffseq:%u\n", 
				s->baddr, s->eaddr, s->eaddr-s->baddr, s->minseq, s->maxseq, s->maxseq-s->minseq);	
	}
}
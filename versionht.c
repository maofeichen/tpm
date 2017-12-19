#include "versionht.h"

int
add_ver_ht(struct AddrHT **addrHT, u32 addr)
{
	struct AddrHT *s;

	if(addrHT == NULL)
		return -1;

	s = find_ver_ht(addrHT, addr);
	if(s == NULL) {	// if not found, creates new 
		s = (struct AddrHT*)malloc(sizeof(struct AddrHT) );
		s->addr = addr;
		HASH_ADD(hh_ver, *addrHT, addr, 4, s);
		s->ver = 1;
	} else {	// if found, updates 
		s->ver = s->ver+1;
	}

	return 0;
}

struct AddrHT *
find_ver_ht(struct AddrHT **addrHT, u32 addr)
{
	struct AddrHT *s;
	HASH_FIND(hh_ver, *addrHT, &addr, 4, s);
	return s;	
}

void
del_ver_ht(struct AddrHT **addrHT)
{
	struct AddrHT *curr, *tmp;
	HASH_ITER(hh_ver, *addrHT, curr, tmp) {
		HASH_DELETE(hh_ver, *addrHT, curr);
		free(curr);
	}
}

void 
count_ver_ht(struct AddrHT **addrHT)
{
	u32 num;
	num = HASH_CNT(hh_ver, *addrHT);
	printf("total: %u mem addr in hash table\n", num);
}

void 
print_ver_ht(struct AddrHT **addrHT)
{
	struct AddrHT *s;
	for(s = *addrHT; s != NULL; s = s->hh_ver.next) {
		printf("addr:%-8x ver:%u\n", s->addr, s->ver);
	}
}

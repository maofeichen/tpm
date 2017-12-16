#include "tpm.c"

#define u32 unsigned int

struct MemHT *hh = NULL;

void t_tpmhash(void);

void t_tpmhash()
{
	u32 addr = 0xbffff7a0;
	u32 val  = 0xbeef;
	u32 seq  = 0;

	struct MemHT *s;
	union TPMNode *n; 

	n = createTPMNode(TPM_Type_Memory, addr, val, seq);

	s = find_mem(&hh, addr);
	if(s == NULL) { printf("addr: 0x%x not in hash table\n", addr); }
	else { printf("addr: 0x%x in hash table\n", addr); }

	if(add_mem(&hh, addr, &(n->tpmnode2) ) == 0) { printf("add mem addr success\n"); }
	else { printf("add mem addr error\n");}

	s = find_mem(&hh, addr);
	if(s == NULL) { printf("addr: 0x%x not in hash table\n", addr); }
	else { printf("addr: 0x%x in hash table\n", addr); }

	count_mem(&hh);
	prnt_mem_ht(&hh);
	del_all_mem(&hh);
}

int main(int argc, char const *argv[])
{	
	t_tpmhash();
	return 0;
}
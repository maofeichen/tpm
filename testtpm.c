#include "tpm.c"

#define u32 unsigned int

struct MemHT *hh = NULL;

void t_tpmhash(void);
void t_tpm(void);


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

void t_tpm()
{
	struct TPMContext* tpm = NULL;
	union TPMNode *n; 
	struct MemHT *l, *r;
	int i;

	u32 addr1 = 0xbffff7a0;
	u32 val1  = 0xbeef;
	u32 seq1  = 0;

	u32 addr2 = 0xbffff7a4;
	u32 val2  = 0xbeef;
	u32 seq2  = 1;

	u32 addr3 = 0xbffff7a8;
	u32 val3  = 0xbeef;
	u32 seq3  = 2;

	tpm = calloc(1, sizeof(struct TPMContext) );

	n = createTPMNode(TPM_Type_Memory, addr1, val1, seq2);
	if(add_mem(&(tpm->mem2NodeHT), addr1, &(n->tpmnode2) ) == 0) { printf("add mem addr success\n"); }
	else { printf("add mem addr error\n");}

	n = createTPMNode(TPM_Type_Memory, addr3, val3, seq3);
	if(add_mem(&(tpm->mem2NodeHT), addr3, &(n->tpmnode2) ) == 0) { printf("add mem addr success\n"); }
	else { printf("add mem addr error\n");}

	count_mem(&(tpm->mem2NodeHT));
	prnt_mem_ht(&(tpm->mem2NodeHT));

	i = has_adjacent(tpm, l, r, addr2, 4);
	if(i > 0) { printf("addr: 0x%x found adjacent addr\n", addr2); }
	else { printf("addr: 0x%x not found adjacent addr\n", addr2); }

	del_all_mem(&(tpm->mem2NodeHT) );	// clear mem addr hash table
	free(tpm);	
}

int main(int argc, char const *argv[])
{	
	// t_tpmhash();
	t_tpm();
	return 0;
}
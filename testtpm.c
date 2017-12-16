#include "tpm.c"
#include <assert.h>

#define u32 unsigned int

struct MemHT *hh = NULL;

void t_tpmhash(void);
void t_tpm_mem(void);
void t_regcntxt_mask(void);
void t_handle_src_reg(void);
void t_handle_src_temp(void);

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

void t_tpm_mem()
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

void t_regcntxt_mask(void)
{
	int id = -1;

	id = get_regcntxt_idx(G_TEMP_ENV);
	assert(id == 1);
	printf("pass G_TEMP_ENV\n");

	id = get_regcntxt_idx(G_TEMP_ESP);
	assert(id == 10);
	printf("pass G_TEMP_ESP\n");

	id = get_regcntxt_idx(G_TEMP_EDI);
	assert(id == 13);
	printf("pass G_TEMP_EDI\n");
}

void t_handle_src_reg(void)
{
	struct TPMNode1 *regCntxt[NUM_REG]   = {0}; 
	struct TPMContext* tpm = NULL;
	struct Record rec = {0};
	union TPMNode* n = NULL;

	rec.s_addr = G_TEMP_ESI;
	rec.s_val  = 0xbeef;
	rec.ts 	   = 0;

	tpm = calloc(1, sizeof(struct TPMContext) );

	handle_src_reg(tpm, &rec, regCntxt, n);
	free(tpm);	
}

void t_handle_src_temp(void)
{
	struct TPMNode1 *tempCntxt[MAX_TEMPIDX]   = {0}; 
	struct TPMContext* tpm = NULL;
	struct Record rec = {0};
	union TPMNode* n = NULL;

	tpm = calloc(1, sizeof(struct TPMContext) );

	rec.s_addr = G_TEMP_ESI;
	rec.s_val  = 0xbeef;
	rec.ts 	   = 0;
	handle_src_temp(tpm, &rec, tempCntxt, n);

	rec.s_addr = 68;
	rec.s_val  = 0xbeef;
	rec.ts 	   = 0;
	handle_src_temp(tpm, &rec, tempCntxt, n);

	free(tpm);	
}

int main(int argc, char const *argv[])
{	
	// t_tpmhash();
	// t_tpm();
	// t_regcntxt_mask();
	t_handle_src_reg();
	t_handle_src_temp();
	return 0;
}
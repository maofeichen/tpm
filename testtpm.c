#include "tpm.c"
#include <assert.h>

#define u32 unsigned int

struct MemHT *hh = NULL;

void t_tpmhash(void);
void t_tpm_mem(void);
void t_regcntxt_mask(void);
void t_handle_src_reg(void);
void t_handle_src_temp(void);
void t_mem_version(void);
void t_has_adjacent(void);
void t_trans(void);

void t_tpmhash()
{
	u32 addr = 0xbffff7a0;
	u32 val  = 0xbeef;
	u32 seq  = 0;

	struct MemHT *s;
	union TPMNode *n; 

	n = createTPMNode(TPM_Type_Memory, addr, val, seq);

	s = find_mem_ht(&hh, addr);
	if(s == NULL) { printf("addr: 0x%x not in hash table\n", addr); }
	else { printf("addr: 0x%x in hash table\n", addr); }

	if(add_mem_ht(&hh, addr, &(n->tpmnode2) ) == 0) { printf("add mem addr success\n"); }
	else { printf("add mem addr error\n");}

	s = find_mem_ht(&hh, addr);
	if(s == NULL) { printf("addr: 0x%x not in hash table\n", addr); }
	else { printf("addr: 0x%x in hash table\n", addr); }

	count_mem_ht(&hh);
	print_mem_ht(&hh);
	del_mem_ht(&hh);
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
	if(add_mem_ht(&(tpm->mem2NodeHT), addr1, &(n->tpmnode2) ) == 0) { printf("add mem addr success\n"); }
	else { printf("add mem addr error\n");}

	n = createTPMNode(TPM_Type_Memory, addr3, val3, seq3);
	if(add_mem_ht(&(tpm->mem2NodeHT), addr3, &(n->tpmnode2) ) == 0) { printf("add mem addr success\n"); }
	else { printf("add mem addr error\n");}

	count_mem_ht(&(tpm->mem2NodeHT));
	print_mem_ht(&(tpm->mem2NodeHT));

	if(has_adjacent(tpm, &l, &r, addr2, 4)) { printf("addr: 0x%x found adjacent addr\n", addr2); }
	else { printf("addr: 0x%x not found adjacent addr\n", addr2); }

	del_mem_ht(&(tpm->mem2NodeHT) );	// clear mem addr hash table
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

void t_mem_version(void)
{
	struct TPMContext* tpm = NULL;
	union TPMNode *front, *next, *third; 
	struct MemHT *l, *r;
	int i;

	u32 addr1 = 0xbffff7a0;
	u32 val1  = 0xbee0;
	u32 seq1  = 0;

	u32 addr2 = 0xbffff7a0;
	u32 val2  = 0xbee4;
	u32 seq2  = 1;

	u32 addr3 = 0xbffff7a0;
	u32 val3  = 0xbee8;
	u32 seq3  = 2;

	front = create_first_version(addr1, val1, seq1);
	set_version(front, 0);

	next = createTPMNode(TPM_Type_Memory, addr2, val2, seq2);
	set_version(next, 1);
	add_next_version(&(front->tpmnode2), &(next->tpmnode2) );

	print_version(&(front->tpmnode2) );

	third = createTPMNode(TPM_Type_Memory, addr3, val3, seq3);
	set_version(third, 2);
	add_next_version(&(next->tpmnode2), &(third->tpmnode2) );

	print_version(&(front->tpmnode2) );
}

void t_has_adjacent()
{
	struct TPMContext* tpm = NULL;
	union TPMNode *n1, *n2, *n3, *n4, *n5; 
	struct MemHT *l, *r;
	int i;
	u32 ver; 

	u32 addr1 = 0xbffff7a0;
	u32 val1  = 0xbeef;
	u32 seq1  = 0;

	u32 addr4 = 0xbffff7a0;
	u32 val4  = 0xbeef0;
	u32 seq4  = 1; 

	u32 addr2 = 0xbffff7a4;
	u32 val2  = 0xbeef;
	u32 seq2  = 3;

	u32 addr3 = 0xbffff7a8;
	u32 val3  = 0xbeef;
	u32 seq3  = 4;

	u32 addr5 = 0xbffff7a8;
	u32 val5  = 0xbfee0;
	u32 seq5  = 5;

	tpm = calloc(1, sizeof(struct TPMContext) );

	n1 = create_first_version(addr1, val1, seq1);
	if(add_mem_ht(&(tpm->mem2NodeHT), addr1, &(n1->tpmnode2) ) == 0) { printf("add mem addr success\n"); }
	else { printf("add mem addr error\n");}

	n2 = createTPMNode(TPM_Type_Memory, addr4, val4, seq4);
	l = find_mem_ht(&(tpm->mem2NodeHT), addr4);
	ver = get_version(l->toMem);
    set_version(n2, ver+1); // set version accordingly
	if(add_mem_ht(&(tpm->mem2NodeHT), addr4, &(n2->tpmnode2) ) == 0) { printf("add mem addr success\n"); }
	else { printf("add mem addr error\n");}
	add_next_version(&(n1->tpmnode2), &(n2->tpmnode2) );

	n3 = create_first_version(addr3, val3, seq3);
	if(add_mem_ht(&(tpm->mem2NodeHT), addr3, &(n3->tpmnode2) ) == 0) { printf("add mem addr success\n"); }
	else { printf("add mem addr error\n");}

	n4 = createTPMNode(TPM_Type_Memory, addr5, val5, seq5);
	r = find_mem_ht(&(tpm->mem2NodeHT), addr5);
	ver = get_version(r->toMem);
	set_version(n4, ver+1);
	if(add_mem_ht(&(tpm->mem2NodeHT), addr5, &(n4->tpmnode2) ) == 0) { printf("add mem addr success\n"); }
	else { printf("add mem addr error\n");}
	add_next_version(&(n3->tpmnode2), &(n4->tpmnode2) );

	count_mem_ht(&(tpm->mem2NodeHT));
	print_mem_ht(&(tpm->mem2NodeHT));

	printf("0xbffff7a0 version: \n");
	print_version(n1);
	printf("0xbffff7a8 version: \n");
	print_version(n3);

	n5 = create_first_version(addr2, val2, seq2);

	update_adjacent(tpm, n5, &l, &r, addr2, 4);
	printf("leftNBR:\n");
	print_mem_node(n5->tpmnode2.leftNBR);
    printf("rightNBR:\n");
    print_mem_node(n5->tpmnode2.rightNBR);

    printf("0xbffff7a0 version: \n");
	print_version(n1);
	printf("0xbffff7a8 version: \n");
	print_version(n3);

	del_mem_ht(&(tpm->mem2NodeHT) );	// clear mem addr hash table
	free(tpm);	
}

void t_trans(void)
{
	struct TPMContext* tpm = NULL;
	union TPMNode *n1, *n2, *n3; 
	struct MemHT *l, *r;
	int i;
	u32 ver; 

	u32 addr1 = 0xbffff7a0;
	u32 val1  = 0xbeef;
	u32 seq1  = 0;

	u32 addr2 = 0xbffff7a4;
	u32 val2  = 0xbeef;
	u32 seq2  = 3;

	u32 addr3 = 0xbffff7a8;
	u32 val3  = 0xbeef;
	u32 seq3  = 4;

	tpm = calloc(1, sizeof(struct TPMContext) );

	n1 = create_first_version(addr1, val1, seq1);
	n2 = create_first_version(addr2, val2, seq2);
	create_trans_node(seq2, TPM_Type_Memory, n1, n2);

	printf("trasn source:\n");
	print_mem_node(&(n1->tpmnode2) );
	printf("trans destination:\n");
	print_transition(n1);

	n3 = create_first_version(addr3, val3, seq3);
	create_trans_node(seq3, TPM_Type_Memory, n1, n3);
	printf("trans destination:\n");
	print_transition(n1);

	free(tpm);
}

int main(int argc, char const *argv[])
{	
	// t_tpmhash();
	// t_tpm_mem();
	// t_regcntxt_mask();
	// t_handle_src_reg();
	// t_handle_src_temp();
	// t_mem_version();
	// t_has_adjacent();
	t_trans();
	return 0;
}
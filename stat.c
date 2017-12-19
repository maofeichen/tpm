#include "stat.h"

static u32 
get_out_degree(union TPMNode *t);

/* version hash table */
static int
add_ver_ht(struct AddrHT **addrHT, u32 addr);

static struct AddrHT *
find_ver_ht(struct AddrHT **addrHT, u32 addr);

static void
del_ver_ht(struct AddrHT **addrHT);

static void 
count_ver_ht(struct AddrHT **addrHT);

static void 
print_ver_ht(struct AddrHT **addrHT);

static int
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

static struct AddrHT *
find_ver_ht(struct AddrHT **addrHT, u32 addr)
{
	struct AddrHT *s;
	HASH_FIND(hh_ver, *addrHT, &addr, 4, s);
	return s;	
}

static void
del_ver_ht(struct AddrHT **addrHT)
{
	struct AddrHT *curr, *tmp;
	HASH_ITER(hh_ver, *addrHT, curr, tmp) {
		HASH_DELETE(hh_ver, *addrHT, curr);
		free(curr);
	}
}

static void 
count_ver_ht(struct AddrHT **addrHT)
{
	u32 num;
	num = HASH_CNT(hh_ver, *addrHT);
	printf("total: %u mem addr in hash table\n", num);
}

static void 
print_ver_ht(struct AddrHT **addrHT)
{
	struct AddrHT *s;
	for(s = *addrHT; s != NULL; s = s->hh_ver.next) {
		printf("addr:%-8x ver:%u\n", s->addr, s->ver);
	}
}

void 
get_cont_buf(struct TPMNode2 *node, u32 *baddr, u32 *eaddr, u32 *minseq, u32 *maxseq)
{
	struct TPMNode2 *b, *e;
	*minseq = 100000;
	*maxseq = 0;

	b = e = node;
	while(b->leftNBR != NULL) {
		u32 seq = b->lastUpdateTS;

		if(*minseq > seq)
			*minseq = seq;

		if(*maxseq < seq)
			*maxseq = seq;

		b = b->leftNBR;
	}
	*baddr = b->addr;

	while(e->rightNBR != NULL) {
		u32 seq = e->lastUpdateTS;
		if(*minseq > seq)
			*minseq = seq;

		if(*maxseq < seq)
			*maxseq = seq;

		e = e->rightNBR;
	}
	*eaddr = e->addr + 4;

	// if((*eaddr - *baddr) >= 8)
	// 	printf("begin addr:0x%-8x end addr:0x%-8x minseq:%u maxseq:%u\n", *baddr, *eaddr, *minseq, *maxseq);	
}

void 
compute_cont_buf(struct TPMContext *tpm)
{
	struct ContBufHT *bufHT = NULL, *s;
	u32 baddr, eaddr, minseq, maxseq;

	for(int i = 0; i < seqNo2NodeHashSize; i++) {
		if(tpm->seqNo2NodeHash[i] != NULL) {
			union TPMNode *t = tpm->seqNo2NodeHash[i];
			if(t->tpmnode1.type == TPM_Type_Memory) {
				get_cont_buf(&(t->tpmnode2), &baddr, &eaddr, &minseq, &maxseq );
				if( (eaddr - baddr) >= 8) {
					s = find_buf_ht(&bufHT, baddr);
					if(s == NULL) {
						if(add_buf_ht(&bufHT, baddr, eaddr, minseq, maxseq) >= 0) {}
						else { fprintf(stderr, "error: add buf ht\n"); return; }
					}
					else {
						if(s->eaddr < eaddr) {
							s->eaddr = eaddr;
							s->minseq = minseq;
							s->maxseq = maxseq;		
						}
					}
				}
			}
		}
	}

	u32 minsz = BIG_NUM, maxsz = 0, totalsz = 0;
	u32 num = HASH_CNT(hh_cont, bufHT);
	printf("total continuous buffers(>=8):%u\n", num);

	struct ContBufHT *t;
	for(t = bufHT; t != NULL; t = t->hh_cont.next) {
		u32 sz = t->eaddr - t->baddr;
		if(minsz > sz)
			minsz = sz;

		if(maxsz < sz)
			maxsz = sz;

		totalsz += sz;
	}
	printf("continuous buffers: min sz:%-2u bytes avg sz:%-2u bytes max sz:%-2u bytes\n", minsz, totalsz/num, maxsz);
	// count_buf_ht(&bufHT);
	printf("--------------------\n");
	print_buf_ht(&bufHT);
	del_buf_ht(&bufHT);
}

void compute_version(struct TPMContext *tpm, u32 type)
{
	struct AddrHT *addrHT = NULL;
	struct AddrHT *s;

	u32 min = BIG_NUM, max = 0, total = 0;
	int i = 0, n = 0; 
	for(; i < seqNo2NodeHashSize; i++) {
		if(tpm->seqNo2NodeHash[i] != NULL) {
			union TPMNode *t = tpm->seqNo2NodeHash[i];
			if(t->tpmnode1.type == type) {
				u32 addr = t->tpmnode1.addr;

				s = find_ver_ht(&addrHT, addr);
				if(s == NULL) { // not in hash table
					if(add_ver_ht(&addrHT, addr) >= 0) {}
					else {
						fprintf(stderr, "error: add ver ht\n");
						return;
					}
				}
				else {
					s->ver = s->ver+1;
				}
			}
		}
	}

	for(s = addrHT; s != NULL; s = s->hh_ver.next) {
		// printf("mem: addr:%-8x ver:%u\n", s->addr, s->ver);
		if(min > s->ver)
			min = s->ver;

		if(max < s->ver)
			max = s->ver;

		total += s->ver;
	}
	n = HASH_CNT(hh_ver, addrHT);
	// print_ver_ht(&addrHT);

	switch(type){
		case TPM_Type_Memory:
			printf("mem  version: min:%-8u avg:%-8u max:%-8u\n", min, total/n, max);
			break;
		case TPM_Type_Register:
			printf("reg  version: min:%-8u avg:%-8u max:%-8u\n", min, total/n, max);
			break;	
		case TPM_Type_Temprary:
			printf("temp version: min:%-8u avg:%-8u max:%-8u\n", min, total/n, max);
			break;
		default:
			fprintf(stderr, "unkown type\n");
			break;	
	}
	del_ver_ht(&addrHT);	
}

void compute_version_all(struct TPMContext *tpm)
{
	struct AddrHT *addrHT = NULL;
	struct AddrHT *s;

	u32 min = BIG_NUM, max = 0, total = 0;
	int i = 0, n = 0; 
	for(; i < seqNo2NodeHashSize; i++) {
		if(tpm->seqNo2NodeHash[i] != NULL) {
			union TPMNode *t = tpm->seqNo2NodeHash[i];
			u32 addr = t->tpmnode1.addr;

			s = find_ver_ht(&addrHT, addr);
			if(s == NULL) { // not in hash table
				if(add_ver_ht(&addrHT, addr) >= 0) {}
				else {
					fprintf(stderr, "error: add ver ht\n");
					return;
				}
			}
			else {
				s->ver = s->ver+1;
			}
		}
	}

	for(s = addrHT; s != NULL; s = s->hh_ver.next) {
		// printf("mem: addr:%-8x ver:%u\n", s->addr, s->ver);
		if(min > s->ver)
			min = s->ver;

		if(max < s->ver)
			max = s->ver;

		total += s->ver;
	}
	n = HASH_CNT(hh_ver, addrHT);
	// print_ver_ht(&addrHT);
	printf("all  version: min:%-8u avg:%-8u max:%-8u\n", min, total/n, max);
	del_ver_ht(&addrHT);	
}

void 
compute_outd(struct TPMContext *tpm, u32 type)
{
	u32 num = 0, min = BIG_NUM, max = 0, total = 0;
	int i = 0;

	for(; i < seqNo2NodeHashSize; i++) {
		if(tpm->seqNo2NodeHash[i] != NULL) {
			union TPMNode *n = tpm->seqNo2NodeHash[i];
			if(n->tpmnode1.type == type) {
				int outd = get_out_degree(tpm->seqNo2NodeHash[i]);

				if(min > outd)
					min = outd;

				if(max < outd)
					max = outd;

				total += outd;
				num++;
			}
		}
	}

	switch(type){
		case TPM_Type_Memory:
			printf("mem  outdegree: min:%-4u avg:%-4u max:%-4u\n", min, total/num, max);
			break;
		case TPM_Type_Register:
			printf("reg  outdegree: min:%-4u avg:%-4u max:%-4u\n", min, total/num, max);
			break;	
		case TPM_Type_Temprary:
			printf("temp outdegree: min:%-4u avg:%-4u max:%-4u\n", min, total/num, max);
			break;
		default:
			fprintf(stderr, "unkown type\n");
			break;	
	}
}

void 
compute_outd_all(struct TPMContext *tpm)
{
	u32 num = 0, min = BIG_NUM, max = 0, total = 0;
	int i = 0;

	for(; i < seqNo2NodeHashSize; i++) {
		if(tpm->seqNo2NodeHash[i] != NULL) {
			int outd = get_out_degree(tpm->seqNo2NodeHash[i]);

			if(min > outd)
				min = outd;

			if(max < outd)
				max = outd;

			total += outd;
			num++;
		}
	}
	printf("all  outdegree: min:%-4u avg:%-4u max:%-4u\n", min, total/num, max);
}

void 
compute_total_node(struct TPMContext *tpm)
{
	int i = 0, n = 0; 
	for(; i < seqNo2NodeHashSize; i++) {
		if(tpm->seqNo2NodeHash[i] != NULL)
			n++;
	}
	printf("total nodes:%d\n", n);
}

void 
stat(struct TPMContext *tpm)
{
	compute_outd_all(tpm);
	compute_outd(tpm, TPM_Type_Memory);
	compute_outd(tpm, TPM_Type_Register);
	compute_outd(tpm, TPM_Type_Temprary);
	printf("--------------------\n");
	compute_version_all(tpm);
	compute_version(tpm, TPM_Type_Memory);
	compute_version(tpm, TPM_Type_Register);
	compute_version(tpm, TPM_Type_Temprary);
	printf("--------------------\n");
	compute_cont_buf(tpm);
}

static u32  
get_out_degree(union TPMNode *t)
{
	u32 n = 0;
	struct Transition *tran = t->tpmnode1.firstChild;
	while (tran != 0) {
		n++;
		tran = tran->next;
	}
	// printf("outdegree:%-2u\n", n);
	return n;
}

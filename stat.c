#include "stat.h"

static u32 
get_out_degree(union TPMNode *t);

static union TPMNode *
get_firstnode_in_ht(struct TPMContext *tpm, u32 type);

void 
get_cont_buf(struct TPMNode2 *node, u32 *baddr, u32 *eaddr, u32 *minseq, u32 *maxseq)
// Computes 
//	- baddr
//	- eaddr
//	- minseq
//	- maxseq
//	given a memory node
{
	struct TPMNode2 *b, *e;
	*minseq = node->lastUpdateTS;
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
	*eaddr = e->addr + 4;	// assume end addr always 4 bytes

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
				if( (eaddr - baddr) >= MIN_BUF_SZ) {
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

	u32 minsz, maxsz = 0, totalsz = 0;
	u32 num = HASH_CNT(hh_cont, bufHT);
	printf("total continuous buffers(>=8):%u\n", num);

	minsz = bufHT->eaddr - bufHT->baddr;
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

	u32 min, max = 0, total = 0;
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

	min = addrHT->ver;
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

	u32 min, max = 0, total = 0;
	int i = 0, n = 0;

	// search all nodes and get versions 
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

	min = addrHT->ver;
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
	u32 num = 0, min, max = 0, total = 0;
	int i = 0;

	union TPMNode *n = (union TPMNode*)get_firstnode_in_ht(tpm, type);
	min = get_out_degree(n);

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
	u32 num = 0, min, max = 0, total = 0;
	int i = 0;

	union TPMNode *n = (union TPMNode*)get_firstnode_in_ht(tpm, 0);
	min = get_out_degree(n);

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

static union TPMNode *
get_firstnode_in_ht(struct TPMContext *tpm, u32 type)
// Returns:
//	first node in hashtalbe based on type, if type is 0, then all types
{
	union TPMNode *n = NULL;

	if(type != 0) {
		for(int i = 0; i < seqNo2NodeHashSize; i++) {
			if(tpm->seqNo2NodeHash[i] != NULL) {
				n = tpm->seqNo2NodeHash[i];
				if(n->tpmnode1.type == type) {
					return n;
				}
			}
		}
	} 
	else {
		for(int i = 0; i < seqNo2NodeHashSize; i++) {
			if(tpm->seqNo2NodeHash[i] != NULL) {
				return tpm->seqNo2NodeHash[i]; 
			}
		}
	}

	return n;
}
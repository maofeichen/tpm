/*
 * tpm.c
 * 
 * created on 12/8/2017
 * 
 * */

#include "tpm.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>

u32 
isPropagationOverwriting(u32 flag)
/* return:
 * 	0: not overwriting
 *  non-0: overwriting
 */
{
  /* to be added */
  
  return 0;
}

union TPMNode *
createTPMNode(u32 type, u32 addr, u32 TS)
{
    union TPMNode *tpmnode;
    
    if (type & TPM_Type_Memory)
    {
	tpmnode = malloc(sizeof(struct TPMNode2));
	memset(&tpmnode->tpmnode2, 0, sizeof(struct TPMNode2));
	tpmnode->tpmnode2.type = type;
	tpmnode->tpmnode2.addr = addr;
	tpmnode->tpmnode2.lastUpdateTS = TS;
    }
    else if ((type & TPM_Type_Register) || (type & TPM_Type_Temprary))
    {
	tpmnode = malloc(sizeof(struct TPMNode1));
	tpmnode->tpmnode1.type = type;
	tpmnode->tpmnode1.addr = addr;
	tpmnode->tpmnode1.lastUpdateTS = TS;
	tpmnode->tpmnode1.firstChild = NULL;
    }
    else return NULL;

    return tpmnode;
}

u32 
processOneXTaintRecord(struct TPMContext *tpm, u32 seqNo, u32 size, u32 srcflg, u32 srcaddr, u32 dstflag, u32 dstaddr)
/* return:
 * 	0: success
 *     <0: error
 */
{
  
  
    return 0;
}

u32 
buildTPM(FILE *taintfp, struct TPMContext *tpm)
/* return:
 * 	>=0: number of TPM nodes created;
 *     <0: error
 */
{
    int n = 0, l = 0;
    char line[128] = {0};

    init_tpmcontext(tpm);

    while(fgets(line, sizeof(line), taintfp) ) {
        char flag[3] = {0};

        if(get_flag(flag, line) ) {
            if(is_mark(flag) ) { // is mark record?
                if(equal_mark(flag, INSN_MARK) ) {
                    // do sth
                    // printf("flag: %s\n", flag);
                }
            } else {
                struct Record rec = {0};
                if(split(line, '\t', &rec) == 0) {
                    p_record(&rec);
                    n++;
                }else { fprintf(stderr, "error: split\n"); return -1; }
            }
        } else { fprintf(stderr, "error: get flag\n"); return -1; }

        l++;
        // printf("%s", line);
    }    

    printf("total lines:\t%d - total nodes:\t%d\n", l, n);
    
    return n;
}

struct TPMNode2 *
mem2NodeSearch(struct TPMContext *tpm, u32 memaddr)
/* return:
 * 	NULL: no node founded with the memaddr
 *  non-NULL: points to the latest version of the TPM node that has the memaddr
 */
{
    struct TPMNode2 *tpmnode2;
    
    return tpmnode2;
}

union TPMNode *
seqNo2NodeSearch(struct TPMContext *tpm, u32 seqNo)
{
    union TPMNode *tpmnode;
    
    return tpmnode;
}

void 
init_tpmcontext(struct TPMContext *tpm)
{
    tpm->nodeNum        = 0;
    tpm->memAddrNum     = 0;
    tpm->tempVarNum     = 0;
    tpm->mem2NodeHT     = NULL;
    // tpm->seqNo2NodeHT   = NULL;
    tpm->minBufferSz    = MIN_BUF_SZ;
    tpm->taintedBufNum  = 0;
    tpm->taintedbuf     = NULL;
}

void 
p_record(struct Record* rec)
{
    printf("record: flag: %x - src addr: %x - src val: %x - dst addr: %x - dst val: %x "
                            "- size: %d - seqNo: %d\n", 
            rec->flag, rec->s_addr, rec->s_val, rec->d_addr, rec->d_val, rec->bytesz, rec->ts);
}
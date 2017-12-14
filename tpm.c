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

/* Helper functions */
static void 
init_tpmcontext(struct TPMContext *tpm);

static void 
clear_tempcontext(struct TPMNode1 *tempCntxt[] );

static int
handle_source(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], struct TPMNode1 *tempCntxt[])

static int
handle_destination(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], struct TPMNode1 *tempCntxt[])

static void 
prnt_record(struct Record* rec);

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

// u32 
// processOneXTaintRecord(struct TPMContext *tpm, u32 seqNo, u32 size, u32 srcflg, u32 srcaddr, u32 dstflag, u32 dstaddr)
u32
processOneXTaintRecord(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], struct TPMNode1 *tempCntxt[])
/* return:
 * 	>=0 : success and num of nodes creates
 *     <0: error
 */
{
    // TODO:
    //  handle source node
    //  hanlde destination node
    //  creates transition node  
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
    struct TPMNode1 *regCntxt[NUM_REG]   = {0}; // points to the latest register node
    struct TPMNode1 *tempCntxt[NUM_TEMP] = {0}; // points to the latest temp node

    init_tpmcontext(tpm);

    char line[128] = {0};
    while(fgets(line, sizeof(line), taintfp) ) 
    {
        char flag[3] = {0};
        if(get_flag(flag, line) ) 
        {
            if(is_mark(flag) ) 
            { // mark record, simply skip except for insn mark
                if(equal_mark(flag, INSN_MARK) ) {
                    // printf("flag: %s\n", flag);
                    // TODO: 
                    //  clear current context of temp, due to temp are 
                    //  only alive within instruction, if encounter an insn mark
                    //  it crosses insn boundary
                    clear_tempcontext(tempCntxt); 
                } // else do nothing
            } else { // data record, creates nodes
                struct Record rec = {0};
                if(split(line, '\t', &rec) == 0) 
                {
                    // prnt_record(&rec);
                    int i = 0;
                    if( (i = processOneXTaintRecord(tpm, &rec, regCntxt, tempCntxt) ) >= 0)
                    {
                        n += i;
                    } else { fprintf(stderr, "error: processOneXTaintRecord\n"); return -1; }
                    n++; // TODO: n should increase by how many new node create each record
                } else { fprintf(stderr, "error: split\n"); return -1; }
            }
        } else { fprintf(stderr, "error: get flag\n"); return -1; }

        l++;
        // printf("%s", line);
    }    

    printf("total lines:\t%d - total data records:\t%d\n", l, n);
    
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

static void 
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

static void 
clear_tempcontext(struct TPMNode1 *tempCntxt[] )
// TODO
{

}

static void 
prnt_record(struct Record* rec)
{
    printf("record: flag: %x - src addr: %x - src val: %x" 
                            "- dst addr: %x - dst val: %x "
                            "- size: %d - seqNo: %d\n", 
            rec->flag, rec->s_addr, rec->s_val, rec->d_addr, rec->d_val, rec->bytesz, rec->ts);
}
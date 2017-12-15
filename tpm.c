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

/* handle each case of source and destination to process a record */
static union TPMNode* 
handle_src_mem(struct TPMContext *tpm, struct Record *rec);

static union TPMNode* 
handle_src_reg(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[]);

static union TPMNode* 
handle_src_temp(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *tempCntxt[]);

static union TPMNode* 
handle_dst_mem(struct TPMContext *tpm, struct Record *rec);

static union TPMNode* 
handle_dst_reg(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[]);

static union TPMNode* 
handle_dst_temp(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *tempCntxt[]);

static struct Transition* 
create_trans_node(struct Record *rec, u32 s_type, union TPMNode* src, union TPMNode* dst);

/* Helper functions */
static void 
init_tpmcontext(struct TPMContext *tpm);

static void 
clear_tempcontext(struct TPMNode1 *tempCntxt[] );

static int 
get_type(u32 flag);

static void 
prnt_record(struct Record *rec);

static void 
prnt_src_addr(struct Record *rec);

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
    int type;

    //  handle source node
    if(rec->is_load) { handle_src_mem(tpm, rec); }  // src is mem addr   
    else 
    { // src is either reg or temp  
        type = get_type(rec->s_addr);
        if (type == TPM_Type_Register) { handle_src_reg(tpm, rec, regCntxt); }
        else if (type == TPM_Type_Temprary) { handle_src_temp(tpm, rec, tempCntxt); }
        else { fprintf(stderr, "error: handle source node\n"); return -1; }
    }

    //  hanlde destination node
    if(rec->is_store) { handle_dst_mem(tpm, rec); } // dst is mem addr
    else 
    { // dst is either reg or temp
        type = get_type(rec->d_addr);
        if(type == TPM_Type_Register) { handle_dst_reg(tpm, rec, regCntxt); }
        else if(type == TPM_Type_Temprary) { handle_dst_temp(tpm, rec, tempCntxt); }
        else { fprintf(stderr, "error: handle destination node\n"); return -1; }
    }

    // TODO:
    //  creates transition node, need to deal how bind the transition node pointer 

    return 0;
}

u32 
buildTPM(FILE *taintfp, struct TPMContext *tpm)
/* return:
 * 	>=0: number of TPM nodes created;
 *     <0: error
 */
{
    int n = 0, l = 0, r = 0;
    struct TPMNode1 *regCntxt[NUM_REG]   = {0}; // points to the latest register node
    struct TPMNode1 *tempCntxt[MAX_TEMPIDX] = {0}; // points to the latest temp node

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
                    //  clear current context of temp, due to temp are 
                    //  only alive within instruction, if encounter an insn mark
                    //  it crosses insn boundary
                    clear_tempcontext(tempCntxt); 
                } // else do nothing
            } 
            else 
            { // data record, creates nodes
                struct Record rec = {0};
                if(split(line, '\t', &rec) == 0) 
                {
                    // prnt_record(&rec);
                    int i = 0;
                    // n increases by how many new nodes created 
                    if( (i = processOneXTaintRecord(tpm, &rec, regCntxt, tempCntxt) ) >= 0) { n += i; } 
                    else { fprintf(stderr, "error: processOneXTaintRecord\n"); return -1; }
                    r++; 
                } 
                else { fprintf(stderr, "error: split\n"); return -1; }
            }
        } 
        else { fprintf(stderr, "error: get flag\n"); return -1; }

        l++;
        // printf("%s", line);
    }    

    printf("total lines:\t%d - total data records:\t%d\n", l, r);
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


static union TPMNode* 
handle_src_mem(struct TPMContext *tpm, struct Record *rec)
// Returns the created or found node (pointer) 
//  1. detects if it's in mem hash table (tpm->memHT)
//      1.1 not found: a new addr
//          a) creates new node
//              1) init "version" to 0 (the earlest)
//          b) updates:
//              1) the mem hash table (tpm->memHT)
//              2) seqNo hash table (tpm->seqNo2NodeHash)
//      1.2 found
//          !!! detects if the value of the mem equals the val of the latest version 
//          of the same addr, due to if same, it's a valid taint propagation.
//          1.2.1 the values are same
//              a) it's valid propagation, do nothing (to handle the destination node)
//          1.2.2 the values are different
//              a) creates a new node
//                  init version as previous version plus one
//              b) updates its previous version pointer (prev->nextversion points to it)
//              b) updates same as 1.1 b)
//  2. updates neighbours: 
//      2.1 detects if its left neighbour exists
//          a) yes, updates its leftNBR points to the earliest version of its left adjcent mem addr
//          b) no, do nothing
//      2.2 detects if its right neighbour exist, similar to 2.1, and updates it's rightNBR
{
    // prnt_src_addr(rec);

    return 0;
}

static union TPMNode* 
handle_src_reg(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[])
{
    // prnt_src_addr(rec);
    return 0;
}

static union TPMNode* 
handle_src_temp(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *tempCntxt[])
{
    // prnt_src_addr(rec);
    return 0;
}

static union TPMNode* 
handle_dst_mem(struct TPMContext *tpm, struct Record *rec)
{
    // prnt_record(rec);
    return 0;
}

static union TPMNode* 
handle_dst_reg(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[])
{
    // prnt_record(rec);
    return 0;
}

static union TPMNode* 
handle_dst_temp(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *tempCntxt[])
{
    // prnt_record(rec);
    return 0;
}

static struct Transition* 
create_trans_node(struct Record *rec, u32 s_type, union TPMNode *src, union TPMNode *dst)
// Returns
//  pointer of the created transition node 
//  NULL : error 
{
    if(src == NULL || dst == NULL)
        return NULL;

    struct Transition *t, *tmp;

    t = (struct Transition*)malloc(sizeof(struct Transition) );
    t->seqNo = rec->ts; // timestamp
    t->child = dst;
    t->next = NULL;

    if(s_type & TPM_Type_Memory) 
    {
        tmp = src->tpmnode2.firstChild;
    }
    else if(s_type & TPM_Type_Temprary || s_type & TPM_Type_Register) 
    {
        tmp = src->tpmnode1.firstChild;
    }

    while(tmp->next != NULL) 
    { 
        tmp = tmp->next; 
    }    // reaches last child 
    tmp->next = t;  // links t to list end

    return t;
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

static int 
get_type(u32 addr)
// Returns:
//  reg or temp based on the addr 
{
    if(addr < G_TEMP_UNKNOWN) 
    {
        return TPM_Type_Temprary;
    }
    else if(addr <=  G_TEMP_EDI) 
    {
        return TPM_Type_Register;
    } 
    else { fprintf(stderr, "error: unkown addr type\n"); return -1; }
}

static void 
prnt_record(struct Record* rec)
{
    printf("record: flag: %x src addr: %x\t\t src val: %x\t\t" 
                            "dst addr: %x\t\t dst val: %x\t\t"
                            "size: %d\t seqNo: %d\tis_load: %u is_store: %u\n", 
            rec->flag, rec->s_addr, rec->s_val, 
            rec->d_addr, rec->d_val, 
            rec->bytesz, rec->ts, rec->is_load, rec->is_store);
}

static void 
prnt_src_addr(struct Record *rec)
{
    printf("source addr: %x - seqNo: %d\n", rec->s_addr, rec->ts);
}
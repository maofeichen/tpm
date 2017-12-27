/*
 * tpm.c
 * 
 * created on 12/8/2017
 * 
 * */

#include "tpm.h"
#include "record.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* mem addr hash table */

// Returns:
//  0: success
//  <0: error
static int
add_mem_ht(struct MemHT **mem2NodeHT, u32 addr, struct TPMNode2 *toMem);

static struct MemHT* 
find_mem_ht(struct MemHT **mem2NodeHT, u32 addr);

static void
del_mem_ht(struct MemHT **mem2NodeHT);

static void 
count_mem_ht(struct MemHT **mem2NodeHT);

static void 
print_mem_ht(struct MemHT **mem2NodeHT);

/* TPMContext related */
static void 
init_tpmcontext(struct TPMContext *tpm);

/* handles different cases of source and destination when processing a record */
static int 
handle_src_mem(struct TPMContext *tpm, struct Record *rec, union TPMNode **src);

static int 
handle_src_reg(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], union TPMNode **src);

static int  
handle_src_temp(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *tempCntxt[], union TPMNode **src);

static int 
handle_dst_mem(struct TPMContext *tpm, struct Record *rec, union TPMNode **dst);

static int 
handle_dst_reg(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], union TPMNode **dst);

static int 
handle_dst_temp(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *tempCntxt[], union TPMNode **dst);

/* transition node */
static struct Transition *
create_trans_node(u32 ts, u32 s_type, union TPMNode* src, union TPMNode* dst);

/* validate taint propagation */
static bool 
is_equal_value(u32 val, union TPMNode *store);

/* mem addr hash table */
static bool  
is_addr_in_ht(struct TPMContext *tpm, struct MemHT **item, u32 addr);

/* handles adjacent memory nodes */
static int 
update_adjacent(struct TPMContext *tpm, union TPMNode *n, struct MemHT **l, struct MemHT **r, u32 addr, u32 bytesz);

static bool 
has_adjacent(struct TPMContext *tpm, struct MemHT **l, struct MemHT **r, u32 addr, u32 bytesz);

static bool 
has_left_adjacent(struct TPMContext *tpm, struct MemHT **item, u32 addr);

static bool  
has_right_adjacent(struct TPMContext *tpm,struct MemHT **item, u32 addr, u32 bytesz);

static bool 
link_adjacent(struct TPMNode2 *linker, struct TPMNode2 *linkee, bool is_left);

/* handles memory node's version */
union TPMNode *
create_first_version(u32 addr, u32 val, u32 ts);

bool 
add_next_version(struct TPMNode2 *front, struct TPMNode2 *next);

static int 
set_version(union TPMNode *tpmnode, u32 ver);

static u32 
get_version(struct TPMNode2 *node);

/* temp or register nodes */
static void 
clear_tempcontext(struct TPMNode1 *tempCntxt[] );

static int 
get_type(u32 flag);

static int 
get_regcntxt_idx(u32 reg);

/* print functions */
static void 
print_record(struct Record *rec);

static void 
print_src_addr(struct Record *rec);

static void 
print_src(struct Record *rec);

static void 
print_dst(struct Record *rec);

static void 
print_nonmem_node(struct TPMNode1 *n);

int 
isPropagationOverwriting(u32 flag, Record *rec)
/* return:
 * 	0: not overwriting
 *  1: overwriting
 *  <0: error
 */
{
    // Due to allow source and destination are same. always overwrite
    if(flag == TCG_XOR_i32 && rec->s_addr != rec->d_addr)
        return 0;
    else
        return 1;
  /* to be added */
  switch(flag) {
    case TCG_LD_i32:
    case TCG_ST_i32:
    case TCG_LD_POINTER_i32:
    case TCG_ST_POINTER_i32: 
    case TCG_NOT_i32:
    case TCG_NEG_i32:
    case TCG_EXT8S_i32:
    case TCG_EXT16S_i32:
    case TCG_EXT8U_i32:
    case TCG_EXT16U_i32:
    case TCG_BSWAP16_i32:
    case TCG_BSWAP32_i32:
    case TCG_SHL_i32:
    case TCG_SHR_i32:
    case TCG_SAR_i32:
    case TCG_ROTL_i32:
    case TCG_ROTR_i32:
    case TCG_MOV_i32:
    case TCG_DEPOSIT_i32:
        return 1;
    case TCG_ADD_i32:
    case TCG_SUB_i32:
    case TCG_MUL_i32:
    case TCG_DIV_i32:
    case TCG_DIVU_i32:
    case TCG_REM_i32:
    case TCG_REMU_i32:
    case TCG_MUL2_i32:
    case TCG_DIV2_i32:
    case TCG_DIVU2_i32:
    case TCG_AND_i32:
    case TCG_OR_i32:
    case TCG_XOR_i32:
    case TCG_SETCOND_i32:
        return 0;
    default:
        fprintf(stderr, "unkown Qemu IR enode:%-2u\n", flag);
        return 1; 
  }
}


union TPMNode *
createTPMNode(u32 type, u32 addr, u32 val, u32 TS)
{
    union TPMNode *tpmnode;
    
    if (type & TPM_Type_Memory)
    {
	tpmnode = malloc(sizeof(struct TPMNode2));
	memset(&tpmnode->tpmnode2, 0, sizeof(struct TPMNode2));
	tpmnode->tpmnode2.type = type;
	tpmnode->tpmnode2.addr = addr;
    tpmnode->tpmnode2.val  = val;   // add val
	tpmnode->tpmnode2.lastUpdateTS = TS;
    }
    else if ((type & TPM_Type_Register) || (type & TPM_Type_Temprary))
    {
	tpmnode = malloc(sizeof(struct TPMNode1));
	tpmnode->tpmnode1.type = type;
	tpmnode->tpmnode1.addr = addr;
    tpmnode->tpmnode1.val  = val;   // add val
	tpmnode->tpmnode1.lastUpdateTS = TS;
	tpmnode->tpmnode1.firstChild = NULL;
    }
    else return NULL;

    return tpmnode;
}

// u32 
// processOneXTaintRecord(struct TPMContext *tpm, u32 seqNo, u32 size, u32 srcflg, u32 srcaddr, u32 dstflag, u32 dstaddr)
int 
processOneXTaintRecord(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], struct TPMNode1 *tempCntxt[])
/* return:
 * 	>=0 : success and num of nodes creates
 *     <0: error
 *  1. handle source
 *  2. handle destination
 *  3. creates transition between source to destination
 */
{
    int type, s_type, sc = 0, dc = 0;
    union TPMNode *src = NULL, *dst = NULL;

#ifdef DEBUG
    printf("--------------------\nprocessing record:\n");
    print_record(rec);
#endif

    //  handle source node
    if(rec->is_load) { // src is mem addr    
        if( (sc = handle_src_mem(tpm, rec, &src) ) >= 0 ) {}
        else { return -1; }
        s_type = TPM_Type_Memory;
    }  
    else { // src is either reg or temp  
        type = get_type(rec->s_addr);
        if (type == TPM_Type_Register) { 
            if( (sc = handle_src_reg(tpm, rec, regCntxt, &src) ) >= 0 ) {}
            else { return -1; }
            s_type = type; 
        }
        else if (type == TPM_Type_Temprary) { 
            if((sc = handle_src_temp(tpm, rec, tempCntxt, &src)) >= 0) {}
            else { return -1; }
            s_type = type; 
        }
        else { return -1; }
    }

    //  hanlde destination node
    if(rec->is_store || rec->is_storeptr) { // dst is mem addr (include store ptr) 
        if((dc =  handle_dst_mem(tpm, rec, &dst) ) >= 0) {}
        else { return -1; } 
    } 
    else { // dst is either reg or temp
        type = get_type(rec->d_addr);
        if(type == TPM_Type_Register) { 
            if((dc = handle_dst_reg(tpm, rec, regCntxt, &dst) ) >= 0) {}
            else { return -1; } 
        }
        else if(type == TPM_Type_Temprary) { 
            if((dc = handle_dst_temp(tpm, rec, tempCntxt, &dst) ) >= 0) {}
            else { return -1; } 
        }
        else { return -1; }
    }

    //  creates transition node, binds the transition node pointer to src
    if( (create_trans_node(rec->ts, s_type, src, dst) ) != NULL) {}
    else { return -1; }

    return sc+dc;
}

int 
buildTPM(FILE *taintfp, struct TPMContext *tpm)
/* return:
 * 	>=0: number of TPM nodes created;
 *     <0: error
 */
{
    int i = 0, l = 0, r = 0;
    u32 n = 0;
    struct TPMNode1 *regCntxt[NUM_REG]      = {0};  // points to the latest register node
    struct TPMNode1 *tempCntxt[MAX_TEMPIDX] = {0};  // points to the latest temp node

    init_tpmcontext(tpm);

    char line[128] = {0};
    while(fgets(line, sizeof(line), taintfp) ) { // iterates each line (record) 
        char flag[3] = {0};
        if(get_flag(flag, line) ) {
            if(is_mark(flag) ) { // mark record, simply skip except for insn mark 
                // printf("flag: %s\n", flag);
                if(equal_mark(flag, INSN_MARK) ) { 
                    clear_tempcontext(tempCntxt); /* clear current context of temp, due to temp are 
                                                    only alive within instruction, if encounter an insn mark  
                                                    it crosses insn boundary */ 
                } 
            } 
            else { // data record, creates nodes 
                struct Record rec = {0};
                if(split(line, '\t', &rec) == 0) {
                    // print_record(&rec);

                    /* n increases by how many new nodes created */ 
                    if( (i = processOneXTaintRecord(tpm, &rec, regCntxt, tempCntxt) ) >= 0) { n += i; }  
                    else { return -1; }

                    r++; 
                } 
                else { return -1; }
            }
        } 
        else { fprintf(stderr, "error: get flag\n"); return -1; }

        l++;
        // printf("%s", line);
    }    

    printf("total lines:\t%d - total data records:\t%d - total nodes: %u\n", l, r, n);
    return n;
}

struct TPMNode2 *
mem2NodeSearch(struct TPMContext *tpm, u32 memaddr)
/* return:
 * 	NULL: no node founded with the memaddr
 *  non-NULL: points to the latest version of the TPM node that has the memaddr
 */
{
    struct MemHT *item        = NULL;
    struct TPMNode2 *tpmnode2 = NULL;
   
    item = find_mem_ht(&(tpm->mem2NodeHT), memaddr);
    if(item == NULL) { return NULL; }
    else {
        tpmnode2 = item->toMem;
        return tpmnode2;
    } 
}

union TPMNode *
seqNo2NodeSearch(struct TPMContext *tpm, u32 seqNo)
{
    union TPMNode *tpmnode = NULL;

    if(seqNo >= seqNo2NodeHashSize) {
        fprintf(stderr, "error: seqNo2NodeSearch: seqNo exceeds hash table size\n");
        return NULL;
    }
    else {
        tpmnode = tpm->seqNo2NodeHash[seqNo];
        return tpmnode;
    }
}

void delTPM(struct TPMContext *tpm)
{
    del_mem_ht(&(tpm->mem2NodeHT) ); // clear mem addr hash table
    free(tpm);                       // TODO: merge in delTPM()
}

void 
searchAvalanche(TPMContext *tpm)
{
    AvalancheSearchCtxt *avalsctxt;

    /* test dfs */
    MemHT *found = find_mem_ht(&(tpm->mem2NodeHT), 0xde911000);
    TPMNode2 *source = found->toMem;
    get_earliest_version(&source);

    init_AvalancheSearchCtxt(&avalsctxt, 8, source, NULL, 0, 0, 0, 0);
    searchAvalancheInOut(avalsctxt);
    free_AvalancheSearchCtxt(avalsctxt);    
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

static int 
handle_src_mem(struct TPMContext *tpm, struct Record *rec, union TPMNode **src)
// Returns
//  >=0: num of new nodes creates 
//  <0: error 
//  stores the created or found node pointer in src 
// 
//  1. detects if src's addr is in mem hash table (tpm->memHT)
//      1.1 not found: new addr
//          a) creates new node
//              1) init "version" to 0 (the earliest)
//          b) updates:
//              1) the mem hash table (tpm->memHT): hash(addr) -> it
//              2) seqNo hash table (tpm->seqNo2NodeHash): hash(seqNo) -> it
//      1.2 found
//          !!! detects if the value of the mem equals the val of the latest version 
//          of the same addr, due to if same, it's a valid taint propagation. (shoudl be)
//
//          1.2.1 the values are same
//              a) it's valid propagation, do nothing 
//          1.2.2 the values are different (!!! this case should not happen, due to its source)
//              a) creates a new node
//                  init version as previous version plus one
//              b) updates its previous version pointer (prev->nextversion points to it)
//              b) updates same as 1.1 b)
//  2. updates neighbours: 
//      2.1 detects if its left neighbour exists (could be 4, 2, 1 bytes)
//          a) yes, updates its leftNBR points to the earliest version of its left adjcent mem node 
//          b) no, do nothing
//      2.2 detects if its right neighbour exist, similar to 2.1, and updates it's rightNBR accordingly
{
    int n = 0;
    struct MemHT *src_hn = NULL, *left = NULL, *right = NULL;

#ifdef DEBUG
    printf("\thandle src mem: ");
    print_src(rec);
#endif

    if(is_addr_in_ht(tpm, &src_hn, rec->s_addr) ) { // in TPM
        /* temporarily disable the sanity check */
        // if(is_equal_value(rec->s_val, src_hn->toMem ) ) {
        //     *src = src_hn->toMem;
        // }
        // else {
        //     fprintf(stderr, "error: handle src memory: values are not matched\n"); 
        //     return -1; 
        // }

        *src = (union TPMNode*)src_hn->toMem;

#ifdef DEBUG
        printf("\thandle src mem: addr:0x%-8x found in hash table\n", rec->s_addr);
        print_mem_node(*src);
#endif       

    }
    else { // not found
        *src = create_first_version(rec->s_addr, rec->s_val, rec->ts);

#ifdef DEBUG
        printf("\taddr:0x%-8x not found in hash table, creates new mem node\n", rec->s_addr);
        print_mem_node(&( (*src)->tpmnode2) );
#endif       

        // updates hash table
        if(add_mem_ht( &(tpm->mem2NodeHT), rec->s_addr, &( (*src)->tpmnode2) ) >= 0 ){} 
        else { fprintf(stderr, "error: handle source mem: add_mem_ht\n"); return -1; }

#ifdef DEBUG
        count_mem_ht(&(tpm->mem2NodeHT) );
        print_mem_ht(&(tpm->mem2NodeHT) );
#endif       

        tpm->seqNo2NodeHash[rec->s_ts] = *src; // updates seqNo hash table
        n++;
    } 

    // updates adjacent mem node if any
    if(update_adjacent(tpm, *src, &left, &right, rec->s_addr, rec->bytesz) >= 0) {}
    else { return -1; }

    return n;
}

static int 
handle_src_reg(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], union TPMNode **src)
// Returns
//  >=0: num of new nodes creates 
//  <0: error 
//  stores the created or found node pointer in src 
//
//  1. detects if register is in the register context array (regCntxt)
//  1.1 not found: new register
//      a) creates new register node
//      b) updates:
//         1) reg context array: regCntxt[reg id] -> it
//         2) seqNo hash table (tpm->seqNo2NodeHash): hash(seqNo) -> it
//  1.2 found
//      !!! verifies if the value of the reg equals to the one stored in reg context [reg id] 
//      due to if same, it's a valid taint propagation. (shoudl be)
{
    int id = -1, n = 0;

#ifdef DEBUG
    printf("\thandle src reg: ");
    print_src(rec);
#endif       

    if((id = get_regcntxt_idx(rec->s_addr) ) >= 0) {
        if(regCntxt[id] == NULL) { // not found
            *src = createTPMNode(TPM_Type_Register, rec->s_addr, rec->s_val, rec->ts);
            regCntxt[id] = &( (*src)->tpmnode1); // updates reg context
            tpm->seqNo2NodeHash[rec->s_ts] = *src; // updates seqNo hash table
            n++;

#ifdef DEBUG
            printf("reg: %x not found in regCntxt, creates new reg node\n", rec->s_addr);
            print_nonmem_node(&( (*src)->tpmnode1) );
            printf("reg: %x - id: %d - addr of the node: %p\n", rec->s_addr, id, regCntxt[id]);
#endif                  
        } 
        else { // found
            // disable the sanity check first
            // if(is_equal_value(rec->s_val, regCntxt[id] ) ) {
            //     *src = regCntxt[id];
            // }
            // else {
            //     fprintf(stderr, "error: handle src reg: values are not matched\n"); 
            //     return -1; 
            // }

            *src = (union TPMNode*)regCntxt[id];
#ifdef DEBUG
            printf("\thandle src reg: found reg in regCntxt\n");
            print_nonmem_node(regCntxt[id]);
#endif      
        }
    }
    else { return -1; } // error

    return n;
}

static int  
handle_src_temp(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *tempCntxt[], union TPMNode **src)
// Returns
//  >=0: num of new nodes creates 
//  <0: error 
//  stores the created or found node pointer in src 
//
//  1. detects if temp is in the temp context array (tempCntxt)
//      1.1 not found: new temp
//          a) creates new temp node
//          b) updates:
//              1) temp context array: tempCntxt[temp id] -> it
//              2) seqNo hash table (tpm->seqNo2NodeHash): hash(seqNo) -> it
//      1.2 found
//          !!! verifies if the value of the temp equals to the one stored in temp context [temp id] 
//          due to if same, it's a valid taint propagation. (shoudl be)
{   int n = 0;

#ifdef DEBUG
    printf("\thandle src temp:");
    print_src(rec);
#endif      

    if(rec->s_addr >= 0xfff0 || rec->s_addr >= MAX_TEMPIDX) {
        fprintf(stderr, "error: temp idx larger than register idx or max temp idx\n");
        return -1;
    }

    if(tempCntxt[rec->s_addr] == NULL) { // not found, creates new node
        *src = createTPMNode(TPM_Type_Temprary, rec->s_addr, rec->s_val, rec->ts);
        tempCntxt[rec->s_addr] = &( (*src)->tpmnode1);    // updates temp context
        tpm->seqNo2NodeHash[rec->s_ts] = *src; // updates seqNo hash table
        n++;

#ifdef DEBUG
        printf("\ttemp: %u not found in tempCntxt, creates new temp node\n", rec->s_addr);
        print_nonmem_node(&( (*src)->tpmnode1) );
        printf("\ttemp: %u - addr of the node: %p\n", rec->s_addr, tempCntxt[rec->s_addr]);
#endif      
    } 
    else {  // found
        // disable the sanity check
        // if(is_equal_value(rec->s_val, tempCntxt[rec->s_addr] ) ) {
        //     *src = tempCntxt[rec->s_addr];
        // }
        // else {
        //     fprintf(stderr, "error: handle src temp: values are not matched\n"); 
        //     return -1; 
        // }

        *src = (union TPMNode*)tempCntxt[rec->s_addr];
#ifdef DEBUG
        printf("\thandle src temp: found temp in tempCntxt\n");
        print_nonmem_node(tempCntxt[rec->s_addr]);       
#endif      
    } 
    return n;
}

static int 
handle_dst_mem(struct TPMContext *tpm, struct Record *rec, union TPMNode **dst)
// Returns
//  >=0: num of new nodes creates 
//  <0: error 
//  stores the created or found node pointer in dst 
//
//  1. detects if it's a overwrite or "addition" operation
//  1.1 overwrite operation (mov)
//      1) detects if its addr is in mem hash table
//         a) yes
//            - creates a new node
//            - set the version accordingly
//            - attach it to the version list 
//         b) no: a new addr
//            - creates a new node
//            - init version to 0
//      2) updates the mem hash table: hash(addr) -> it
//  1.2 "addition" operation (add, xor...)
//      1) detects if its addr is in the mem hash table
//         a) yes
//            !!! verifies if the value equals the val of the latest version
//         b) no
//            - creates a new node
//            - init version number
//            - updates the mem hash table: hash(addr) -> it
//            - updates seqNo hash table
//  2. updates neighbours: 
//  2.1 detects if its left neighbour exists (could be 4, 2, 1 bytes)
//      a) yes, updates its leftNBR points to the earliest version of its left adjcent mem node 
//      b) no, do nothing
//  2.2 detects if its right neighbour exist, similar to 2.1, and updates it's rightNBR accordingly
{
    int n = 0;
    u32 version = 0;
    struct MemHT *dst_hn = NULL, *left = NULL, *right = NULL;

#ifdef DEBUG
    printf("\thandle dst mem:");
    print_dst(rec);
#endif      

    if(isPropagationOverwriting(rec->flag, rec) ) { // overwrite
        if( is_addr_in_ht(tpm, &dst_hn, rec->d_addr) ) { // in TPM 
            *dst = createTPMNode(TPM_Type_Memory, rec->d_addr, rec->d_val, rec->ts);
            version = get_version(dst_hn->toMem);
            set_version(*dst, version+1); // set version accordingly
            add_next_version(dst_hn->toMem, &( (*dst)->tpmnode2) );             

#ifdef DEBUG
            print_mem_node(dst_hn->toMem);
            print_mem_node(&( (*dst)->tpmnode2) );
            printf("\tversion:\n");
            print_version(dst_hn->toMem);
#endif      
        }
        else { // not found
            *dst = create_first_version(rec->d_addr, rec->d_val, rec->ts);
        }

        // updates mem hash table
        if(add_mem_ht( &(tpm->mem2NodeHT), rec->d_addr, &( (*dst)->tpmnode2) ) >= 0) {}
        else { fprintf(stderr, "error: handle destination mem: add_mem_ht\n"); return -1; }

        tpm->seqNo2NodeHash[rec->d_ts] = *dst;   // updates seqNo hash table
        n++;
    } 
    else {  // non overwring
#ifdef DEBUG
        printf("\thandle destination mem: non overwring\n");
#endif      
        if(is_addr_in_ht(tpm, &dst_hn, rec->d_addr) ) {
            printf("handle dst mem - non overwriting - TODO: verifies if values are same\n");
            return -1;  // TODO
        }
        else { // not found
            *dst = create_first_version(rec->d_addr, rec->d_val, rec->ts);
            tpm->seqNo2NodeHash[rec->d_ts] = *dst;   // updates seqNo hash table
            n++;
        }

        // both cases, updates mem hash table
        if(add_mem_ht( &(tpm->mem2NodeHT), rec->d_addr, &( (*dst)->tpmnode2) ) >= 0) {}
        else { return -1; }
    }

    // updates adjacent mem node if any
    if(update_adjacent(tpm, *dst, &left, &right, rec->d_addr, rec->bytesz) >= 0) {}
    else { return -1; }

    return n;
}

static int 
handle_dst_reg(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], union TPMNode **dst)
// Returns
//  >=0 success, and number of new nodes creates
//  <-0 error
//  the created node stores in dst
//  1 determines if it's in TPM: regCntxt has its register id
//  1.1 No
//      a) creates a new node
//      b) updates the register context: regCntxt[reg_id] -> created node
//      c) updates the seqNo hash table
//  1.2 Yes: determines if its overwrite or "addition" operation
//  1.2.1 overwrite (mov)
//      a) creates a new node
//      b) updates the register context: regCntxt[reg_id] -> created node
//      c) updates the seqNo hash table
//  1.2.2 "addtion" (add, xor, etc)
//      a) verifies that the value of register and the one found in the regCntxt should be same
{
    int id = -1, n = 0;

#ifdef DEBUG
    printf("\thandle dst reg:");
    print_dst(rec);
#endif      

    if((id = get_regcntxt_idx(rec->d_addr) ) >= 0) {
        if(regCntxt[id] == NULL){ // not in tpm
            *dst = createTPMNode(TPM_Type_Register, rec->d_addr, rec->d_val, rec->ts);
            regCntxt[id] = &( (*dst)->tpmnode1);
            tpm->seqNo2NodeHash[rec->d_ts] = *dst;   // updates seqNo hash table
            n++;
        }
        else { // in tpm
            if(isPropagationOverwriting(rec->flag, rec) ) { // overwrite
                *dst = createTPMNode(TPM_Type_Register, rec->d_addr, rec->d_val, rec->ts);
                regCntxt[id] = &( (*dst)->tpmnode1);
                tpm->seqNo2NodeHash[rec->d_ts] = *dst;   // updates seqNo hash table
                n++;
            } 
            else { // non overwrite
#ifdef DEBUG
                printf("\thandle dst reg: non overwrite hit\n");
#endif         
                /* disable the sanity check */ 
                // if(is_equal_value(rec->d_val, regCntxt[id]) ) {
                //     *dst = regCntxt[id];
                // }
                // else {
                //     fprintf(stderr, "error: values are not equal\n");
                //     print_nonmem_node(regCntxt[id]);
                //     return -1;
                // }           
                *dst = (union TPMNode*)regCntxt[id]; 
                // TODO: update the seqNo hash table                                       
            }
        }
    }
    else { return -1; }

    return n;
}

static int 
handle_dst_temp(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *tempCntxt[], union TPMNode **dst)
// Returns
//  >=0 success, and number of new nodes creates
//  <-0 error
//  the created node stores in dst
//  1 determines if it's in TPM: tempCntxt has its temp id
//  1.1 No
//      a) creates a new node
//      b) updates the temp context: tempCntxt[temp_id] -> created node
//      c) updates the seqNo hash table
//  1.2 Yes: determines if its overwrite or "addition" operation
//  1.2.1 overwrite (mov)
//      a) creates a new node
//      b) updates the temp context: tempCntxt[temp_id] -> created node
//      c) updates the seqNo hash table
//  1.2.2 "addtion" (add, xor, etc)
//      a) verifies that the value of temp and the one found in the tempCntxt should be same
{
    int n = 0;

#ifdef DEBUG
    printf("\thandle dst temp: ");
    print_dst(rec);
#endif                     

    if(rec->d_addr >= 0xfff0 || rec->d_addr >= MAX_TEMPIDX) {
        fprintf(stderr, "error: temp idx larger than register idx or max temp idx\n");
        return -1;       
    }

    if(tempCntxt[rec->d_addr] == NULL) { // Not in TPM
        *dst = createTPMNode(TPM_Type_Temprary, rec->d_addr, rec->d_val, rec->ts);
        tempCntxt[rec->d_addr] = &( (*dst)->tpmnode1);
        tpm->seqNo2NodeHash[rec->d_ts] = *dst;   // updates seqNo hash table
        n++;
    }
    else { // in TPM
        if(isPropagationOverwriting(rec->flag, rec) ) { // overwrite
            *dst = createTPMNode(TPM_Type_Temprary, rec->d_addr, rec->d_val, rec->ts);
            tempCntxt[rec->d_addr] = &( (*dst)->tpmnode1);
            tpm->seqNo2NodeHash[rec->d_ts] = *dst;   // updates seqNo hash table
            n++;
        }
        else { // non overwrite
#ifdef DEBUG
                printf("\thandle dst temp: non overwrite hit\n");
#endif                             
                /* disable the sanity check */ 
                // if(is_equal_value(rec->d_val, tempCntxt[rec->d_addr]) ) {
                //     *dst = tempCntxt[rec->d_addr];
                // }
                // else {
                //     fprintf(stderr, "error: values are not equal\n");
                //     print_nonmem_node(tempCntxt[rec->d_addr]);
                //     return -1;
                // }
                *dst = (union TPMNode*)tempCntxt[rec->d_addr];
                // TODO: update the seqNo hash table                                       
        }
    }
    return n;
}

static struct Transition *
create_trans_node(u32 ts, u32 s_type, union TPMNode *src, union TPMNode *dst)
// Returns
//  pointer of the created transition node 
//  NULL : error 
{
    if(src == NULL || dst == NULL) {
        fprintf(stderr, "error: create trans node: src: %p - dst: %p\n", src, dst);
        return NULL;
    }

    struct Transition *t, *tmp;

    t = (struct Transition*)malloc(sizeof(struct Transition) );
    t->seqNo = ts; // timestamp
    t->child = dst;
    t->next = NULL;

    if(s_type & TPM_Type_Memory) { 
        if(src->tpmnode2.firstChild == NULL) { // no trans node
            src->tpmnode2.firstChild = t;
            return t;
        } 
        else { tmp = src->tpmnode2.firstChild; }
    }
    else if(s_type & TPM_Type_Temprary || s_type & TPM_Type_Register) {
        if(src->tpmnode1.firstChild == NULL) {
            src->tpmnode1.firstChild = t;
            return t;
        }
        else { tmp = src->tpmnode1.firstChild; } 
    }
    else {
        fprintf(stderr, "error: create trans node: unkown src type\n"); 
        return NULL; 
    }

    while(tmp->next != NULL) { tmp = tmp->next; }   // reaches last child 
    tmp->next = t;  // links t to list end

    return t;
}

static bool 
is_equal_value(u32 val, union TPMNode *store)
// Returns 
//  t: if values equal
//  f: otherwise
{
    if( store == NULL)
        return false;

    if(val == store->tpmnode1.val) { return true; }
    else { return false; }
}

static bool  
is_addr_in_ht(struct TPMContext *tpm, struct MemHT **item, u32 addr)
// Returns:
//  t: if has mem node
//  f: if not found 
//      found item stored in *item
{   
    *item = NULL;
    *item = find_mem_ht( &(tpm->mem2NodeHT), addr);
    if( (*item) != NULL) { return 1; }
    else { return 0; }
}

static int 
update_adjacent(struct TPMContext *tpm, union TPMNode *n, struct MemHT **l, struct MemHT **r, u32 addr, u32 bytesz)
// Returns:
//  >0: if has any update
//  0: no update
//  <0: error
{
    if(tpm == NULL || n == NULL) {
        fprintf(stderr, "error: update adjacent - tpm: %p - n: %p\n", tpm, n);
        return -1;
    }

    bool is_left = false;
    struct TPMNode2 *self = NULL;

    if(has_adjacent(tpm, l, r, addr, bytesz) ) {
        struct TPMNode2 *earliest = NULL;
        if(*l != NULL){
            earliest = (*l)->toMem;
            if(get_earliest_version(&earliest) == 0) {
                is_left = true;
                link_adjacent(&(n->tpmnode2), earliest, is_left);   // update the self leftNBR

                self = &(n->tpmnode2);
                if(get_earliest_version(&self) == 0) {
                    is_left = false;
                    link_adjacent(earliest, self, is_left); // updates the target rightNBR 
                }
                else { return -1; }
            }
            else { return -1; }


        }

        if(*r != NULL){
            earliest = (*r)->toMem;
            if(get_earliest_version(&earliest) == 0) {
                is_left = false;
                link_adjacent(&(n->tpmnode2), earliest, is_left); // updates the self rightNBR

                self = &(n->tpmnode2);
                if(get_earliest_version(&self) == 0) {
                    is_left = true;
                    link_adjacent(earliest, self, is_left); // updates the target leftNBR
                }
            }
            else { return -1; }
        }
        return 1;
    }
    else { return 0; }
}

static bool 
has_adjacent(struct TPMContext *tpm, struct MemHT **l, struct MemHT **r, u32 addr, u32 bytesz)
// Returns:
//  1: if has either left or right adjacent mem node
//  0: otherwise
{
    bool rl = false, rr = false;

    rl = has_left_adjacent(tpm, l, addr);
    rr = has_right_adjacent(tpm, r, addr, bytesz);

    if( rl || rr ) {
        return true;
    } 
    else { return false; }
}

static bool 
has_left_adjacent(struct TPMContext *tpm, struct MemHT **item, u32 addr)
// Returns:
//  t: if has left adjacent mem node
//  f: otherwise
{
    *item = NULL;
    u32 l_adjcnt;

    l_adjcnt = addr - DWORD;    // try 4 bytes first
    *item = find_mem_ht( &(tpm->mem2NodeHT), l_adjcnt);
    if(*item != NULL) {
#ifdef DEBUG
        printf("has left adjacent: addr: 0x%x\n", (*item)->toMem->addr); 
#endif                                
        return true; 
    }else { // doesn't find 4 bytes left adjacent
        l_adjcnt = addr - WORD; // try 2 bytes 
        *item = find_mem_ht( &(tpm->mem2NodeHT), l_adjcnt);
        if(*item != NULL) {
#ifdef DEBUG
            printf("has left adjacent: addr: 0x%x\n", (*item)->toMem->addr);  
#endif                                
            return true; 
        }
        else {
            l_adjcnt = addr - BYTE; // try 1 byte
            *item = find_mem_ht( &(tpm->mem2NodeHT), l_adjcnt);
            if(*item != NULL) {
#ifdef DEBUG
                printf("has left adjacent: addr: 0x%x\n", (*item)->toMem->addr);  
#endif                                               
                return true; 
            }
            else { return false; } 
        }
    }
}

static bool 
has_right_adjacent(struct TPMContext *tpm, struct MemHT **item,  u32 addr, u32 bytesz)
// Returns:
//  t: if has right adjacent mem node
//  f: otherwise
{
    u32 r_adjcnt = addr + bytesz;
    *item = NULL;

    *item = find_mem_ht( &(tpm->mem2NodeHT), r_adjcnt);
    if(*item != NULL) {
#ifdef DEBUG
        printf("has right adjacent: addr: 0x%x\n", (*item)->toMem->addr);   
#endif                                                   
        return true; 
    }
    else { return false; }
}

static bool 
link_adjacent(struct TPMNode2 *linker, struct TPMNode2 *linkee, bool is_left)
// Returns:
//  true: success
//  false: error
//  links the linkee to the linker's leftNBR or rightNBR based on is_left
{
    if(linker == NULL || linkee == NULL) {
        fprintf(stderr, "error: link adjacent: linker:%p linkee:%p\n", linker, linkee);
        return false;
    }

    if(is_left) { linker->leftNBR = linkee; }
    else { linker->rightNBR = linkee; }

    return true;
}

static int 
set_version(union TPMNode *tpmnode, u32 ver)
// Returns:
//  0: success
//  <0: error
{
    if(tpmnode == NULL)
        return -1;

    tpmnode->tpmnode2.version = ver;
    return 0; 
}

union TPMNode *
create_first_version(u32 addr, u32 val, u32 ts)
// creates first version (0) memory node 
{
    union TPMNode *n;
    n = createTPMNode(TPM_Type_Memory, addr, val, ts);
    set_version(n, 0);   
    n->tpmnode2.nextVersion = &(n->tpmnode2); // init points to itself
    return n; 
}

bool 
add_next_version(struct TPMNode2 *front, struct TPMNode2 *next)
// Returns
//  true: success
//  false: error
{
    if(front == NULL || next == NULL)
        return false;

    // front node nextVersion should points to head mem node (0 ver)
    if(front->nextVersion->version != 0)
        return false; 

    next->nextVersion  = front->nextVersion; // now next points to head
    front->nextVersion = next;               // front points to next
    return true;
}

static u32 
get_version(struct TPMNode2 *node)
// Returns
//  the version of the mem node
{
    return node->version;
}

int 
get_earliest_version(struct TPMNode2 **earliest)
// Returns:
//  0: success
//  <0: error
//  stores the earliest version in earliest
{
    if(earliest == NULL) {
        fprintf(stderr, "error: get earliest version\n");
        return -1;
    }

    // circulates the linked list until found 0 version
    while( (*earliest)->version != 0) { 
        *earliest = (*earliest)->nextVersion; 
    }
    return 0;
}


static void 
clear_tempcontext(struct TPMNode1 *tempCntxt[] )
{
   for(int i = 0; i < MAX_TEMPIDX; i++) {
    tempCntxt[i] = NULL;
   } 
}

static int 
get_type(u32 addr)
// Returns:
//  reg or temp based on the addr 
{
    if(addr < G_TEMP_UNKNOWN) { return TPM_Type_Temprary; }
    else if(addr <=  G_TEMP_EDI) { return TPM_Type_Register; } 
    else { fprintf(stderr, "error: unkown addr type: addr: %u\n", addr); return -1; }
}

static int 
get_regcntxt_idx(u32 reg)
// Returns:
//  idx of the register in regCntxt
//  <0: error
{
    if(reg >= 0xfff0 && reg <= 0xfffd) { return (reg & REG_IDX_MASK); }
    else {
        fprintf(stderr, "error: get regcntxt idx: wrong reg\n");
        return -1;
    }
}

static void 
print_record(struct Record* rec)
{
    printf("flag:%-2x s_addr:%-8x s_val:%-8x" 
                    " d_addr:%-8x d_val:%-8x"
                    " size:%-2d seqNo:%-8u s_seqNo:%-8u d_seqNo:%-8u" 
                    " load:%-1u store:%-1u loadptr:%-1u storeptr:%-1u\n", 
            rec->flag, rec->s_addr, rec->s_val, 
                       rec->d_addr, rec->d_val, 
                       rec->bytesz, rec->ts, rec->s_ts, rec->d_ts, 
                       rec->is_load, rec->is_store, rec->is_loadptr, rec->is_storeptr);
}

static void 
print_src_addr(struct Record *rec)
{
    printf("s_addr:%-8x seqNo:%-16u\n", rec->s_addr, rec->ts);
}

static void 
print_src(struct Record *rec)
{
    printf("flag:%-2x s_addr:%-8x s_val:%-8x\n", rec->flag, rec->s_addr, rec->s_val);
}

static void 
print_dst(struct Record *rec)
{
    printf("flag:%-2x d_addr:%-8x d_val:%-8x\n", rec->flag, rec->d_addr, rec->d_val);
}

void 
print_mem_node(struct TPMNode2 *n)
{
    printf("mem: type:%-1u addr:0x%-8x val:%-8x lastUpdateTS:%-16u"
            " firstChild:%-8p leftNBR:%-8p rightNBR:%-8p nextVersion:%-8p"
            " version:%-9u hitcnt:%-8u\n", 
            n->type, n->addr, n->val, n->lastUpdateTS, 
            n->firstChild, n->leftNBR, n->rightNBR, n->nextVersion,
            n->version, n->hitcnt);
}

static void 
print_nonmem_node(struct TPMNode1 *n)
{
     printf("non-mem: type:%-1u addr:0x%-8x val:%-8x lastUpdateTS:%-16u\n", 
            n->type, n->addr, n->val, n->lastUpdateTS);   
}

void 
print_version(struct TPMNode2 *head)
{
    if(head == NULL)
        return;

    do{
        // printf("version: %u\n", head->version);
        print_mem_node(head);
        head = head->nextVersion;
    } while(head == NULL || head->version != 0);
}

void 
print_transition(union TPMNode *head)
{
    struct Transition *t = head->tpmnode1.firstChild; 

    while(t != NULL) {
       if(t->child->tpmnode1.type == TPM_Type_Memory) {
        print_mem_node(&(t->child->tpmnode2) );
       } 
       else if(t->child->tpmnode1.type == TPM_Type_Register 
               || t->child->tpmnode1.type == TPM_Type_Temprary){
        print_nonmem_node(&(t->child->tpmnode1) );
       }
       else { fprintf(stderr, "error: print trans: unkown type\n"); break; }

       t = t->next;
    }
}

void 
print_single_transition(Transition *transition)
{
    if(transition != NULL) {
        printf("Transition:%p\n seqNo:%u\n", transition, transition->seqNo);
        printf("Child:\n");
        print_tpmnode(transition->child);
    }
}

void 
print_tpmnode(TPMNode *tpmnode)
{
    if(tpmnode != NULL) {
        if(tpmnode->tpmnode1.type == TPM_Type_Memory) {
            print_mem_node(&(tpmnode->tpmnode2) );
        }
        else {
            print_nonmem_node(&(tpmnode->tpmnode1) );
        }
    }
}

int
add_mem_ht(struct MemHT **mem2NodeHT, u32 addr, struct TPMNode2 *toMem)
{
    struct MemHT *s;

    if(mem2NodeHT == NULL || toMem == NULL)
        return -1;

    s = find_mem_ht(mem2NodeHT, addr);
    if(s == NULL) { // if not found, creates new 
        s = (struct MemHT*)malloc(sizeof(struct MemHT) );
        s->addr = addr;
        HASH_ADD(hh_mem, *mem2NodeHT, addr, 4, s);
        s->toMem = toMem;
    } else {    // if found, updates 
        s->toMem = toMem;
    }

    return 0;
}

/* mem addr hash table */
static struct MemHT *
find_mem_ht(struct MemHT **mem2NodeHT, u32 addr)
{
    struct MemHT *s;
    HASH_FIND(hh_mem, *mem2NodeHT, &addr, 4, s);
    return s;   
}

static void
del_mem_ht(struct MemHT **mem2NodeHT)
{
    struct MemHT *curr, *tmp;
    HASH_ITER(hh_mem, *mem2NodeHT, curr, tmp) {
        HASH_DELETE(hh_mem, *mem2NodeHT, curr);
        free(curr);
    }
}

static void 
count_mem_ht(struct MemHT **mem2NodeHT)
{
    u32 num;
    num = HASH_CNT(hh_mem, *mem2NodeHT);
    printf("total: %u mem addr in hash table\n", num);
}

static void 
print_mem_ht(struct MemHT **mem2NodeHT)
{
    struct MemHT *s;
    for(s = *mem2NodeHT; s != NULL; s = s->hh_mem.next) {
        printf("mem - addr: %x - to mem node: %p\n", s->addr, s->toMem);
    }
}
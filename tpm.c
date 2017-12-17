/*
 * tpm.c
 * 
 * created on 12/8/2017
 * 
 * */

#include "tpm.h"
#include "util.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* TPMContext related */
static void 
init_tpmcontext(struct TPMContext *tpm);

/* handles different cases of source and destination when processing a record */
static int 
handle_src_mem(struct TPMContext *tpm, struct Record *rec, union TPMNode* src);

static int 
handle_src_reg(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], union TPMNode* src);

static int  
handle_src_temp(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *tempCntxt[], union TPMNode* src);

static int 
handle_dst_mem(struct TPMContext *tpm, struct Record *rec, union TPMNode* dst);

static int 
handle_dst_reg(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], union TPMNode* dst);

static int 
handle_dst_temp(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *tempCntxt[], union TPMNode* dst);

/* transition node */
static struct Transition *
create_trans_node(struct Record *rec, u32 s_type, union TPMNode* src, union TPMNode* dst);

/* mem addr hash table */
static bool  
is_addr_in_ht(struct TPMContext *tpm, struct MemHT *item, u32 addr);

/* handles adjacent memory nodes */
static int 
update_adjacent(struct TPMContext *tpm, union TPMNode *n, struct MemHT *l, struct MemHT *r, u32 addr, u32 bytesz);

static bool 
has_adjacent(struct TPMContext *tpm, struct MemHT *l, struct MemHT *r, u32 addr, u32 bytesz);

static bool 
has_left_adjacent(struct TPMContext *tpm, struct MemHT *item, u32 addr);

static bool  
has_right_adjacent(struct TPMContext *tpm,struct MemHT *item, u32 addr, u32 bytesz);

/* handles memory node's version */
union TPMNode *
create_first_version(u32 addr, u32 val, u32 ts);

bool 
add_next_version(struct TPMNode2 *front, struct TPMNode2 *next);

static int 
set_version(union TPMNode *tpmnode, u32 ver);

static u32 
get_version(struct TPMNode2 *node);

static int 
get_earliest_version(struct TPMNode2 **earliest);

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
print_mem_node(struct TPMNode2 *n);

static void 
print_nonmem_node(struct TPMNode1 *n);

static void 
print_version(struct TPMNode2 *head);

u32 
isPropagationOverwriting(u32 flag)
/* return:
 * 	0: not overwriting
 *  non-0: overwriting
 */
{
  /* to be added */
  
  return 1;
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
u32
processOneXTaintRecord(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], struct TPMNode1 *tempCntxt[])
/* return:
 * 	>=0 : success and num of nodes creates
 *     <0: error
 *  1) handle source
 *  2) handle destination
 *  3) creates transition between source to destination
 */
{
    int type, sc = 0, dc = 0;
    union TPMNode *src = NULL, *dst = NULL;

    //  handle source node
    if(rec->is_load) { // src is mem addr    
        if( (sc = handle_src_mem(tpm, rec, src) ) >= 0 ) {}
        else { return -1; }
    }  
    else { // src is either reg or temp  
        type = get_type(rec->s_addr);
        if (type == TPM_Type_Register) { 
            if( (sc = handle_src_reg(tpm, rec, regCntxt, src) ) >= 0 ) {}
            else { return -1; } 
        }
        else if (type == TPM_Type_Temprary) { 
            if((sc = handle_src_temp(tpm, rec, tempCntxt, src)) >= 0) {}
            else { return -1; } 
        }
        else { return -1; }
    }

    //  hanlde destination node
    if(rec->is_store) { // dst is mem addr 
        if((dc =  handle_dst_mem(tpm, rec, dst) ) >= 0) {}
        else { return -1; } 
    } 
    else { // dst is either reg or temp
        type = get_type(rec->d_addr);
        if(type == TPM_Type_Register) { 
            if((dc = handle_dst_reg(tpm, rec, regCntxt, dst) ) >= 0) {}
            else { return -1; } 
        }
        else if(type == TPM_Type_Temprary) { 
            if((dc = handle_dst_temp(tpm, rec, tempCntxt, dst) ) >= 0) {}
            else { return -1; } 
        }
        else { return -1; }
    }

    // TODO:
    //  creates transition node, need to deal how bind the transition node pointer 

    return sc+dc;
}

u32 
buildTPM(FILE *taintfp, struct TPMContext *tpm)
/* return:
 * 	>=0: number of TPM nodes created;
 *     <0: error
 */
{
    int n = 0, i = 0, l = 0, r = 0;
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
                    // n increases by how many new nodes created  
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

void 
delTPM(struct TPMContext *tpm)
{

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
handle_src_mem(struct TPMContext *tpm, struct Record *rec, union TPMNode* src)
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

    print_record(rec);

    if(is_addr_in_ht(tpm, src_hn, rec->s_addr) ) {
        printf("handle src mem: addr: 0x%x found in hash table\n", rec->s_addr);
        return -1; // TODO: hasn't handle the case yet
    }
    else { // not found
        printf("addr: 0x%x not found in hash table, creates new mem node\n", rec->s_addr);
        src = create_first_version(rec->s_addr, rec->s_val, rec->ts);
        print_mem_node(&(src->tpmnode2) );

        // updates hash table
        if(add_mem_ht( &(tpm->mem2NodeHT), rec->s_addr, &(src->tpmnode2) ) >= 0 ){} 
        else { fprintf(stderr, "error: handle source mem: add_mem_ht\n"); return -1; }

        count_mem_ht(&(tpm->mem2NodeHT) );
        print_mem_ht(&(tpm->mem2NodeHT) );

        tpm->seqNo2NodeHash[rec->ts] = src; // updates seqNo hash table
        n++;
    } 

    // updates adjacent mem node if any
    if(update_adjacent(tpm, src, left, right, rec->s_addr, rec->bytesz) >= 0) {}
    else { return -1; }

    return n;
}

static int 
handle_src_reg(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], union TPMNode* src)
// Returns
//  >=0: num of new nodes creates 
//  <0: error 
//  stores the created or found node pointer in src 
//
//  1. detects if register is in the register context array (regCntxt)
//      1.1 not found: new register
//          a) creates new register node
//          b) updates:
//              1) reg context array: regCntxt[reg id] -> it
//              2) seqNo hash table (tpm->seqNo2NodeHash): hash(seqNo) -> it
//      1.2 found
//          !!! verifies if the value of the reg equals to the one stored in reg context [reg id] 
//          due to if same, it's a valid taint propagation. (shoudl be)
{
    int id = -1, n = 0;

    if((id = get_regcntxt_idx(rec->s_addr) ) >= 0) {
        if(regCntxt[id] == NULL) { // not found
            printf("reg: %x not found in regCntxt, creates new reg node\n", rec->s_addr);
            src = createTPMNode(TPM_Type_Register, rec->s_addr, rec->s_val, rec->ts);
            print_nonmem_node(&(src->tpmnode1) );

            regCntxt[id] = &(src->tpmnode1);    // updates reg context
            tpm->seqNo2NodeHash[rec->ts] = src; // updates seqNo hash table
            printf("reg: %x - id: %d - addr of the node: %p\n", rec->s_addr, id, regCntxt[id]);
            n++;
        } 
        else { // found
            printf("handle src reg: found reg in regCntxt\n");
            return -1;
        }
    }
    else { return -1; } // error

    return n;
}

static int  
handle_src_temp(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *tempCntxt[], union TPMNode* src)
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

    if(rec->s_addr >= 0xfff0 || rec->s_addr >= MAX_TEMPIDX) {
        fprintf(stderr, "error: temp idx larger than register idx or max temp idx\n");
        return -1;
    }

    if(tempCntxt[rec->s_addr] == NULL) { // not found, creates new node
        printf("temp: %u not found in tempCntxt, creates new temp node\n", rec->s_addr);
        src = createTPMNode(TPM_Type_Temprary, rec->s_addr, rec->s_val, rec->ts);
        print_nonmem_node(&(src->tpmnode1) );

        tempCntxt[rec->s_addr] = &(src->tpmnode1);    // updates temp context
        tpm->seqNo2NodeHash[rec->ts] = src; // updates seqNo hash table
        printf("temp: %u - addr of the node: %p\n", rec->s_addr, tempCntxt[rec->s_addr]);
        n++;
    } 
    else {  // found
        printf("handle src temp: found temp in tempCntxt\n");
        return -1;
    } 
    return n;
}

static int 
handle_dst_mem(struct TPMContext *tpm, struct Record *rec, union TPMNode* dst)
// Returns
//  >=0: num of new nodes creates 
//  <0: error 
//  stores the created or found node pointer in dst 
//
//  1. detects if it's a overwrite or "addition" operation
//      1.1 overwrite operation (mov)
//          1) detects if its addr is in mem hash table
//              a) yes
//                  - creates a new node
//                  - set the version accordingly
//                  - attach it to the version list 
//              b) no: a new addr
//                  - creates a new node
//                  - init version to 0
//          3) updates the mem hash table: hash(addr) -> it
//      1.2 "addition" operation (add, xor...)
//          1) detects if its addr is in the mem hash table
//              a) yes
//                  !!! verifies if the value equals the val of the latest version
//              b) no
//                  - creates a new node
//                  - init version number
//                  - updates the mem hash table: hash(addr) -> it
//  2. updates neighbours: 
//      2.1 detects if its left neighbour exists (could be 4, 2, 1 bytes)
//          a) yes, updates its leftNBR points to the earliest version of its left adjcent mem node 
//          b) no, do nothing
//      2.2 detects if its right neighbour exist, similar to 2.1, and updates it's rightNBR accordingly
{
    int n = 0;
    u32 version = 0;
    struct MemHT *dst_hn = NULL, *left = NULL, *right = NULL;

    if(isPropagationOverwriting(rec->flag) ) { // overwrite
        if( is_addr_in_ht(tpm, dst_hn, rec->d_addr) ) { 
            dst = createTPMNode(TPM_Type_Memory, rec->d_addr, rec->d_val, rec->ts);
            version = get_version(dst_hn->toMem);
            set_version(dst, version+1); // set version accordingly
            add_next_version(dst_hn->toMem, &(dst->tpmnode2) );             

            print_mem_node(&(dst->tpmnode2) );
        }
        else { // not found
            dst = create_first_version(rec->d_addr, rec->d_val, rec->ts);
        }

        // updates mem hash table
        if(add_mem_ht( &(tpm->mem2NodeHT), rec->d_addr, &(dst->tpmnode2) ) >= 0) {}
        else { fprintf(stderr, "error: handle destination mem: add_mem_ht\n"); return -1; }
        n++;
    } 
    else {  // non overwring
        printf("handle destination mem: non overwring\n");
        if(is_addr_in_ht(tpm, dst_hn, rec->d_addr) ) {
            printf("handle dst mem - non overwriting - TODO: verifies if values are same\n");
            return -1;  // TODO
        }
        else { // not found
            dst = create_first_version(rec->d_addr, rec->d_val, rec->ts);
            n++;
        }

        // both cases, updates mem hash table
        if(add_mem_ht( &(tpm->mem2NodeHT), rec->d_addr, &(dst->tpmnode2) ) >= 0) {}
        else { return -1; }
    }

    // updates adjacent mem node if any
    if(update_adjacent(tpm, dst, left, right, rec->s_addr, rec->bytesz) >= 0) {}
    else { return -1; }

    return n;
}

static int 
handle_dst_reg(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *regCntxt[], union TPMNode* dst)
{
    // print_record(rec);
    return 0;
}

static int 
handle_dst_temp(struct TPMContext *tpm, struct Record *rec, struct TPMNode1 *tempCntxt[], union TPMNode* dst)
{
    // print_record(rec);
    return 0;
}

static struct Transition *
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

    if(s_type & TPM_Type_Memory) { tmp = src->tpmnode2.firstChild; }
    else if(s_type & TPM_Type_Temprary || s_type & TPM_Type_Register) 
    { tmp = src->tpmnode1.firstChild; }

    while(tmp->next != NULL) { tmp = tmp->next; }   // reaches last child 
    tmp->next = t;  // links t to list end

    return t;
}

static bool  
is_addr_in_ht(struct TPMContext *tpm, struct MemHT *item, u32 addr)
// Returns:
//  t: if has mem node
//  f: if not found 
//      found item stored in *item
{   
    item = NULL;
    item = find_mem_ht( &(tpm->mem2NodeHT), addr);
    if(item != NULL) { return 1; }
    else { return 0; }
}

static int 
update_adjacent(struct TPMContext *tpm, union TPMNode *n, struct MemHT *l, struct MemHT *r, u32 addr, u32 bytesz)
// Returns:
//  >0: if has any update
//  0: no update
//  <0: error
{
    if(tpm == NULL || n == NULL) {
        fprintf(stderr, "error: update adjacent - tpm: %p - n: %p\n", tpm, n);
        return -1;
    }

    if(has_adjacent(tpm, l, r, addr, bytesz) ) {
        struct TPMNode2 *earliest = NULL;
        if(l != NULL){
            earliest = l->toMem;
            if(get_earliest_version(&earliest) == 0) {
                n->tpmnode2.leftNBR = earliest;
            }
            else { return -1; }
        }

        if(r != NULL){
            earliest = r->toMem;
            if(get_earliest_version(&earliest) == 0) {
                n->tpmnode2.rightNBR = earliest; 
            }
            else { return -1; }
        }
        return 1;
    }
    else { return 0; }
}

static bool 
has_adjacent(struct TPMContext *tpm, struct MemHT *l, struct MemHT *r, u32 addr, u32 bytesz)
// Returns:
//  1: if has either left or right adjacent mem node
//  0: otherwise
{
    bool rl = false, rr = false;

    l = NULL, r = NULL;
    rl = has_left_adjacent(tpm, l, addr);
    rr = has_right_adjacent(tpm, r, addr, bytesz);

    if( rl || rr ) {
        return true;
    } 
    else { return false; }
}

static bool 
has_left_adjacent(struct TPMContext *tpm, struct MemHT *item, u32 addr)
// Returns:
//  t: if has left adjacent mem node
//  f: otherwise
{
    item = NULL;
    u32 l_adjcnt;

    l_adjcnt = addr - DWORD;    // try 4 bytes first
    item = find_mem_ht( &(tpm->mem2NodeHT), l_adjcnt);
    if(item != NULL) {
        printf("has left adjacent: addr: 0x%x\n", item->toMem->addr); 
        return true; 
    }else { // doesn't find 4 bytes left adjacent
        l_adjcnt = addr - WORD; // try 2 bytes 
        item = find_mem_ht( &(tpm->mem2NodeHT), l_adjcnt);
        if(item != NULL) {
            printf("has left adjacent: addr: 0x%x\n", item->toMem->addr);  
            return true; 
        }
        else {
            l_adjcnt = addr - BYTE; // try 1 byte
            item = find_mem_ht( &(tpm->mem2NodeHT), l_adjcnt);
            if(item != NULL) {
                printf("has left adjacent: addr: 0x%x\n", item->toMem->addr);  
                return true; 
            }
            else { return false; } 
        }
    }
}

static bool 
has_right_adjacent(struct TPMContext *tpm, struct MemHT *item,  u32 addr, u32 bytesz)
// Returns:
//  t: if has right adjacent mem node
//  f: otherwise
{
    u32 r_adjcnt = addr + bytesz;
    item = NULL;

    item = find_mem_ht( &(tpm->mem2NodeHT), r_adjcnt);
    if(item != NULL) { 
        printf("has right adjacent: addr: 0x%x\n", item->toMem->addr);   
        return true; 
    }
    else { return false; }
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

static int 
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
    else { fprintf(stderr, "error: unkown addr type\n"); return -1; }
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
    printf("record: flag: %x src addr: %x\t\t src val: %x\t\t" 
                            "dst addr: %x\t\t dst val: %x\t\t"
                            "size: %d\t seqNo: %d\t" 
                            "is_load: %u is_store: %u\n", 
            rec->flag, rec->s_addr, rec->s_val, 
                       rec->d_addr, rec->d_val, 
                       rec->bytesz, rec->ts, 
                       rec->is_load, rec->is_store);
}

static void 
print_src_addr(struct Record *rec)
{
    printf("source addr: %x - seqNo: %d\n", rec->s_addr, rec->ts);
}

static void 
print_mem_node(struct TPMNode2 *n)
{
    printf("mem node: type: %u - addr: 0x%x - val: %x - lastUpdateTS: %u"
            " - firstChild: %p - leftNBR: %p - rightNBR: %p - nextVersion: %p"
            " - version: %u - hitcnt: %u \n", 
            n->type, n->addr, n->val, n->lastUpdateTS, 
            n->firstChild, n->leftNBR, n->rightNBR, n->nextVersion,
            n->version, n->hitcnt);
}

static void 
print_nonmem_node(struct TPMNode1 *n)
{
     printf("non mem node: type: %u - addr: 0x%x - val: %x - lastUpdateTS: %u\n", 
            n->type, n->addr, n->val, n->lastUpdateTS);   
}

static void 
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
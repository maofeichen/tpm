#include "tpmnode.h"
#include "flag.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

union TPMNode *
createTPMNode(u32 type, u32 addr, u32 val, int TS, u32 bytesz)
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
    tpmnode->tpmnode2.bytesz = bytesz;
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

int
getNodeType(u32 addr)
// Returns:
//  reg or temp based on the addr
{
    if(addr < G_TEMP_UNKNOWN) { return TPM_Type_Temprary; }
    else if(addr <=  G_TEMP_EDI) { return TPM_Type_Register; }
    else { fprintf(stderr, "error: unkown addr type: addr: %u\n", addr); return -1; }
}

void 
setLastUpdateTS(TPMNode *tpmnode, int lastUpdateTS)
{
    tpmnode->tpmnode1.lastUpdateTS = lastUpdateTS;
}

union TPMNode *
create1stVersionMemNode(u32 addr, u32 val, int ts, u32 bytesz)
// creates first version (0) memory node 
{
    union TPMNode *n;
    n = createTPMNode(TPM_Type_Memory, addr, val, ts, bytesz);
    setMemNodeVersion(n, 0);   
    n->tpmnode2.nextVersion = &(n->tpmnode2); // init points to itself
    return n; 
}

bool 
addNextVerMemNode(struct TPMNode2 *front, struct TPMNode2 *next)
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

int 
setMemNodeVersion(union TPMNode *tpmnode, u32 ver)
// Returns:
//  0: success
//  <0: error
{
    if(tpmnode == NULL)
        return -1;

    tpmnode->tpmnode2.version = ver;
    return 0; 
}

u32 
getMemNodeVersion(struct TPMNode2 *node)
// Returns
//  the version of the mem node
{
    return node->version;
}

int 
getMemNode1stVersion(struct TPMNode2 **earliest)
// Returns:
//  0: success
//  <0: error
//  stores the earliest version in earliest
{
    if(*earliest == NULL) {
        fprintf(stderr, "error: get earliest version\n");
        return -1;
    }

    // circulates the linked list until found 0 version
    while( (*earliest)->version != 0) { 
        *earliest = (*earliest)->nextVersion; 
    }
    return 0;
}

TaintedBuf *createTaintedBuf(TPMNode2 *bufstart)
{
    TaintedBuf *taintedBuf = malloc(sizeof(TaintedBuf) );
    memset(taintedBuf, 0, sizeof(TaintedBuf) );
    taintedBuf->bufstart = bufstart;
}

void 
printNode(TPMNode *tpmnode)
{
    if(tpmnode != NULL) {
        if(tpmnode->tpmnode1.type == TPM_Type_Memory) {
            printMemNode(&(tpmnode->tpmnode2) );
        }
        else {
            printNonmemNode(&(tpmnode->tpmnode1) );
        }
    }
}

void 
printMemNode(struct TPMNode2 *n)
{
    printf("mem: type:%-1u addr:0x%-8x val:%-8x lastUpdateTS:%-16d"
            " firstChild:%-8p leftNBR:%-8p rightNBR:%-8p nextVersion:%-8p"
            " version:%-9u hitcnt:%-8u\n", 
            n->type, n->addr, n->val, n->lastUpdateTS, 
            n->firstChild, n->leftNBR, n->rightNBR, n->nextVersion,
            n->version, n->hitcnt);
}

void 
printNonmemNode(struct TPMNode1 *n)
{
     printf("non-mem: type:%-1u addr:0x%-8x val:%-8x lastUpdateTS:%-16d\n", 
            n->type, n->addr, n->val, n->lastUpdateTS);   
}

void 
printMemNodeAllVersion(struct TPMNode2 *head)
{
    if(head == NULL)
        return;

    do{
        // printf("version: %u\n", head->version);
        printMemNode(head);
        head = head->nextVersion;
    } while(head == NULL || head->version != 0);
}

void 
printTaintedBuf(TaintedBuf *head)
{
    while(head != NULL) {
        printf("TaintedBuf: bufstart:%x - next:%p\n", head->bufstart->addr, head->next);
        head = head->next;
    }
}
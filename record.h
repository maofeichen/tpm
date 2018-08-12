#ifndef RECORD_H
#define RECORD_H

#include <stdbool.h>
#include "type.h"

#define MAX_NUM_FIELD	9	// max num of fields, flag, addr, ect a record has
#define MAX_FIELD_SZ	16	// max byte sz of a field

struct Record
{
    u32 flag;   // src and dst flags are same
    u32 s_addr;
    u32 s_val;
    u32 d_addr;
    u32 d_val;
    u32 bytesz;
    u32 ts;     // time stamp (seqNo)
    u32 s_ts;   // src time stamp
    u32 d_ts;   // dst time stamp
    u32 is_load;
    u32 is_loadptr;
    u32 is_store;
    u32 is_storeptr;
    u32 group_mark;
};
typedef struct Record Record;

bool
getRecordFlag(char *flag, char *rec);
// Returns:
//	t: success
//	f: error
//	stores first 2 chars (flag) in flag

bool
equalRecordMark(char *flag, char *mark);
// Returns:
//	t: if flag is mark
//	f: otherwise

bool
isControlRecord(char *flag);
// Returns:
//	true: if given flag is a mark record
//	false: otherwise

bool
isLoadRecord(char *flag);
// Returns:
//	t: if it's a load IR
//	f: otherwise

bool isLoadptrRecord(char *flag);

bool
isStoreRecord(char *flag);
// Returns:
//	t: if it's a store IR
//	f: otherwise

bool
isStoreptrRecord(char *flag);
// Returns:
//	t: if it's a store ptr IR
//	f: otherwise

u32
getRecSrcTS(u32 ts);
// Returns:
//	src ts give the records ts

u32
getRecDstTS(u32 ts);
// Returns:
//	dst ts given the record ts

int
analyzeRecord(char *s, char c, struct Record *rec);
// Returns:
//	0: success
//	<0: error
//	given a single record line, and separator, splits it into rec as
//		- flag
//		- src addr
//		- src val
//		- dst addr
//		- dst val
//		- ts (seqNo)
//		- bytesz if has

/* print */
void 
printRecord(struct Record *rec);

void 
printRecSrcAddr(struct Record *rec);

void 
printRecSrc(struct Record *rec);

void 
printRecDst(struct Record *rec);

#endif

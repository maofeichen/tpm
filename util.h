#ifndef UTIL_H
#define UTIL_H

#include "tpm.h"
#include <stdbool.h>

#define u32 unsigned int

#define MAX_NUM_FIELD	8	// max num of fields, flag, addr, ect a record has
#define MAX_FIELD_SZ	16	// max byte sz of a field

// Returns:
//	t: success
//	f: error
//	stores first 2 chars (flag) in flag
bool get_flag(char *flag, char *rec);

// Returns:
//	t: if flag is mark
//	f: otherwise
bool equal_mark(char *flag, char *mark);

// Returns:
//	true: if given flag is a mark record
//	false: otherwise
bool is_mark(char *flag);

// Returns:
//	t: if it's a load IR
//	f: otherwise
bool is_load(char *flag);

bool is_loadptr(char *flag);

// Returns:
//	t: if it's a store IR
//	f: otherwise
bool is_store(char *flag);

// Returns:
//	t: if it's a store ptr IR
//	f: otherwise
bool is_storeptr(char *flag);

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
int split(char *s, char c, struct Record *rec);


#endif
#ifndef UTIL_H
#define UTIL_H

#include "tpm.h"
#include <stdbool.h>

// Returns:
//	true: if given flag is a mark record
//	false: otherwise
bool is_mark(char *flag);

// Returns:
//	0: success
//	<0: error
//	given a single record line, and separator, splits it into rec as
//		- flag
//		- src addr
//		- src val
//		- dst addr
//		- dst val
int split(char *s, char c, struct Record *rec);

#endif
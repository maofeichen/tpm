#ifndef UTIL_H
#define UTIL_H

#include "tpm.h"

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
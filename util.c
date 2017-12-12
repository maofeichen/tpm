#include "flag.h"
#include "util.h"
#include <string.h> //strcmp

bool 
is_mark(char *flag)
{
	if( (strcmp(flag,INSN_MARK) == 0) || 
		(strcmp(flag,CALL_INSN) == 0) || 
		(strcmp(flag, CALL_INSN_SEC) == 0) || 
		(strcmp(flag, CALL_INSN_FF2) == 0) || 
		(strcmp(flag, CALL_INSN_FF2_SEC) == 0) || 
		(strcmp(flag, RET_INSN) == 0) || 
		(strcmp(flag, RET_INSN_SEC) == 0) ) {
		return true;	
	} else { return false; }
}

int 
split(char *s, char c, struct Record *rec)
{
	if(s == NULL)
		return -1;
	
	do {
		char *b = s;
		while(*s != c && *s)
		  s++;

		// determine record base on flag
	} while (*s++ != 0);	
	return 0;	
}
#include "util.h"

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
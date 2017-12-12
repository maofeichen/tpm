#include "flag.h"
#include "util.h"
#include <string.h> //strcmp
#include <stdlib.h>

bool
get_flag(char *flag, char *rec)
{
	if(strlen(rec) <= 2) { return false; }
	else {
		memcpy(flag, rec, 2);
		return true;
	}
}

bool 
equal_mark(char *flag, char *mark)
{
	if(strcmp(flag, mark) == 0) { return true;}
	else { return false; }
}

bool 
is_mark(char *flag)
{
	// printf("flag: %s\n", flag);
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

	char r[MAX_NUM_FIELD][MAX_FIELD_SZ] = {0};
	char *b = s, *e = s;
	int i = 0;

	// stores each field in rec to r
	do {
		int sz = 0;
		char *b = e;

		while(*e != c && *e){
		  e++;
		  sz++;
		}
		memcpy(r[i], b, sz);
		i++;
	} while (*e++ != 0);	


	for(i = 0; i < MAX_NUM_FIELD; i++) {
		if(r[i][0] == '\0')
			break;
		printf("%d field:%s\n", i, r[i]);
	}

	char flag[3] = {0};
	if(get_flag(flag, s) ) {
		if(equal_mark(flag, TCG_QEMU_LD) ) { // split load rec
			// printf("flag: %s - split load\n", flag);
			// return split_load(s, c, rec);
		} else if(equal_mark(flag, TCG_QEMU_ST) ) { // split store rec
			// printf("flag: %s - split store\n", flag);
			// return split_store(s, c, rec);
		} else { // others
			// printf("flag: %s - split non mem record\n", flag);
			// return split_nonmem(s, c, rec);
		}
	} else { fprintf(stderr, "error: get flag\n"); return -1; }

	return 0;
}

static int 
split_load(char *s, char c, struct Record *rec)
{

	do {
		char *b = s;
		while(*s != c && *s)
		  s++;

	} while (*s++ != 0);	

	return 0;	
}

static int split_store(char *s, char c, struct Record *rec)
{
	return 0;
}

static int 
split_nonmem(char *s, char c, struct Record *rec)
{
	do {
		int sz = 0;
		char *b = s;
		char field[16] = {0};
		u32 ifield = 0;

		while(*s != c && *s){
		  s++;
		  sz++;
		}
		memcpy(field, b, sz);
		ifield = (u32)strtoul(field, NULL, 16);
		printf("field: %s - ifield: %x\n", field, ifield);


	} while (*s++ != 0);	

	return 0;
}

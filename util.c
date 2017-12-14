#include "flag.h"
#include "util.h"
#include <string.h> //strcmp
#include <stdlib.h>

// static int split_load(char r[MAX_NUM_FIELD][MAX_FIELD_SZ], struct Record *rec);
// static int split_store(char r[MAX_NUM_FIELD][MAX_FIELD_SZ], struct Record *rec);
static int split_mem(char r[MAX_NUM_FIELD][MAX_FIELD_SZ], struct Record *rec);
static int split_nonmem(char r[MAX_NUM_FIELD][MAX_FIELD_SZ], struct Record *rec);

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

bool 
is_load(char *flag)
{
	return equal_mark(flag, TCG_QEMU_LD);
}

bool 
is_store(char *flag)
{
	return equal_mark(flag, TCG_QEMU_ST);
}

int 
split(char *s, char c, struct Record *rec)
{
	if(s == NULL)
		return -1;

	char r[MAX_NUM_FIELD][MAX_FIELD_SZ] = { {0} };
	char *e = s;
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


	// for(i = 0; i < MAX_NUM_FIELD; i++) {
	// 	if(r[i][0] == '\0')
	// 		break;
	// 	printf("%d field:%s\n", i, r[i]);
	// }

	char flag[3] = {0};
	if(get_flag(flag, s) ) {
		if(equal_mark(flag, TCG_QEMU_LD) || equal_mark(flag, TCG_QEMU_ST)) { // split mem 
			// printf("flag: %s - split mem record\n", flag);
			split_mem(r, rec);
		} else { // others
			// printf("flag: %s - split non mem record\n", flag);
			split_nonmem(r, rec);
		}
	} else { fprintf(stderr, "error: get flag\n"); return -1; }

	return 0;
}

static int 
split_mem(char r[MAX_NUM_FIELD][MAX_FIELD_SZ], struct Record *rec)
{
	// int i;
	// for(i = 0; i < MAX_NUM_FIELD; i++) {
	// 	if(r[i][0] == '\0')
	// 		break;
	// 	printf("%d field:%s\n", i, r[i]);
	// }

	rec->flag 	= strtoul(r[0], NULL, 16); 	// 0st str: flag
	rec->s_addr	= strtoul(r[1], NULL, 16);	// 1st str: src addr
	rec->s_val	= strtoul(r[2], NULL, 16); 	// 2nd str: src val
	rec->d_addr	= strtoul(r[4], NULL, 16); 	// 4th str: dst addr
	rec->d_val	= strtoul(r[5], NULL, 16);	// 5th str: dst val
	u32 bitsz	= strtoul(r[6], NULL, 10);	// 6th str: mem size
	rec->bytesz	= bitsz / 8;
	rec->ts 	= strtoul(r[7], NULL, 10);	// 7th str: seqNo
	if(is_load(r[0]) )
		rec->is_load = 1;
	else if(is_store(r[0]) )
		rec->is_store = 1;

	return 0;
}

static int 
split_nonmem(char r[MAX_NUM_FIELD][MAX_FIELD_SZ], struct Record *rec)
{
	// int i;
	// for(i = 0; i < MAX_NUM_FIELD; i++) {
	// 	if(r[i][0] == '\0')
	// 		break;
	// 	printf("%d field:%s\n", i, r[i]);
	// }

	rec->flag 	= strtoul(r[0], NULL, 16); 	// 0st str: flag
	rec->s_addr	= strtoul(r[1], NULL, 16);	// 1st str: src addr
	rec->s_val	= strtoul(r[2], NULL, 16); 	// 2nd str: src val
	rec->d_addr	= strtoul(r[4], NULL, 16); 	// 4th str: dst addr
	rec->d_val	= strtoul(r[5], NULL, 16);	// 5th str: dst val
	// rec->bytesz	= 0;
	rec->ts 	= strtoul(r[6], NULL, 10);	// 6th str: seqNo
	return 0;
}

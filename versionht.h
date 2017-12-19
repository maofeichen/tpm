#ifndef VERSIONHT_H
#define VERSIONHT_H

#include "uthash.h"

#define u32 unsigned int

struct AddrHT
{
    u32 addr;
    u32 ver; 	
    UT_hash_handle hh_ver;  // hash table head, required by uthash
};

/* version hash table */
int
add_ver_ht(struct AddrHT **addrHT, u32 addr);

struct AddrHT *
find_ver_ht(struct AddrHT **addrHT, u32 addr);

void
del_ver_ht(struct AddrHT **addrHT);

void 
count_ver_ht(struct AddrHT **addrHT);

void 
print_ver_ht(struct AddrHT **addrHT);

#endif
#ifndef STAT_H
#define STAT_H 

#include "tpm.h"
#include "uthash.h"

#ifndef STAT
#define STAT
#endif

#define BIG_NUM	1000

struct AddrHT
{
    u32 addr;
    u32 ver; 	
    UT_hash_handle hh_ver;  // hash table head, required by uthash
};

/* continuous buf */
void get_cont_buf(struct TPMNode2 *node);
void compute_cont_buf(struct TPMContext *tpm);

/* version */
void compute_version(struct TPMContext *tpm, u32 type);
void compute_version_all(struct TPMContext *tpm);

/* out degree */
void compute_outd(struct TPMContext *tpm, u32 type);
void compute_outd_all(struct TPMContext *tpm);

void compute_total_node(struct TPMContext *tpm);

void stat(struct TPMContext *tpm);

#endif

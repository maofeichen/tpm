#ifndef STAT_H
#define STAT_H 

#include "tpm.h"
#include "uthash.h"
#include "versionht.h"
#include "contbufht.h"

#ifndef STAT
#define STAT
#endif

#define MIN_BUF_SZ	8

/* continuous buf */
void get_cont_buf(struct TPMNode2 *node, u32 *baddr, u32 *eaddr, u32 *minseq, u32 *maxseq);
void compute_cont_buf(struct TPMContext *tpm);

/* version */
void compute_version(struct TPMContext *tpm, u32 type);
void compute_version_all(struct TPMContext *tpm);

/* out degree */
void compute_outd(struct TPMContext *tpm, u32 type);
void compute_outd_all(struct TPMContext *tpm);

/* general */
void compute_total_node(struct TPMContext *tpm);

void stat(struct TPMContext *tpm);

#endif

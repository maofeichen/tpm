#ifndef ENV_H_
#define ENV_H_

/* 32/64 env */
#if __x86_64__
#define ENV64
#else
#define ENV32
#endif

/* TPM reverse transition
 *  TPM propagates forward by default, with enable this flag. During building
 *  TPM, it'll also create reverse transitions: dest --> src. */
#define TPM_RE_TRANSITON    0
#endif /* ENV_H_ */

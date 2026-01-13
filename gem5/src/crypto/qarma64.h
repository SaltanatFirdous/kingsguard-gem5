
#ifndef __CRYPTO_QARMA64_H__
#define __CRYPTO_QARMA64_H__

typedef unsigned char cell_t;

#ifdef __cplusplus
extern "C" {
#endif

void qarma64Encrypt(cell_t * input,
             const cell_t W[16], const cell_t W_p[16],
             const cell_t core_key[16], const cell_t middle_key[16],
             const cell_t tweak[16],
             int R);

void qarma64KeySpecialisation(const cell_t k0[16], const cell_t w0[16],
	cell_t * k1, cell_t * k1_M, cell_t * w1);

#ifdef __cplusplus
}
#endif

#endif //__CRYPTO_QARMA64_H__
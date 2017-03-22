
#ifndef HEADER_SM3_H
#define HEADER_SM3_H

#define SM3_DIGEST_SIZE	32
#define SM3_BLOCK_SIZE		64
#define SM3_CBLOCK		(SM3_BLOCK_SIZE)
#define SM3_HMAC_SIZE		(SM3_DIGEST_SIZE)


#include <linux/types.h>

struct sm3_ctx {
	u32 digest[8];
	int nblocks;
	unsigned char block[64];
	int num;
};

#if 0
void sm3_init(struct shash_desc *desc);
void sm3_update(struct shash_desc *desc, const unsigned char *data, size_t data_len);
void sm3_final(struct shash_desc *desc, unsigned char digest[SM3_DIGEST_SIZE]);
void sm3_compress(uint32_t digest[8], const unsigned char block[SM3_BLOCK_SIZE]);
#endif

#endif

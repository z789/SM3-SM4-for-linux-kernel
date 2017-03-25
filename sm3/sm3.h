
#ifndef HEADER_SM3_H
#define HEADER_SM3_H

#define SM3_DIGEST_SIZE		32
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

#endif

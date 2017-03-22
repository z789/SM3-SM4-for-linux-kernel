#ifndef HEADER_SM4_H
#define HEADER_SM4_H

#define SM4_KEY_SIZE		16
#define SM4_BLOCK_SIZE		16
#define SM4_IV_LENGTH		(SM4_BLOCK_SIZE)
#define SM4_NUM_ROUNDS		32

#include <linux/types.h>

struct sm4_key {
	uint32_t rk[SM4_NUM_ROUNDS];
};

struct sm4_ctx {
	struct sm4_key ekey;
	struct sm4_key dkey;
};
#endif

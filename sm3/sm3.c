#include <crypto/internal/hash.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/cryptohash.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include "sm3.h"

static void sm3_compress(u32 digest[8], const unsigned char block[64]);

static int sm3_init(struct shash_desc *desc)
{
	struct sm3_ctx *ctx = shash_desc_ctx(desc);

	ctx->digest[0] = 0x7380166F;
	ctx->digest[1] = 0x4914B2B9;
	ctx->digest[2] = 0x172442D7;
	ctx->digest[3] = 0xDA8A0600;
	ctx->digest[4] = 0xA96F30BC;
	ctx->digest[5] = 0x163138AA;
	ctx->digest[6] = 0xE38DEE4D;
	ctx->digest[7] = 0xB0FB0E4E;

	ctx->nblocks = 0;
	ctx->num = 0;

	return 0;
}

static int sm3_update(struct shash_desc *desc, const unsigned char *data,
			 size_t data_len)
{
	struct sm3_ctx *ctx = shash_desc_ctx(desc);

	if (ctx->num) {
		unsigned int left = SM3_BLOCK_SIZE - ctx->num;

		if (data_len < left) {
			memcpy(ctx->block + ctx->num, data, data_len);
			ctx->num += data_len;
			return 0;
		} else {
			memcpy(ctx->block + ctx->num, data, left);
			sm3_compress(ctx->digest, ctx->block);
			ctx->nblocks++;
			data += left;
			data_len -= left;
		}
	}

	while (data_len >= SM3_BLOCK_SIZE) {
		sm3_compress(ctx->digest, data);
		ctx->nblocks++;
		data += SM3_BLOCK_SIZE;
		data_len -= SM3_BLOCK_SIZE;
	}
	ctx->num = data_len;
	if (data_len)
		memcpy(ctx->block, data, data_len);

	return 0;
}

static int sm3_final(struct shash_desc *desc, unsigned char *digest)
{
	struct sm3_ctx *ctx = shash_desc_ctx(desc);
	int i;
	u32 *pdigest = (u32 *)digest;
	u64 *count = (u64 *)(ctx->block + SM3_BLOCK_SIZE - 8);

	ctx->block[ctx->num] = 0x80;

	if (ctx->num + 9 <= SM3_BLOCK_SIZE) {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 9);
	} else {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 1);
		sm3_compress(ctx->digest, ctx->block);
		memset(ctx->block, 0, SM3_BLOCK_SIZE - 8);
	}

	count[0] = cpu_to_be64((ctx->nblocks << 9) + (ctx->num << 3));

	sm3_compress(ctx->digest, ctx->block);
	for (i = 0; i < ARRAY_SIZE(ctx->digest); i++)
		pdigest[i] = cpu_to_be32(ctx->digest[i]);

	return 0;
}

#define ROTATELEFT(X, n)  (((X)<<(n)) | ((X)>>(32-(n))))

#define P0(x) ((x) ^  ROTATELEFT((x), 9)  ^ ROTATELEFT((x), 17))
#define P1(x) ((x) ^  ROTATELEFT((x), 15) ^ ROTATELEFT((x), 23))

#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))

#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))


static const u32 T16 = 0x79CC4519;
static const u32 T64 = 0x7A879D8A;

static void sm3_compress(u32 digest[8], const unsigned char block[64])
{
	int j;
	u32 W[68];
	const u32 *pblock = (const u32 *)block;

	u32 A = digest[0];
	u32 B = digest[1];
	u32 C = digest[2];
	u32 D = digest[3];
	u32 E = digest[4];
	u32 F = digest[5];
	u32 G = digest[6];
	u32 H = digest[7];
	u32 SS1, SS2, TT1, TT2;

	for (j = 0; j < 16; j++)
		W[j] = cpu_to_be32(pblock[j]);
	for (j = 16; j < 68; j++)
		W[j] = P1(W[j-16] ^ W[j-9] ^ ROTATELEFT(W[j-3], 15)) ^ ROTATELEFT(W[j - 13], 7) ^ W[j-6];

	for (j = 0; j < 16; j++) {

		SS1 = ROTATELEFT((ROTATELEFT(A, 12) + E + ROTATELEFT(T16, j)), 7);
		SS2 = SS1 ^ ROTATELEFT(A, 12);
		TT1 = FF0(A, B, C) + D + SS2 + (W[j] ^ W[j+4]);
		TT2 = GG0(E, F, G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F, 19);
		F = E;
		E = P0(TT2);
	}

	for (j = 16; j < 64; j++) {

		SS1 = ROTATELEFT((ROTATELEFT(A, 12) + E + ROTATELEFT(T64, j)), 7);
		SS2 = SS1 ^ ROTATELEFT(A, 12);
		TT1 = FF1(A, B, C) + D + SS2 + (W[j] ^ W[j+4]);
		TT2 = GG1(E, F, G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F, 19);
		F = E;
		E = P0(TT2);
	}

	digest[0] ^= A;
	digest[1] ^= B;
	digest[2] ^= C;
	digest[3] ^= D;
	digest[4] ^= E;
	digest[5] ^= F;
	digest[6] ^= G;
	digest[7] ^= H;
}


static int sm3_export(struct shash_desc *desc, void *out)
{
	struct sm3_ctx *ctx = shash_desc_ctx(desc);

	memcpy(out, ctx, sizeof(*ctx));
	return 0;
}

static int sm3_import(struct shash_desc *desc, const void *in)
{
	struct sm3_ctx *ctx = shash_desc_ctx(desc);

	memcpy(ctx, in, sizeof(*ctx));
	return 0;
}

static struct shash_alg alg = {
	.digestsize	=	SM3_DIGEST_SIZE,
	.init		=	sm3_init,
	.update		=	sm3_update,
	.final		=	sm3_final,
	.export		=	sm3_export,
	.import		=	sm3_import,
	.descsize	=	sizeof(struct sm3_ctx),
	.statesize	=	sizeof(struct sm3_ctx),
	.base		=	{
		.cra_name	=	"sm3",
		.cra_flags	=	CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize	=	SM3_BLOCK_SIZE,
		.cra_module	=	THIS_MODULE,
	}
};

static int __init sm3_mod_init(void)
{
	return crypto_register_shash(&alg);
}

static void __exit sm3_mod_fini(void)
{
	crypto_unregister_shash(&alg);
}

module_init(sm3_mod_init);
module_exit(sm3_mod_fini);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("SM3 Message Digest Algorithm. This product includes software developed by the GmSSL Project (http://gmssl.org/)");
MODULE_ALIAS_CRYPTO("sm3");

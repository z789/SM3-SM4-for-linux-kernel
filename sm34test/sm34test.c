#include<linux/kernel.h>
#include<linux/module.h>
#include<linux/init.h>
#include<linux/crypto.h>
#include<linux/string.h>
#include<linux/scatterlist.h>
//#include<crypto/sm3.h>
//#include<crypto/sm4.h>
#include"../sm3/sm3.h"
#include"../sm4/sm4.h"
#include<crypto/hash.h>
#include<crypto/skcipher.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 1)
#include <crypto/internal/cipher.h>
MODULE_IMPORT_NS(CRYPTO_INTERNAL);
#endif


/*
 * http://www.gmbz.org.cn/upload/2018-07-24/1532401392982079739.pdf
 * Annex A example
 */
/* "abc" */
static unsigned char sm3_msg1[] = {0x61, 0x62, 0x63};
static unsigned char digest_sm3_msg1[] = {
	0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
	0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
	0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
	0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
};

/* "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd" */
static unsigned char sm3_msg2[] = {
	0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
	0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
	0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
	0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
	0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
	0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
	0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
	0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64
};
static unsigned char digest_sm3_msg2[] = {
	0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1,
	0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d,
	0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65,
	0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32
};

/*
 * The paper http://www.gmbz.org.cn/upload/2018-04-04/1522788048733065051.pdf
 * Annex A (informative) Examples
*/
uint8_t sm4_plain[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};
uint8_t sm4_key[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE,
	0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};
uint8_t sm4_cipher[] = {
	0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E,
	0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46
};
uint8_t sm4_cipher1000000[] = {
	0x59, 0x52, 0x98, 0xC7, 0xC6, 0xFD, 0x27, 0x1F,
	0x04, 0x02, 0xF8, 0x04, 0xC3, 0x3D, 0x3F, 0x66
};


static char plain[16] = "0123456789abcdef";
static char key[16] = "0123456789abcdef";
static char xtskey[32] = "0123456789abcdef";
static char lrwkey[32] = "0123456789abcdef";

#define BUF_LEN (128+1)
static char buf_hex[BUF_LEN];
static int print_hex(const char *h, char *buf, int len)
{
	int i, j;

	if (!buf)
		return -EINVAL;

	printk(KERN_INFO "%s:", h);

	i = 0;
	j = 0;
	while (i < len) {
		sprintf(buf_hex+j*2, "%02X", (unsigned char)buf[i]);
		if (unlikely((j*2+1) % BUF_LEN == 0)) {
			buf_hex[j*2] = '\0';
			printk(KERN_INFO "%s", buf_hex);
			j = 0;
		} else{
			j++;
		}
		i++;
	}
	buf_hex[j*2] = '\0';
	printk(KERN_INFO "%s", buf_hex);

	return 0;
}

#define PREFIX_LEN 32
static int print_plain(const char *name, char *buf, int len)
{
	char h[PREFIX_LEN];

	snprintf(h, sizeof(h), "%s %s", name, "plain");
	return print_hex(h, buf, len);
}

static int print_cipher(const char *name, char *buf, int len)
{
	char h[PREFIX_LEN];

	snprintf(h, sizeof(h), "%s %s", name, "cipher");
	return print_hex(h, buf, len);
}

static int print_decrypt(const char *name, char *buf, int len)
{
	char h[PREFIX_LEN];

	snprintf(h, sizeof(h), "%s %s", name, "decrypted");
	return print_hex(h, buf, len);
}

static int test_sm3(const char *name, char *buf, int len)
{
	struct crypto_shash *tfm = NULL;
	struct shash_desc *desc = NULL;
	char result[SM3_DIGEST_SIZE];
	int desc_len = 0;
	int ret = -EINVAL;

	if (!name || !buf || len < 0)
		return ret;

	tfm = crypto_alloc_shash(name, 0, 0);
	if (IS_ERR(tfm)) {
		printk(KERN_INFO "alloc shash err:%s\n", name);
		ret = PTR_ERR(tfm);
		tfm = NULL;
		goto end;
	}

	desc_len = crypto_shash_descsize(tfm) + sizeof(*desc);
	desc = kmalloc(desc_len, GFP_KERNEL);
	if (!desc) {
		ret = -ENOMEM;
		goto end;
	}

	desc->tfm = tfm;

	ret = crypto_shash_init(desc);
	if (ret)
		goto end;

	ret = crypto_shash_update(desc, buf, len);
	if (ret)
		goto end;

	crypto_shash_final(desc, result);
	print_plain(name, buf, len);
	print_cipher(name, result, sizeof(result));

	ret = 0;

end:
	kfree(desc);
	if (tfm)
		crypto_free_shash(tfm);

	return ret;
}

static int hash_sm3_buf(char *buf, int len, char *result, int result_len)
{
	struct crypto_shash *tfm = NULL;
	struct shash_desc *desc = NULL;
	int desc_len = 0;
	int ret = -EINVAL;

	if (!buf || len < 0 || !result || result_len < SM3_DIGEST_SIZE)
		return ret;

	tfm = crypto_alloc_shash("sm3", 0, 0);
	if (IS_ERR(tfm)) {
		printk(KERN_INFO "alloc shash err: sm3\n");
		ret = PTR_ERR(tfm);
		tfm = NULL;
		goto end;
	}

	desc_len = crypto_shash_descsize(tfm) + sizeof(*desc);
	desc = kmalloc(desc_len, GFP_KERNEL);
	if (!desc) {
		ret = -ENOMEM;
		goto end;
	}

	desc->tfm = tfm;

	ret = crypto_shash_init(desc);
	if (ret)
		goto end;

	ret = crypto_shash_update(desc, buf, len);
	if (ret)
		goto end;

	crypto_shash_final(desc, result);

	ret = 0;

end:
	kfree(desc);
	if (tfm)
		crypto_free_shash(tfm);

	return ret;
}

static int test_sm3_vector(void)
{
	char result[SM3_DIGEST_SIZE];
	int ret = -1;

	ret = hash_sm3_buf(sm3_msg1, sizeof(sm3_msg1), result, sizeof(result));
	if (ret < 0)
		goto end;
	if (memcmp(result, digest_sm3_msg1, sizeof(digest_sm3_msg1))) {
		printk(KERN_INFO "SM3 test vector msg1 FAIL!\n");
		goto end;
	}

	ret = hash_sm3_buf(sm3_msg2, sizeof(sm3_msg2), result, sizeof(result));
	if (ret < 0)
		goto end;
	if (memcmp(result, digest_sm3_msg2, sizeof(digest_sm3_msg2))) {
		printk(KERN_INFO "SM3 test vector msg2 FAIL!\n");
		goto end;
	}

	printk(KERN_INFO "SM3 test all vector OK!\n");
	ret = 0;
end:
	return ret;
}

static int test_hmac_sm3(const char *name, char *plaintext, int psize, char *key, int ksize)
{
	struct crypto_shash *tfm = NULL;
	struct shash_desc *shash = NULL;
	char result[SM3_HMAC_SIZE];
	int ret = -1;

	if (!name || !plaintext || psize < 0 || !key || ksize < 0)
		return -EINVAL;

	tfm = crypto_alloc_shash(name, 0, 0);
	if (IS_ERR(tfm)) {
		printk(KERN_INFO "crypto_alloc_ahash failed: err %ld", PTR_ERR(tfm));
		ret = PTR_ERR(tfm);
		tfm = NULL;
		goto end;
	}

	ret = crypto_shash_setkey(tfm, key, ksize);
	if (ret) {
		printk(KERN_INFO "crypto_ahash_setkey failed: err %d", ret);
		goto end;
	}

	shash = kzalloc(sizeof(*shash) + crypto_shash_descsize(tfm),
			GFP_KERNEL);
	if (!shash) {
		ret = -ENOMEM;
		goto end;
	}

	shash->tfm = tfm;

	print_plain(name, plaintext, psize);
	ret = crypto_shash_digest(shash, plaintext, psize, result);
	print_cipher(name, result, sizeof(result));

	kfree(shash);

end:
	if (tfm)
		crypto_free_shash(tfm);
	return ret;
}

static int equal_plain_decrypt(const char *plain, int plen, const char *decrypt, int dlen)
{
	if ((plen != dlen) || memcmp(plain, decrypt, plen) != 0)
		return 0;
	return 1;
}

static int test_result(const char *name, const char *plain, int plen,
				 const char *decrypt, int dlen)
{
	int ret = 0;

	ret = equal_plain_decrypt(plain, plen, decrypt, dlen);
	if (ret)
		printk(KERN_INFO "%s test OK!\n", name);
	else
		printk(KERN_INFO "%s test ERR!\n", name);

	return ret;
}

static int test_sm4_one(const char *name, char *buf, int len, char *key, int klen)
{
	struct  crypto_cipher *tfm = NULL;
	char *result = NULL;
	int ret = -1;
	int result_len = 0;

	tfm = crypto_alloc_cipher(name, 0, 0);
	if (IS_ERR(tfm)) {
		printk(KERN_INFO "crypto_alloc_cipher failed: err %ld", PTR_ERR(tfm));
		tfm = NULL;
		return PTR_ERR(tfm);
	}

	result_len = roundup(len, crypto_cipher_blocksize(tfm));
	result = kmalloc(result_len, GFP_KERNEL);
	if (!result) {
		ret = -ENOMEM;
		goto end;
	}

	ret = crypto_cipher_setkey(tfm, key, klen);
	if (ret) {
		printk(KERN_INFO "crypto setkey err!\n");
		goto end;
	}

	print_plain(name, buf, len);
	crypto_cipher_encrypt_one(tfm, result, buf);
	print_cipher(name, result, result_len);

	crypto_cipher_decrypt_one(tfm, result, result);
	print_decrypt(name, result, result_len);

	test_result(name, buf, len, result, result_len);

	ret = 0;

end:
	kfree(result);
	if (tfm)
		crypto_free_cipher(tfm);

	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 1)
static int sm4_blkcipher_enc_dec(const char *name, char *in, int inlen,
				char *out, int outlen, char *key, int klen, int is_enc)
{
	struct  crypto_blkcipher *tfm = NULL;
	struct blkcipher_desc desc;
	struct scatterlist sin;
	struct scatterlist sout;
	char *iv = NULL;
	int ret = -EINVAL;
	int blksize = 0;
	int iv_len = 0;

	if (!name || !in || inlen < 0 || !out || outlen < 0
			|| !key || klen < 0)
		return -EINVAL;

	if (!(crypto_has_blkcipher(name, 0, 0))) {
		printk(KERN_INFO "no has blkcipher:%s\n", name);
		goto end;
	}

	tfm = crypto_alloc_blkcipher(name, 0, 0);
	if (IS_ERR(tfm)) {
		printk(KERN_INFO "crypto_alloc_blkcipher failed: err %ld name:%s\n", PTR_ERR(tfm), name);
		ret = PTR_ERR(tfm);
		tfm = NULL;
		goto end;
	}

	desc.tfm = tfm;
	desc.flags = 0;

	blksize = crypto_blkcipher_blocksize(tfm);
	if (inlen % blksize) {
		printk(KERN_INFO "in size err!\n");
		goto end;
	}
	ret = crypto_blkcipher_setkey(tfm, key, klen);
	if (ret) {
		printk(KERN_INFO "crypto setkey err!\n");
		goto end;
	}

	iv = crypto_blkcipher_crt(tfm)->iv;
	iv_len = crypto_blkcipher_ivsize(tfm);
	memset(iv, 0, iv_len);

	sg_init_one(&sin, in, inlen);
	sg_init_one(&sout, out, outlen);

	if (is_enc) {
		ret = crypto_blkcipher_encrypt(&desc, &sout, &sin, inlen);
		if (ret < 0) {
			printk(KERN_INFO "crypto_blkcipher_encrypt!\n");
			goto end;
		}
	} else{
		ret = crypto_blkcipher_decrypt(&desc, &sout, &sin, inlen);
		if (ret < 0) {
			printk(KERN_INFO "crypto_blkcipher_decrypt!\n");
			goto end;
		}
	}

end:
	if (tfm)
		crypto_free_blkcipher(tfm);

	return ret;
}


static int test_sm4_blkcipher(const char *name, char *in, int inlen, char *key, int klen)
{
	char *cout = NULL;
	char *pout = NULL;
	int clen, plen;
	int ret = -1;

	if (!name || !in || inlen < 0 || !key || klen < 0)
		return -EINVAL;

	clen = roundup(inlen, SM4_BLOCK_SIZE);
	plen = roundup(inlen, SM4_BLOCK_SIZE);

	cout = kzalloc(clen, GFP_KERNEL);
	pout = kzalloc(plen, GFP_KERNEL);
	if (!cout || !pout) {
		ret = -ENOMEM;
		goto end;
	}

	printk(KERN_INFO "crypto_blkcipher API");
	ret = sm4_blkcipher_enc_dec(name, in, inlen, cout, clen, key, klen, 1);
	if (ret)
		goto end;
	print_plain(name, in, inlen);
	print_cipher(name, cout, clen);

	ret = sm4_blkcipher_enc_dec(name, cout, clen, pout, plen, key, klen, 0);
	print_decrypt(name, pout, plen);

	test_result(name, in, inlen, pout, plen);

end:
	kfree(cout);
	kfree(pout);

	return ret;
}
#else
static int test_sm4_blkcipher(const char *name, char *in, int inlen, char *key, int klen)
{
	return 0;
}
#endif

static int sm4_skcipher_enc_dec(const char *name, char *in, int inlen,
				char *out, int outlen, char *key, int klen, int is_enc)
{
	struct crypto_skcipher *tfm = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sin;
	struct scatterlist sout;
	char iv[32] = {0};
	int ret = -EINVAL;

	if (!name || !in || inlen < 0 || !out || outlen < 0
			|| !key || klen < 0)
		return -EINVAL;

	if (!crypto_has_skcipher(name, 0, CRYPTO_ALG_ASYNC)) {
		printk(KERN_INFO "no has skcipher:%s\n", name);
		goto end;
	}

	tfm = crypto_alloc_skcipher(name, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		printk(KERN_INFO "crypto_alloc_skcipher failed: err %ld name:%s\n", PTR_ERR(tfm), name);
		ret = PTR_ERR(tfm);
		tfm = NULL;
		goto end;
	}

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		printk(KERN_INFO "skcipher_alloc_alloc failed\n");
		ret = -ENOMEM;
		goto end;
	}

	if (crypto_skcipher_setkey(tfm, key, klen)) {
		printk(KERN_INFO "crypto_skcipher setkey err!\n");
		ret = -EAGAIN;
		goto end;
	}

	sg_init_one(&sin, in, inlen);
	sg_init_one(&sout, out, outlen);

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP, NULL, NULL);
	skcipher_request_set_crypt(req, &sin, &sout, inlen, iv);

	if (is_enc)
		ret = crypto_skcipher_encrypt(req);
	else
		ret = crypto_skcipher_decrypt(req);

end:
	skcipher_request_free(req);
	if (tfm)
		crypto_free_skcipher(tfm);
	return ret;
}


static int test_sm4_skcipher(const char *name, char *in, int inlen, char *key, int klen)
{
	char *cout = NULL;
	char *pout = NULL;
	int clen, plen;
	int ret = -1;

	if (!name || !in || inlen < 0 || !key || klen < 0)
		return -EINVAL;

	clen = roundup(inlen, SM4_BLOCK_SIZE);
	plen = roundup(inlen, SM4_BLOCK_SIZE);

	cout = kzalloc(clen, GFP_KERNEL);
	pout = kzalloc(plen, GFP_KERNEL);
	if (!cout || !pout) {
		ret = -ENOMEM;
		goto end;
	}

	printk(KERN_INFO "crypto_skcipher API");
	ret = sm4_skcipher_enc_dec(name, in, inlen, cout, clen, key, klen, 1);
	if (ret)
		goto end;
	print_plain(name, in, inlen);
	print_cipher(name, cout, clen);

	ret = sm4_skcipher_enc_dec(name, cout, clen, pout, plen, key, klen, 0);
	if (ret)
		printk("sm4_skcipher_dec err!\n");
	print_decrypt(name, pout, plen);

	test_result(name, in, inlen, pout, plen);

end:
	kfree(cout);
	kfree(pout);

	return ret;
}

static int enc_dec_sm4_one(char *buf, int len, char *result, int result_len,
		char *key, int klen, int is_enc, int round)
{
	struct crypto_cipher *tfm = NULL;
	char src_buf[SM4_BLOCK_SIZE] = {0};
	char dst_buf[SM4_BLOCK_SIZE] = {0};
	char *src = src_buf;
	char *dst = dst_buf;
	char *tmp = NULL;
	void (*crypto_cipher_one)(struct crypto_cipher *tfm, u8 *dst, const u8 *src)
		                      = crypto_cipher_encrypt_one;

	int ret = -1;

	if (!buf || len < SM4_BLOCK_SIZE || !result || result_len < SM4_BLOCK_SIZE ||
		!key || klen < 1 || round < 1)
		return -EINVAL;

	tfm = crypto_alloc_cipher("sm4", 0, 0);
	if (IS_ERR(tfm)) {
		printk(KERN_INFO "crypto_alloc_cipher failed: err %ld", PTR_ERR(tfm));
		tfm = NULL;
		return PTR_ERR(tfm);
	}

	ret = crypto_cipher_setkey(tfm, key, klen);
	if (ret) {
		printk(KERN_INFO "crypto setkey err!\n");
		goto end;
	}

	if (!is_enc)
		crypto_cipher_one = crypto_cipher_decrypt_one;

	memcpy(src_buf, buf, sizeof(src_buf));
	while (round-- > 0) {
		crypto_cipher_one(tfm, dst, src);
		tmp = src;
		src = dst;
		dst = src;
	}
	memcpy(result, dst, sizeof(dst_buf));
	ret = 0;

end:
	if (tfm)
		crypto_free_cipher(tfm);

	return ret;
}

static int enc_sm4_one(char *buf, int len, char *result, int result_len,
		char *key, int klen, int round)
{
	return enc_dec_sm4_one(buf, len, result, result_len,
			key, klen, 1, round);
}

static int dec_sm4_one(char *buf, int len, char *result, int result_len,
		char *key, int klen, int round)
{
	return enc_dec_sm4_one(buf, len, result, result_len,
			key, klen, 0, round);
}

static int test_sm4_vector(void)
{
	char result[SM3_BLOCK_SIZE];
	int ret = -1;

	ret = enc_sm4_one(sm4_plain, sizeof(sm4_plain), result, sizeof(result),
			sm4_key, sizeof(sm4_key), 1);
	if (ret < 0)
		goto end;
	if (memcmp(result, sm4_cipher, sizeof(sm4_cipher))) {
		printk(KERN_INFO "SM4 test vector 1 round encrypt FAIL!\n");
		goto end;
	}

	ret = dec_sm4_one(sm4_cipher, sizeof(sm4_cipher), result, sizeof(result),
			sm4_key, sizeof(sm4_key), 1);
	if (ret < 0)
		goto end;
	if (memcmp(result, sm4_plain, sizeof(sm4_plain))) {
		printk(KERN_INFO "SM4 test vector 1 round decrypt FAIL!\n");
		goto end;
	}

	ret = enc_sm4_one(sm4_plain, sizeof(sm4_plain), result, sizeof(result),
			sm4_key, sizeof(sm4_key), 1000000);
	if (ret < 0)
		goto end;
	if (memcmp(result, sm4_cipher1000000, sizeof(sm4_cipher1000000))) {
		printk(KERN_INFO "SM4 test vector 1000000 round encrypt FAIL!\n");
		goto end;
	}

	ret = dec_sm4_one(sm4_cipher1000000, sizeof(sm4_cipher1000000),
			result, sizeof(result), sm4_key, sizeof(sm4_key), 1000000);
	if (ret < 0)
		goto end;
	if (memcmp(result, sm4_plain, sizeof(sm4_plain))) {
		printk(KERN_INFO "SM4 test vector 1000000 round decrypt FAIL!\n");
		goto end;
	}

	printk(KERN_INFO "SM4 test all vector OK!\n");
	ret = 0;
end:
	return ret;
}

static int __init sm34_init(void)
{
	char cbcplain[64] = "0123456789abcdef0123456789abcdef...";

	test_sm3_vector();
	test_sm4_vector();

	test_sm3("sm3", plain, sizeof(plain));
	test_hmac_sm3("hmac(sm3)", plain, sizeof(plain), key, sizeof(key));
	test_sm4_one("sm4", plain, sizeof(plain), key, sizeof(key));
	test_sm4_blkcipher("cbc(sm4)", cbcplain, sizeof(cbcplain),
				key, sizeof(key));
	test_sm4_skcipher("cbc(sm4)", cbcplain, sizeof(cbcplain),
				key, sizeof(key));
	test_sm4_blkcipher("ecb(sm4)", cbcplain, sizeof(cbcplain),
				key, sizeof(key));
	test_sm4_blkcipher("cfb(sm4)", cbcplain, sizeof(cbcplain),
				key, sizeof(key));
	test_sm4_blkcipher("ctr(sm4)", cbcplain, sizeof(cbcplain),
				key, sizeof(key));
	test_sm4_blkcipher("cts(cbc(sm4))", cbcplain, sizeof(cbcplain),
				key, sizeof(key));
	test_sm4_skcipher("cts(cbc(sm4))", cbcplain, sizeof(cbcplain),
				key, sizeof(key));
	test_sm4_blkcipher("ofb(sm4)", cbcplain, sizeof(cbcplain),
				key, sizeof(key));
	test_sm4_skcipher("ofb(sm4)", cbcplain, sizeof(cbcplain),
				key, sizeof(key));
	test_sm4_blkcipher("pcbc(sm4)", cbcplain, sizeof(cbcplain),
				key, sizeof(key));
	test_sm4_skcipher("pcbc(sm4)", cbcplain, sizeof(cbcplain),
				key, sizeof(key));
	test_sm4_blkcipher("lrw(sm4)", cbcplain, sizeof(cbcplain),
				lrwkey, sizeof(lrwkey));
	test_sm4_skcipher("lrw(sm4)", cbcplain, sizeof(cbcplain),
				lrwkey, sizeof(lrwkey));
	test_sm4_blkcipher("xts(sm4)", cbcplain, sizeof(cbcplain),
				xtskey, sizeof(xtskey));
	test_sm4_skcipher("xts(sm4)", cbcplain, sizeof(cbcplain),
				xtskey, sizeof(xtskey));

	/* -1, no need rmmod cmd when next insmod the ko */
	return -1;
}

static void __exit sm34_exit(void)
{

}

module_init(sm34_init);
module_exit(sm34_exit);
MODULE_LICENSE("GPL");

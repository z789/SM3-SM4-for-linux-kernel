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

static int __init sm34_init(void)
{
	char cbcplain[64] = "0123456789abcdef0123456789abcdef...";

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

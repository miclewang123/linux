#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/kthread.h>
#include <linux/version.h>

#include <crypto/sm4.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/crypto.h>
#include <crypto/algapi.h>
#include <asm/byteorder.h>
#include <asm/unaligned.h>

#include <crypto/internal/hash.h>
#include <linux/mm.h>
#include <crypto/sm3.h>
#include <crypto/sm3_base.h>
#include <linux/bitops.h>

#include "swcsm36.h"

///////////////// sm4 //////////////////////////////////////
#if 1
	#if 1
static const u32 fk[4] = {
	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

static const u8 sbox[256] = {
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

static const u32 ck[] = {
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

static u32 sm4_t_non_lin_sub(u32 x)
{
	int i;
	u8 *b = (u8 *)&x;

	for (i = 0; i < 4; ++i)
		b[i] = sbox[b[i]];

	return x;
}

static u32 sm4_key_lin_sub(u32 x)
{
	return x ^ rol32(x, 13) ^ rol32(x, 23);

}

static u32 sm4_enc_lin_sub(u32 x)
{
	return x ^ rol32(x, 2) ^ rol32(x, 10) ^ rol32(x, 18) ^ rol32(x, 24);
}

static u32 sm4_key_sub(u32 x)
{
	return sm4_key_lin_sub(sm4_t_non_lin_sub(x));
}

static u32 sm4_enc_sub(u32 x)
{
	return sm4_enc_lin_sub(sm4_t_non_lin_sub(x));
}

static u32 sm4_round(const u32 *x, const u32 rk)
{
	return x[0] ^ sm4_enc_sub(x[1] ^ x[2] ^ x[3] ^ rk);
}
	#endif

/**
 * crypto_sm4_expand_key - Expands the SM4 key as described in GB/T 32907-2016
 * @ctx:	The location where the computed key will be stored.
 * @in_key:	The supplied key.
 * @key_len:	The length of the supplied key.
 *
 * Returns 0 on success. The function fails only if an invalid key size (or
 * pointer) is supplied.
 */
int crypto_sm4_expand_key(struct crypto_sm4_ctx *ctx, const u8 *in_key,
			  unsigned int key_len)
{
	u32 rk[4], t;
	const u32 *key = (u32 *)in_key;
	int i;

	if (key_len != SM4_KEY_SIZE)
		return -EINVAL;

	for (i = 0; i < 4; ++i)
		rk[i] = get_unaligned_be32(&key[i]) ^ fk[i];

	for (i = 0; i < 32; ++i) {
		t = rk[0] ^ sm4_key_sub(rk[1] ^ rk[2] ^ rk[3] ^ ck[i]);
		ctx->rkey_enc[i] = t;
		rk[0] = rk[1];
		rk[1] = rk[2];
		rk[2] = rk[3];
		rk[3] = t;
	}

	for (i = 0; i < 32; ++i)
		ctx->rkey_dec[i] = ctx->rkey_enc[31 - i];

	return 0;
}
// EXPORT_SYMBOL_GPL(crypto_sm4_expand_key);

/**
 * crypto_sm4_set_key - Set the SM4 key.
 * @tfm:	The %crypto_tfm that is used in the context.
 * @in_key:	The input key.
 * @key_len:	The size of the key.
 *
 * This function uses crypto_sm4_expand_key() to expand the key.
 * &crypto_sm4_ctx _must_ be the private data embedded in @tfm which is
 * retrieved with crypto_tfm_ctx().
 *
 * Return: 0 on success; -EINVAL on failure (only happens for bad key lengths)
 */
int crypto_sm4_set_key(struct crypto_tfm *tfm, const u8 *in_key,
		       unsigned int key_len)
{
	struct crypto_sm4_ctx *ctx = crypto_tfm_ctx(tfm);

	return crypto_sm4_expand_key(ctx, in_key, key_len);
}
// EXPORT_SYMBOL_GPL(crypto_sm4_set_key);

static void sm4_do_crypt(const u32 *rk, u32 *out, const u32 *in)
{
	u32 x[4], i, t;

	for (i = 0; i < 4; ++i)
		x[i] = get_unaligned_be32(&in[i]);

	for (i = 0; i < 32; ++i) {
		t = sm4_round(x, rk[i]);
		x[0] = x[1];
		x[1] = x[2];
		x[2] = x[3];
		x[3] = t;
	}

	for (i = 0; i < 4; ++i)
		put_unaligned_be32(x[3 - i], &out[i]);
}

/* encrypt a block of text */

void crypto_sm4_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct crypto_sm4_ctx *ctx = crypto_tfm_ctx(tfm);

	sm4_do_crypt(ctx->rkey_enc, (u32 *)out, (u32 *)in);
}
// EXPORT_SYMBOL_GPL(crypto_sm4_encrypt);

/* decrypt a block of text */

void crypto_sm4_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct crypto_sm4_ctx *ctx = crypto_tfm_ctx(tfm);

	sm4_do_crypt(ctx->rkey_dec, (u32 *)out, (u32 *)in);
}
// EXPORT_SYMBOL_GPL(crypto_sm4_decrypt);

static struct crypto_alg sm4_alg = {
	.cra_name		=	"sm4",
	.cra_driver_name	=	"sm4-generic",
	.cra_priority		=	100,
	.cra_flags		=	CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		=	SM4_BLOCK_SIZE,
	.cra_ctxsize		=	sizeof(struct crypto_sm4_ctx),
	.cra_module		=	THIS_MODULE,
	.cra_u			=	{
		.cipher = {
			.cia_min_keysize	=	SM4_KEY_SIZE,
			.cia_max_keysize	=	SM4_KEY_SIZE,
			.cia_setkey		=	crypto_sm4_set_key,
			.cia_encrypt		=	crypto_sm4_encrypt,
			.cia_decrypt		=	crypto_sm4_decrypt
		}
	}
};
#endif
///////////////// sm3 //////////////////////////////////////
#if 1
#if 0
const u8 sm3_zero_message_hash[SM3_DIGEST_SIZE] = {
	0x1A, 0xB2, 0x1D, 0x83, 0x55, 0xCF, 0xA1, 0x7F,
	0x8e, 0x61, 0x19, 0x48, 0x31, 0xE8, 0x1A, 0x8F,
	0x22, 0xBE, 0xC8, 0xC7, 0x28, 0xFE, 0xFB, 0x74,
	0x7E, 0xD0, 0x35, 0xEB, 0x50, 0x82, 0xAA, 0x2B
};
//EXPORT_SYMBOL_GPL(sm3_zero_message_hash);

static inline u32 p0(u32 x)
{
	return x ^ rol32(x, 9) ^ rol32(x, 17);
}

static inline u32 p1(u32 x)
{
	return x ^ rol32(x, 15) ^ rol32(x, 23);
}

static inline u32 ff(unsigned int n, u32 a, u32 b, u32 c)
{
	return (n < 16) ? (a ^ b ^ c) : ((a & b) | (a & c) | (b & c));
}

static inline u32 gg(unsigned int n, u32 e, u32 f, u32 g)
{
	return (n < 16) ? (e ^ f ^ g) : ((e & f) | ((~e) & g));
}

static inline u32 t(unsigned int n)
{
	return (n < 16) ? SM3_T1 : SM3_T2;
}

static void sm3_expand(u32 *t, u32 *w, u32 *wt)
{
	int i;
	unsigned int tmp;

	/* load the input */
	for (i = 0; i <= 15; i++)
		w[i] = get_unaligned_be32((__u32 *)t + i);

	for (i = 16; i <= 67; i++) {
		tmp = w[i - 16] ^ w[i - 9] ^ rol32(w[i - 3], 15);
		w[i] = p1(tmp) ^ (rol32(w[i - 13], 7)) ^ w[i - 6];
	}

	for (i = 0; i <= 63; i++)
		wt[i] = w[i] ^ w[i + 4];
}

static void sm3_compress(u32 *w, u32 *wt, u32 *m)
{
	u32 ss1;
	u32 ss2;
	u32 tt1;
	u32 tt2;
	u32 a, b, c, d, e, f, g, h;
	int i;

	a = m[0];
	b = m[1];
	c = m[2];
	d = m[3];
	e = m[4];
	f = m[5];
	g = m[6];
	h = m[7];

	for (i = 0; i <= 63; i++) {

		ss1 = rol32((rol32(a, 12) + e + rol32(t(i), i & 31)), 7);

		ss2 = ss1 ^ rol32(a, 12);

		tt1 = ff(i, a, b, c) + d + ss2 + *wt;
		wt++;

		tt2 = gg(i, e, f, g) + h + ss1 + *w;
		w++;

		d = c;
		c = rol32(b, 9);
		b = a;
		a = tt1;
		h = g;
		g = rol32(f, 19);
		f = e;
		e = p0(tt2);
	}

	m[0] = a ^ m[0];
	m[1] = b ^ m[1];
	m[2] = c ^ m[2];
	m[3] = d ^ m[3];
	m[4] = e ^ m[4];
	m[5] = f ^ m[5];
	m[6] = g ^ m[6];
	m[7] = h ^ m[7];

	a = b = c = d = e = f = g = h = ss1 = ss2 = tt1 = tt2 = 0;
}

static void sm3_transform(struct sm3_state *sst, u8 const *src)
{
	unsigned int w[68];
	unsigned int wt[64];

	sm3_expand((u32 *)src, w, wt);
	sm3_compress(w, wt, sst->state);

	memzero_explicit(w, sizeof(w));
	memzero_explicit(wt, sizeof(wt));
}

static void sm3_generic_block_fn(struct sm3_state *sst, u8 const *src,
				    int blocks)
{
	while (blocks--) {
		sm3_transform(sst, src);
		src += SM3_BLOCK_SIZE;
	}
}
#endif

#if 0
	SM3_CONTEXT SM3Context;	 
	ECCrefPublicKey pubkey;
	
	unsigned char bHashData[64] = {0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
								   0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
								   0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
								   0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64};
	unsigned char bHashStdResult64[32] = {0xde,0xbe,0x9f,0xf9,0x22,0x75,0xb8,0xa1,0x38,0x60,0x48,0x89,0xc1,0x8e,0x5a,0x4d,
										  0x6f,0xdb,0x70,0xe5,0x38,0x7e,0x57,0x65,0x29,0x3d,0xcb,0xa3,0x9c,0x0c,0x57,0x32};
										  	
	unsigned char x[32] = {0xec,0x37,0xa5,0xa6,0xdb,0x31,0x01,0xec,0xfc,0x39,0x08,0xc9,0xce,0x1f,0xfe,0x7b,
						   0x69,0xe6,0x8a,0x8c,0x3d,0x07,0x31,0x25,0xc4,0x18,0xa3,0x8a,0xd3,0x21,0x91,0x44};
												
	unsigned char y[32] = {0x8d,0xa4,0x75,0x85,0xb4,0x3b,0xba,0xda,0x6b,0x4b,0xbe,0xe8,0x94,0xa2,0x38,0xe6,
						   0x00,0xf0,0x29,0xb6,0xe9,0x1c,0x1f,0x33,0x1c,0x38,0x55,0x81,0x04,0xb9,0xcb,0x6e};
							           
	unsigned char bHashStdResult[32] = {0x64,0x9d,0x02,0x0a,0x21,0x2d,0x0e,0x66,0xba,0x3b,0xeb,0xa8,0x85,0xc9,0x4d,0xe6,
										0x54,0x5b,0x15,0x57,0x72,0x8d,0x10,0x96,0xfe,0x7b,0x6c,0xb0,0xb8,0x1f,0x33,0xbd};
	unsigned char bHashStdResultpub[32] = {0x7e,0xa6,0x54,0x4c,0x2b,0x4b,0x6a,0xc7,0xdf,0x9c,0x3f,0x95,0x4b,0xf9,0x3c,0x15,
										   0x8f,0x49,0x44,0x89,0x91,0xbe,0xd5,0xa0,0x6e,0x97,0x48,0xce,0x93,0x73,0x7c,0x54};

	unsigned char bHashResult[32];
	unsigned int rv;
	unsigned int i,plainlen;
	
	pubkey.bits = 256;
	memcpy(pubkey.x,x,32);
	memcpy(pubkey.y,y,32);
		
	plainlen = 8193;
	for(i=0;i<plainlen;i++)
		inbuf1[i] = (i+1)%255;

	rv = Kel_SM3_Init(&SM3Context, &pubkey, "1234567812345678", 16);
	if(rv)
	{
		printk(KERN_ERR"Kel_SM3_Init ERROR[0x%08x]\n", rv);
		return rv;
	}
  
	rv = Kel_SM3_Update(&SM3Context, inbuf1, plainlen);
	if(rv)
	{
		printk(KERN_ERR"Kel_SM3_Update ERROR[0x%08x]\n", rv);
		return rv;
	}

	memset(bHashResult, 0x0, 32);
	rv = Kel_SM3_Final(&SM3Context, bHashResult);
	if(rv)
	{
		printk(KERN_ERR"Kel_SM3_Final ERROR![0x%08x]\n", rv);
		return rv;
	}
#endif

int crypto_sm3_init(struct shash_desc *desc)
{
	SM3_CONTEXT *ctx = shash_desc_ctx(desc);
	//unsigned int rv = Kel_SM3_Init(ctx, &pubkey, "1234567812345678", 16);
	unsigned int rv = Kel_SM3_Init(ctx, 0, 0, 0);
	return rv;
}
//EXPORT_SYMBOL(crypto_sm3_init);

int crypto_sm3_update(struct shash_desc *desc, const u8 *data,
			  unsigned int len)
{
	SM3_CONTEXT *ctx = shash_desc_ctx(desc);
	return Kel_SM3_Update(ctx, (unsigned char*)data, len);
}
//EXPORT_SYMBOL(crypto_sm3_update);

int crypto_sm3_final(struct shash_desc *desc, u8 *out)
{
	SM3_CONTEXT *ctx = shash_desc_ctx(desc);
	return  Kel_SM3_Final(ctx, (unsigned char*)out);
}
//EXPORT_SYMBOL(crypto_sm3_final);

int crypto_sm3_finup(struct shash_desc *desc, const u8 *data,
			unsigned int len, u8 *hash)
{
	SM3_CONTEXT *ctx = shash_desc_ctx(desc);
	if(Kel_SM3_Update(ctx, (unsigned char*)data, len) == 0)
		return Kel_SM3_Final(ctx, (unsigned char*)hash);
	else
		return 1;
}
// EXPORT_SYMBOL(crypto_sm3_finup);

static struct shash_alg sm3_alg = {
	.digestsize	=	SM3_DIGEST_SIZE,
	.init		=	crypto_sm3_init,	//sm3_base_init,
	.update		=	crypto_sm3_update,
	.final		=	crypto_sm3_final,
	.finup		=	crypto_sm3_finup,
	.descsize	=	sizeof(SM3_CONTEXT),		//sizeof(struct sm3_state),
	.base		=	{
		.cra_name	 =	"sm3",
		.cra_driver_name =	"sm3-swxa",
		.cra_blocksize	 =	SM3_BLOCK_SIZE,
		.cra_module	 =	THIS_MODULE,
	}
};
#endif
////////////////////////////////////////////////////////
int mod_init_func(void)
{     
	int ret;

	printk(KERN_ERR "test module begin......\n");

	ret = crypto_register_alg(&sm4_alg);
	if(ret) {
		printk(KERN_ERR "crypto_register_alg(&sm4_alg) failed!\n");
		return -1;
	}
	
	ret = crypto_register_shash(&sm3_alg);
	if(ret) {
		printk(KERN_ERR "crypto_register_shash(&sm3_alg) failed!\n");
		return -1;
	}	
	return 0;
}

void mod_exit_func(void)
{
	printk(KERN_ERR "test module exit........\n");

	crypto_unregister_alg(&sm4_alg);
 	crypto_unregister_shash(&sm3_alg);
}

module_init(mod_init_func);
module_exit(mod_exit_func);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Test of SM3 and SM4 Algorithm");

MODULE_ALIAS_CRYPTO("test");
MODULE_ALIAS_CRYPTO("test-generic");

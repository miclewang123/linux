#ifndef __SM_H__
#define __SM_H__

#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <crypto/internal/hash.h>
#include <linux/crypto.h>

/**
 * struct swxa_blkcipher_op_ctx - cipher operation context
 * @key:	cipher key
 * @iv:		cipher IV
 *
 * Context associated to a cipher operation.
 */
struct swxa_blkcipher_op_ctx {
	u32 key[4];
	u32 iv[4];
};

struct swxa_dev {
	spinlock_t lock;
	struct crypto_queue queue;
	struct crypto_async_request *req;
	struct task_struct *queue_th;
};

struct swxa_ctx {
	const struct swxa_req_ops *ops;
};

struct swxa_req_ops {
	int (*process)(struct crypto_async_request *req);
	void (*step)(struct crypto_async_request *req, struct swxa_ctx *ctx);
};

struct swxa_skcipher_std_req {
	struct swxa_dev  swxadev;
    struct  swxa_blkcipher_op_ctx op;
	u32 size;
	int skip_ctx;
};

struct swxa_skcipher_req {
	struct swxa_skcipher_std_req std;
	int src_nents;
	int dst_nents;
	int errorValue;
};

typedef struct SM3_CONTEXT_st
{
    u32 stateIV[8];	/*state (ABCDEFGH)*/
    u32 count[2];	/*number of bits, modulo 2^64 (lsb first) */
    u8 buffer[64];	/* input buffer */
} SM3_CONTEXT;

typedef struct ECCrefPublicKey_st
{
	u32  bits;
	u8 x[32]; 
	u8 y[32]; 
} ECCrefPublicKey;

/* CESA functions */
struct swxa_dev sw_dev;

extern int Kel_SM4CBCDec(u32 keynum, u8 *key, u32 keylen,u8 *iv, 
						 u8 *inbuf, u32 inlen, u8 *outbuf, u32 *outlen);
	
extern int Kel_SM4CBCEnc(u32 keynum, u8 *key, u32 keylen,u8 *iv, 
						 u8 *inbuf, u32 inlen, u8 *outbuf, u32 *outlen);
extern int Kel_SM4ECBEnc(u32 keynum, u8 *key,u32 keylen, u8 *inbuf,
				  u32 inlen, u8 *outbuf, u32 *outlen);
extern int Kel_SM4ECBDec(u32 keynum, u8 *key,u32 keylen, u8 *inbuf, 
				  u32 inlen, u8 *outbuf, u32 *outlen);				  
extern int Kel_SM1ECBEnc(u32 keynum, u8 *key,u32 keylen, u8 *inbuf, 
				  u32 inlen, u8 *outbuf, u32 *outlen);
extern int Kel_SM1ECBDec(u32 keynum, u8 *key,u32 keylen, u8 *inbuf, 
	           u32 inlen, u8 *outbuf, u32 *outlen);
extern int Kel_SM1CBCEnc(u32 keynum, u8 *key, u32 keylen,u8 *iv, 
	              u8 *inbuf, u32 inlen, u8 *outbuf, u32 *outlen);	           
extern int Kel_SM1CBCDec(u32 keynum, u8 *key, u32 keylen,u8 *iv, 
	              u8 *inbuf, u32 inlen, u8 *outbuf, u32 *outlen);
	              	           		  
extern int Kel_SM3_Init(SM3_CONTEXT *pCtx, ECCrefPublicKey *pucPublicKey, u8  *pucID, u32 uiIDLength);
extern int Kel_SM3_Update(SM3_CONTEXT *pCtx, const u8 *pbData, u32 uiDataLen);
extern int Kel_SM3_Final(SM3_CONTEXT *pCtx, u8 pbResult[32]);								




#define SM3_DIGEST_SIZE	32
#define SM3_BLOCK_SIZE	64

#define SM3_T1		0x79CC4519
#define SM3_T2		0x7A879D8A

#define SM3_IVA		0x7380166f
#define SM3_IVB		0x4914b2b9
#define SM3_IVC		0x172442d7
#define SM3_IVD		0xda8a0600
#define SM3_IVE		0xa96f30bc
#define SM3_IVF		0x163138aa
#define SM3_IVG		0xe38dee4d
#define SM3_IVH		0xb0fb0e4e

extern const u8 sm3_zero_message_hash[SM3_DIGEST_SIZE];

struct sm3_state {
	u32 state[SM3_DIGEST_SIZE / 4];
	u64 count;
	u8 buffer[SM3_BLOCK_SIZE];
};

struct shash_desc;

extern int crypto_sm3_update(struct shash_desc *desc, const u8 *data, u32 len);

extern int crypto_sm3_finup(struct shash_desc *desc, const u8 *data, u32 len, u8 *hash);
			     
			     
			    
typedef void (sm3_block_fn)(struct sm3_state *sst, u8 const *src, int blocks);

static inline int sm3_base_init(struct shash_desc *desc)
{
	struct sm3_state *sctx = shash_desc_ctx(desc);

	sctx->state[0] = SM3_IVA;
	sctx->state[1] = SM3_IVB;
	sctx->state[2] = SM3_IVC;
	sctx->state[3] = SM3_IVD;
	sctx->state[4] = SM3_IVE;
	sctx->state[5] = SM3_IVF;
	sctx->state[6] = SM3_IVG;
	sctx->state[7] = SM3_IVH;
	sctx->count = 0;

	return 0;
}

static inline int sm3_base_do_update(struct shash_desc *desc,
				      const u8 *data,
				      u32 len,
				      sm3_block_fn *block_fn)
{
	struct sm3_state *sctx = shash_desc_ctx(desc);
	u32 partial = sctx->count % SM3_BLOCK_SIZE;

	sctx->count += len;

	if (unlikely((partial + len) >= SM3_BLOCK_SIZE)) {
		int blocks;

		if (partial) {
			int p = SM3_BLOCK_SIZE - partial;

			memcpy(sctx->buffer + partial, data, p);
			data += p;
			len -= p;

			block_fn(sctx, sctx->buffer, 1);
		}

		blocks = len / SM3_BLOCK_SIZE;
		len %= SM3_BLOCK_SIZE;

		if (blocks) {
			block_fn(sctx, data, blocks);
			data += blocks * SM3_BLOCK_SIZE;
		}
		partial = 0;
	}
	if (len)
		memcpy(sctx->buffer + partial, data, len);

	return 0;
}

static inline int sm3_base_do_finalize(struct shash_desc *desc,
					sm3_block_fn *block_fn)
{
	const int bit_offset = SM3_BLOCK_SIZE - sizeof(__be64);
	struct sm3_state *sctx = shash_desc_ctx(desc);
	__be64 *bits = (__be64 *)(sctx->buffer + bit_offset);
	u32 partial = sctx->count % SM3_BLOCK_SIZE;

	sctx->buffer[partial++] = 0x80;
	if (partial > bit_offset) {
		memset(sctx->buffer + partial, 0x0, SM3_BLOCK_SIZE - partial);
		partial = 0;

		block_fn(sctx, sctx->buffer, 1);
	}

	memset(sctx->buffer + partial, 0x0, bit_offset - partial);
	*bits = cpu_to_be64(sctx->count << 3);
	block_fn(sctx, sctx->buffer, 1);

	return 0;
}

static inline int sm3_base_finish(struct shash_desc *desc, u8 *out)
{
	struct sm3_state *sctx = shash_desc_ctx(desc);
	__be32 *digest = (__be32 *)out;
	int i;

	for (i = 0; i < SM3_DIGEST_SIZE / sizeof(__be32); i++)
		put_unaligned_be32(sctx->state[i], digest++);

	*sctx = (struct sm3_state){};
	return 0;
} 



#endif /* __SM_H__ */

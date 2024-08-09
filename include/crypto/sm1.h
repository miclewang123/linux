/* SPDX-License-Identifier: GPL-2.0 */

/*sm1
 * Common values for the SM1 algorithm
 * Copyright (C) 2018 ARM Limited or its affiliates.
 */

#ifndef _CRYPTO_SM1_H
#define _CRYPTO_SM1_H

#include <linux/types.h>
#include <linux/crypto.h>

#define SM1_KEY_SIZE	16
#define SM1_BLOCK_SIZE	16
#define SM1_RKEY_WORDS	32

struct crypto_sm1_ctx {
	u32 rkey_enc[SM1_RKEY_WORDS];
	u32 rkey_dec[SM1_RKEY_WORDS];
};

int crypto_sm1_set_key(struct crypto_tfm *tfm, const u8 *in_key,
		       unsigned int key_len);
int crypto_sm1_expand_key(struct crypto_sm1_ctx *ctx, const u8 *in_key,
			  unsigned int key_len);

void crypto_sm1_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in);
void crypto_sm1_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in);

#endif

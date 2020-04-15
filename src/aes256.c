/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <bearssl.h>

#include <string.h>

#include "fido.h"

int
aes256_cbc_enc(const fido_blob_t *key, const fido_blob_t *in, fido_blob_t *out)
{
	br_aes_ct64_cbcenc_keys	ctx;
	unsigned char	 	iv[32];
	int		 	ok = -1;

	memset(iv, 0, sizeof(iv));
	out->ptr = NULL;
	out->len = 0;

	/* sanity check */
	if ((in->len % 16) != 0 || (out->ptr = calloc(1, in->len)) == NULL) {
		fido_log_debug("%s: in->len=%zu", __func__, in->len);
		goto fail;
	}
	if (key->len != 32) {
		fido_log_debug("%s: key->len=%zu", __func__, key->len);
		goto fail;
	}

	memcpy(out->ptr, in->ptr, in->len);
	br_aes_ct64_cbcenc_init(&ctx, key->ptr, key->len);
	br_aes_ct64_cbcenc_run(&ctx, iv, out->ptr, out->len);
	explicit_bzero(&ctx, sizeof(ctx));

	out->len = in->len;

	ok = 0;
fail:
	if (ok < 0) {
		free(out->ptr);
		out->ptr = NULL;
		out->len = 0;
	}

	return (ok);
}

int
aes256_cbc_dec(const fido_blob_t *key, const fido_blob_t *in, fido_blob_t *out)
{
	br_aes_ct64_cbcdec_keys	 ctx;
	unsigned char		 iv[32];
	int			 ok = -1;

	memset(iv, 0, sizeof(iv));
	out->ptr = NULL;
	out->len = 0;

	/* sanity check */
	if ((in->len % 16) != 0 || (out->ptr = calloc(1, in->len)) == NULL) {
		fido_log_debug("%s: in->len=%zu", __func__, in->len);
		goto fail;
	}
	if (key->len != 32) {
		fido_log_debug("%s: key->len=%zu", __func__, key->len);
		goto fail;
	}

	memcpy(out->ptr, in->ptr, in->len);
	br_aes_ct64_cbcdec_init(&ctx, key->ptr, key->len);
	br_aes_ct64_cbcdec_run(&ctx, iv, out->ptr, out->len);
	explicit_bzero(&ctx, sizeof(ctx));

	out->len = in->len;

	ok = 0;
fail:
	if (ok < 0) {
		free(out->ptr);
		out->ptr = NULL;
		out->len = 0;
	}

	return (ok);
}

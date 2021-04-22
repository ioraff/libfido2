/*
 * Copyright (c) 2021 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <bearssl.h>

#include "fido.h"

static int
aes256_cbc(const fido_blob_t *key, const u_char *iv, const fido_blob_t *in,
    fido_blob_t *out, int encrypt)
{
	union {
		br_aes_ct64_cbcenc_keys enc;
		br_aes_ct64_cbcdec_keys dec;
	} ctx;
	u_char civ[16];
	int ok = -1;

	memset(out, 0, sizeof(*out));

	if (key->len != 32) {
		fido_log_debug("%s: invalid key len %zu", __func__, key->len);
		goto fail;
	}
	if (in->len % 16 || in->len == 0) {
		fido_log_debug("%s: invalid input len %zu", __func__, in->len);
		goto fail;
	}
	out->len = in->len;
	if ((out->ptr = calloc(1, out->len)) == NULL) {
		fido_log_debug("%s: calloc", __func__);
		goto fail;
	}
	memcpy(out->ptr, in->ptr, in->len);
	memcpy(civ, iv, sizeof(civ));
	if (encrypt) {
		br_aes_ct64_cbcenc_init(&ctx.enc, key->ptr, key->len);
		br_aes_ct64_cbcenc_run(&ctx.enc, civ, out->ptr, out->len);
	} else {
		br_aes_ct64_cbcdec_init(&ctx.dec, key->ptr, key->len);
		br_aes_ct64_cbcdec_run(&ctx.dec, civ, out->ptr, out->len);
	}
	explicit_bzero(&ctx, sizeof(ctx));

	ok = 0;
fail:
	if (ok < 0)
		fido_blob_reset(out);

	return ok;
}

static int
aes256_cbc_proto1(const fido_blob_t *key, const fido_blob_t *in,
    fido_blob_t *out, int encrypt)
{
	u_char iv[16];

	memset(&iv, 0, sizeof(iv));

	return aes256_cbc(key, iv, in, out, encrypt);
}

static int
aes256_cbc_fips(const fido_blob_t *secret, const fido_blob_t *in,
    fido_blob_t *out, int encrypt)
{
	fido_blob_t key, cin, cout;
	u_char iv[16];

	memset(out, 0, sizeof(*out));

	if (secret->len != 64) {
		fido_log_debug("%s: invalid secret len %zu", __func__,
		    secret->len);
		return -1;
	}
	if (in->len < sizeof(iv)) {
		fido_log_debug("%s: invalid input len %zu", __func__, in->len);
		return -1;
	}
	if (encrypt) {
		if (fido_get_random(iv, sizeof(iv)) < 0) {
			fido_log_debug("%s: fido_get_random", __func__);
			return -1;
		}
		cin = *in;
	} else {
		memcpy(iv, in->ptr, sizeof(iv));
		cin.ptr = in->ptr + sizeof(iv);
		cin.len = in->len - sizeof(iv);
	}
	key.ptr = secret->ptr + 32;
	key.len = secret->len - 32;
	if (aes256_cbc(&key, iv, &cin, &cout, encrypt) < 0)
		return -1;
	if (encrypt) {
		if (cout.len > SIZE_MAX - sizeof(iv) ||
		    (out->ptr = calloc(1, sizeof(iv) + cout.len)) == NULL) {
			fido_blob_reset(&cout);
			return -1;
		}
		out->len = sizeof(iv) + cout.len;
		memcpy(out->ptr, iv, sizeof(iv));
		memcpy(out->ptr + sizeof(iv), cout.ptr, cout.len);
		fido_blob_reset(&cout);
	} else
		*out = cout;

	return 0;
}

static int
aes256_gcm(const fido_blob_t *key, const fido_blob_t *nonce,
    const fido_blob_t *aad, const fido_blob_t *in, fido_blob_t *out,
    int encrypt)
{
	br_gcm_context ctx;
	br_aes_ct64_ctr_keys ctr;
	size_t textlen;
	int ok = -1;

	memset(out, 0, sizeof(*out));

	if (nonce->len != 12 || key->len != 32) {
		fido_log_debug("%s: invalid params %zu, %zu, %zu", __func__,
		    nonce->len, key->len, aad->len);
		goto fail;
	}
	if (in->len > SIZE_MAX - 16 || in->len < 16) {
		fido_log_debug("%s: invalid input len %zu", __func__, in->len);
		goto fail;
	}
	/* add tag to (on encrypt) or trim tag from the output (on decrypt) */
	out->len = encrypt ? in->len + 16 : in->len - 16;
	if ((out->ptr = calloc(1, out->len)) == NULL) {
		fido_log_debug("%s: calloc", __func__);
		goto fail;
	}
	br_aes_ct64_ctr_init(&ctr, key->ptr, key->len);
	br_gcm_init(&ctx, &ctr.vtable, br_ghash_ctmul64);
	br_gcm_reset(&ctx, nonce->ptr, nonce->len);

	if (encrypt)
		textlen = in->len;
	else
		textlen = in->len - 16;
	br_gcm_aad_inject(&ctx, aad->ptr, aad->len);
	br_gcm_flip(&ctx);
	memcpy(out->ptr, in->ptr, textlen);
	br_gcm_run(&ctx, encrypt, out->ptr, textlen);
	if (encrypt) {
		/* append the mac tag */
		br_gcm_get_tag(&ctx, out->ptr + out->len - 16);
	} else if (!br_gcm_check_tag(&ctx, in->ptr + in->len - 16)) {
		fido_log_debug("%s: AES-GCM tag mismatch", __func__);
		goto fail;
	}

	ok = 0;
fail:
	explicit_bzero(&ctx, sizeof(ctx));
	explicit_bzero(&ctr, sizeof(ctr));
	if (ok < 0)
		fido_blob_reset(out);

	return ok;
}

int
aes256_cbc_enc(const fido_dev_t *dev, const fido_blob_t *secret,
    const fido_blob_t *in, fido_blob_t *out)
{
	return fido_dev_get_pin_protocol(dev) == 2 ? aes256_cbc_fips(secret,
	    in, out, 1) : aes256_cbc_proto1(secret, in, out, 1);
}

int
aes256_cbc_dec(const fido_dev_t *dev, const fido_blob_t *secret,
    const fido_blob_t *in, fido_blob_t *out)
{
	return fido_dev_get_pin_protocol(dev) == 2 ? aes256_cbc_fips(secret,
	    in, out, 0) : aes256_cbc_proto1(secret, in, out, 0);
}

int
aes256_gcm_enc(const fido_blob_t *key, const fido_blob_t *nonce,
    const fido_blob_t *aad, const fido_blob_t *in, fido_blob_t *out)
{
	return aes256_gcm(key, nonce, aad, in, out, 1);
}

int
aes256_gcm_dec(const fido_blob_t *key, const fido_blob_t *nonce,
    const fido_blob_t *aad, const fido_blob_t *in, fido_blob_t *out)
{
	return aes256_gcm(key, nonce, aad, in, out, 0);
}

/*
 * Copyright (c) 2018-2021 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <bearssl.h>

#include "fido.h"
#include "fido/es256.h"

static int
hkdf_sha256(uint8_t *key, const char *info, const fido_blob_t *secret)
{
	br_hkdf_context ctx;
	uint8_t salt[32];

	memset(salt, 0, sizeof(salt));
	br_hkdf_init(&ctx, &br_sha256_vtable, salt, sizeof(salt));
	br_hkdf_inject(&ctx, secret->ptr, secret->len);
	br_hkdf_flip(&ctx);
	br_hkdf_produce(&ctx, info, strlen(info), key, br_sha256_SIZE);
	explicit_bzero(&ctx, sizeof(ctx));

	return 0;
}

static int
kdf(uint8_t prot, fido_blob_t *key, /* const */ fido_blob_t *secret)
{
	br_sha256_context ctx;
	char hmac_info[] = "CTAP2 HMAC key"; /* const */
	char aes_info[] = "CTAP2 AES key"; /* const */

	switch (prot) {
	case CTAP_PIN_PROTOCOL1:
		/* use sha256 on the resulting secret */
		key->len = br_sha256_SIZE;
		if ((key->ptr = calloc(1, key->len)) == NULL) {
			fido_log_debug("%s: SHA256", __func__);
			return -1;
		}
		br_sha256_init(&ctx);
		br_sha256_update(&ctx, secret->ptr, secret->len);
		br_sha256_out(&ctx, key->ptr);
		explicit_bzero(&ctx, sizeof(ctx));
		break;
	case CTAP_PIN_PROTOCOL2:
		/* use two instances of hkdf-sha256 on the resulting secret */
		key->len = 2 * br_sha256_SIZE;
		if ((key->ptr = calloc(1, key->len)) == NULL ||
		    hkdf_sha256(key->ptr, hmac_info, secret) < 0 ||
		    hkdf_sha256(key->ptr + br_sha256_SIZE, aes_info,
		    secret) < 0) {
			fido_log_debug("%s: hkdf", __func__);
			return -1;
		}
		break;
	default:
		fido_log_debug("%s: unknown pin protocol %u", __func__, prot);
		return -1;
	}

	return 0;
}

static int
do_ecdh(const fido_dev_t *dev, const es256_sk_t *sk, const es256_pk_t *pk,
    fido_blob_t **ecdh)
{
	const br_ec_impl *ec;
	unsigned char q[65];
	fido_blob_t secret;
	int ok = -1;

	if ((*ecdh = fido_blob_new()) == NULL)
		goto fail;

	q[0] = 4;
	memcpy(q + 1, pk->x, 32);
	memcpy(q + 1 + 32, pk->y, 32);

	ec = br_ec_get_default();
	if ((ec->supported_curves & 1 << BR_EC_secp256r1) == 0 ||
	    ec->mul(q, sizeof(q), sk->d, sizeof(sk->d), BR_EC_secp256r1) != 1) {
		fido_log_debug("%s: ECDH", __func__);
		goto fail;
	}
	secret.ptr = q + ec->xoff(BR_EC_secp256r1, &secret.len);

	if (kdf(fido_dev_get_pin_protocol(dev), *ecdh, &secret) < 0) {
		fido_log_debug("%s: kdf", __func__);
		goto fail;
	}

	ok = 0;
fail:
	explicit_bzero(q, sizeof(q));
	if (ok < 0)
		fido_blob_free(ecdh);

	return ok;
}

int
fido_do_ecdh(fido_dev_t *dev, es256_pk_t **pk, fido_blob_t **ecdh)
{
	es256_sk_t *sk = NULL; /* our private key */
	es256_pk_t *ak = NULL; /* authenticator's public key */
	int r;

	*pk = NULL;
	*ecdh = NULL;
	if ((sk = es256_sk_new()) == NULL || (*pk = es256_pk_new()) == NULL) {
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}
	if (es256_sk_create(sk) < 0 || es256_derive_pk(sk, *pk) < 0) {
		fido_log_debug("%s: es256_derive_pk", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}
	if ((ak = es256_pk_new()) == NULL ||
	    fido_dev_authkey(dev, ak) != FIDO_OK) {
		fido_log_debug("%s: fido_dev_authkey", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}
	if (do_ecdh(dev, sk, ak, ecdh) < 0) {
		fido_log_debug("%s: do_ecdh", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	r = FIDO_OK;
fail:
	es256_sk_free(&sk);
	es256_pk_free(&ak);

	if (r != FIDO_OK) {
		es256_pk_free(pk);
		fido_blob_free(ecdh);
	}

	return r;
}

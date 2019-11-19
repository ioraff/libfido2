/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <bearssl.h>

#include "fido.h"
#include "fido/es256.h"

static int
do_ecdh(const es256_sk_t *sk, const es256_pk_t *pk, fido_blob_t **ecdh)
{
	unsigned char		 q[65];
	const br_ec_impl	*ec;
	br_sha256_context	 ctx;
	size_t			 xoff, xlen;
	int			 ok = -1;

	*ecdh = NULL;

	/* allocate blobs for secret & ecdh */
	if ((*ecdh = fido_blob_new()) == NULL)
		goto fail;

	q[0] = 4;
	memcpy(q + 1, pk->x, 32);
	memcpy(q + 1 + 32, pk->y, 32);

	/* perform ecdh */
	ec = br_ec_get_default();
	if ((ec->supported_curves & 1 << BR_EC_secp256r1) == 0 ||
	    ec->mul(q, sizeof(q), sk->d, sizeof(sk->d), BR_EC_secp256r1) != 1) {
		fido_log_debug("%s: ECDH", __func__);
		goto fail;
	}

	/* use sha256 as a kdf on the resulting secret */
	(*ecdh)->len = br_sha256_SIZE;
	if (((*ecdh)->ptr = calloc(1, (*ecdh)->len)) == NULL) {
		fido_log_debug("%s: sha256", __func__);
		goto fail;
	}
	xoff = ec->xoff(BR_EC_secp256r1, &xlen);
	br_sha256_init(&ctx);
	br_sha256_update(&ctx, q + xoff, xlen);
	br_sha256_out(&ctx, (*ecdh)->ptr);

	ok = 0;
fail:
	explicit_bzero(q, sizeof(q));
	if (ok < 0)
		fido_blob_free(ecdh);

	return (ok);
}

int
fido_do_ecdh(fido_dev_t *dev, es256_pk_t **pk, fido_blob_t **ecdh)
{
	es256_sk_t	*sk = NULL; /* our private key */
	es256_pk_t	*ak = NULL; /* authenticator's public key */
	int		 r;

	*pk = NULL; /* our public key; returned */
	*ecdh = NULL; /* shared ecdh secret; returned */

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

	if (do_ecdh(sk, ak, ecdh) < 0) {
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

	return (r);
}

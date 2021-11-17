/*
 * Copyright (c) 2018-2021 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <bearssl.h>

#include "fido.h"
#include "fido/rs256.h"

static int
decode_bignum(const cbor_item_t *item, void *ptr, size_t len)
{
	if (cbor_isa_bytestring(item) == false ||
	    cbor_bytestring_is_definite(item) == false ||
	    cbor_bytestring_length(item) != len) {
		fido_log_debug("%s: cbor type", __func__);
		return (-1);
	}

	memcpy(ptr, cbor_bytestring_handle(item), len);

	return (0);
}

static int
decode_rsa_pubkey(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	rs256_pk_t *k = arg;

	if (cbor_isa_negint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8)
		return (0); /* ignore */

	switch (cbor_get_uint8(key)) {
	case 0: /* modulus */
		return (decode_bignum(val, &k->n, sizeof(k->n)));
	case 1: /* public exponent */
		return (decode_bignum(val, &k->e, sizeof(k->e)));
	}

	return (0); /* ignore */
}

int
rs256_pk_decode(const cbor_item_t *item, rs256_pk_t *k)
{
	if (cbor_isa_map(item) == false ||
	    cbor_map_is_definite(item) == false ||
	    cbor_map_iter(item, k, decode_rsa_pubkey) < 0) {
		fido_log_debug("%s: cbor type", __func__);
		return (-1);
	}

	return (0);
}

rs256_pk_t *
rs256_pk_new(void)
{
	return (calloc(1, sizeof(rs256_pk_t)));
}

void
rs256_pk_free(rs256_pk_t **pkp)
{
	rs256_pk_t *pk;

	if (pkp == NULL || (pk = *pkp) == NULL)
		return;

	freezero(pk, sizeof(*pk));
	*pkp = NULL;
}

int
rs256_pk_from_ptr(rs256_pk_t *pk, const void *ptr, size_t len)
{
	if (len < sizeof(*pk))
		return (FIDO_ERR_INVALID_ARGUMENT);

	memcpy(pk, ptr, sizeof(*pk));

	return (FIDO_OK);
}

int
rs256_verify_sig(const fido_blob_t *dgst, const br_rsa_public_key *pkey,
    const fido_blob_t *sig)
{
	unsigned char	hash[br_sha256_SIZE];
	int		ok = -1;

	/* RS256 verify needs SHA256-sized hash */
	if (dgst->len != br_sha256_SIZE) {
		fido_log_debug("%s: dgst->len=%zu", __func__, dgst->len);
		return (-1);
	}

	if (br_rsa_pkcs1_vrfy_get_default()(sig->ptr, sig->len,
	    BR_HASH_OID_SHA256, dgst->len, pkey, hash) != 1 ||
	    memcmp(dgst->ptr, hash, sizeof(hash)) != 0) {
		fido_log_debug("%s: RSA verify", __func__);
		goto fail;
	}

	ok = 0;
fail:
	return (ok);
}

int
rs256_pk_verify_sig(const fido_blob_t *dgst, const rs256_pk_t *pk,
    const fido_blob_t *sig)
{
	br_rsa_public_key	pkey;
	int		 	ok = -1;

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
	pkey.n = (unsigned char *)pk->n;
	pkey.nlen = sizeof(pk->n);
	pkey.e = (unsigned char *)pk->e;
	pkey.elen = sizeof(pk->e);
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

	if (rs256_verify_sig(dgst, &pkey, sig) < 0) {
		fido_log_debug("%s: rs256_verify_sig", __func__);
		goto fail;
	}

	ok = 0;
fail:
	return (ok);
}

/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <bearssl.h>

#include <string.h>
#include "fido.h"
#include "fido/es256.h"

static int
decode_coord(const cbor_item_t *item, void *xy, size_t xy_len)
{
	if (cbor_isa_bytestring(item) == false ||
	    cbor_bytestring_is_definite(item) == false ||
	    cbor_bytestring_length(item) != xy_len) {
		fido_log_debug("%s: cbor type", __func__);
		return (-1);
	}

	memcpy(xy, cbor_bytestring_handle(item), xy_len);

	return (0);
}

static int
decode_pubkey_point(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	es256_pk_t *k = arg;

	if (cbor_isa_negint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8)
		return (0); /* ignore */

	switch (cbor_get_uint8(key)) {
	case 1: /* x coordinate */
		return (decode_coord(val, &k->x, sizeof(k->x)));
	case 2: /* y coordinate */
		return (decode_coord(val, &k->y, sizeof(k->y)));
	}

	return (0); /* ignore */
}

int
es256_pk_decode(const cbor_item_t *item, es256_pk_t *k)
{
	if (cbor_isa_map(item) == false ||
	    cbor_map_is_definite(item) == false ||
	    cbor_map_iter(item, k, decode_pubkey_point) < 0) {
		fido_log_debug("%s: cbor type", __func__);
		return (-1);
	}

	return (0);
}

cbor_item_t *
es256_pk_encode(const es256_pk_t *pk, int ecdh)
{
	cbor_item_t		*item = NULL;
	struct cbor_pair	 argv[5];
	int			 alg;
	int			 ok = -1;

	memset(argv, 0, sizeof(argv));

	if ((item = cbor_new_definite_map(5)) == NULL)
		goto fail;

	/* kty */
	if ((argv[0].key = cbor_build_uint8(1)) == NULL ||
	    (argv[0].value = cbor_build_uint8(2)) == NULL ||
	    !cbor_map_add(item, argv[0]))
		goto fail;

	/*
	 * "The COSEAlgorithmIdentifier used is -25 (ECDH-ES +
	 * HKDF-256) although this is NOT the algorithm actually
	 * used. Setting this to a different value may result in
	 * compatibility issues."
	 */
	if (ecdh)
		alg = COSE_ECDH_ES256;
	else
		alg = COSE_ES256;

	/* alg */
	if ((argv[1].key = cbor_build_uint8(3)) == NULL ||
	    (argv[1].value = cbor_build_negint8(-alg - 1)) == NULL ||
	    !cbor_map_add(item, argv[1]))
		goto fail;

	/* crv */
	if ((argv[2].key = cbor_build_negint8(0)) == NULL ||
	    (argv[2].value = cbor_build_uint8(1)) == NULL ||
	    !cbor_map_add(item, argv[2]))
		goto fail;

	/* x */
	if ((argv[3].key = cbor_build_negint8(1)) == NULL ||
	    (argv[3].value = cbor_build_bytestring(pk->x,
	    sizeof(pk->x))) == NULL || !cbor_map_add(item, argv[3]))
		goto fail;

	/* y */
	if ((argv[4].key = cbor_build_negint8(2)) == NULL ||
	    (argv[4].value = cbor_build_bytestring(pk->y,
	    sizeof(pk->y))) == NULL || !cbor_map_add(item, argv[4]))
		goto fail;

	ok = 0;
fail:
	if (ok < 0) {
		if (item != NULL) {
			cbor_decref(&item);
			item = NULL;
		}
	}

	for (size_t i = 0; i < 5; i++) {
		if (argv[i].key)
			cbor_decref(&argv[i].key);
		if (argv[i].value)
			cbor_decref(&argv[i].value);
	}

	return (item);
}

es256_sk_t *
es256_sk_new(void)
{
	return (calloc(1, sizeof(es256_sk_t)));
}

void
es256_sk_free(es256_sk_t **skp)
{
	es256_sk_t *sk;

	if (skp == NULL || (sk = *skp) == NULL)
		return;

	explicit_bzero(sk, sizeof(*sk));
	free(sk);

	*skp = NULL;
}

es256_pk_t *
es256_pk_new(void)
{
	return (calloc(1, sizeof(es256_pk_t)));
}

void
es256_pk_free(es256_pk_t **pkp)
{
	es256_pk_t *pk;

	if (pkp == NULL || (pk = *pkp) == NULL)
		return;

	explicit_bzero(pk, sizeof(*pk));
	free(pk);

	*pkp = NULL;
}

int
es256_pk_from_ptr(es256_pk_t *pk, const void *ptr, size_t len)
{
	if (len < sizeof(*pk))
		return (FIDO_ERR_INVALID_ARGUMENT);

	memcpy(pk, ptr, sizeof(*pk));

	return (FIDO_OK);
}

int
es256_pk_set_x(es256_pk_t *pk, const unsigned char *x)
{
	memcpy(pk->x, x, sizeof(pk->x));

	return (0);
}

int
es256_pk_set_y(es256_pk_t *pk, const unsigned char *y)
{
	memcpy(pk->y, y, sizeof(pk->y));

	return (0);
}

int
es256_sk_create(es256_sk_t *key)
{
	br_prng_seeder		 seeder;
	br_hmac_drbg_context	 rng;
	br_ec_private_key	 skey;
	unsigned char		 kbuf[BR_EC_KBUF_PRIV_MAX_SIZE];
	int			 ok = -1;

	if ((seeder = br_prng_seeder_system(NULL)) == NULL) {
		fido_log_debug("%s: no PRNG seeder", __func__);
		goto fail;
	}
	br_hmac_drbg_init(&rng, &br_sha256_vtable, NULL, 0);
	if (seeder(&rng.vtable) == 0) {
		fido_log_debug("%s: seed PRNG", __func__);
		goto fail;
	}
	if (br_ec_keygen(&rng.vtable, br_ec_get_default(), &skey, kbuf,
	    BR_EC_secp256r1) != sizeof(key->d)) {
		fido_log_debug("%s: EC keygen", __func__);
		goto fail;
	}
	memcpy(key->d, skey.x, sizeof(key->d));
	explicit_bzero(&skey, sizeof(skey));
	explicit_bzero(kbuf, sizeof(kbuf));

	ok = 0;
fail:
	return (ok);
}

int
es256_derive_pk(const es256_sk_t *sk, es256_pk_t *pk)
{
	br_ec_private_key	skey;
	br_ec_public_key 	pkey;
	unsigned char	 	kbuf[BR_EC_KBUF_PUB_MAX_SIZE];
	int		 	ok = -1;

	skey.curve = BR_EC_secp256r1;
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
	skey.x = (unsigned char *)sk->d;
	skey.xlen = sizeof(sk->d);
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
	if (br_ec_compute_pub(br_ec_get_default(), &pkey, kbuf, &skey) != 65 ||
	    pkey.q[0] != 4 ||
	    es256_pk_set_x(pk, pkey.q + 1) != 0 ||
	    es256_pk_set_y(pk, pkey.q + 1 + 32) != 0) {
		fido_log_debug("%s: EC compute pub", __func__);
		goto fail;
	}

	ok = 0;
fail:
	explicit_bzero(kbuf, sizeof(kbuf));

	return (ok);
}

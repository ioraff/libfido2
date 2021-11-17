/*
 * Copyright (c) 2021 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

/*
 * Trusted Platform Module (TPM) 2.0 attestation support. Documentation
 * references are relative to revision 01.38 of the TPM 2.0 specification.
 */

#include <bearssl.h>

#include "fido.h"

/* Part 1, 4.89: TPM_GENERATED_VALUE */
#define TPM_MAGIC	0xff544347

/* Part 2, 6.3: TPM_ALG_ID */
#define TPM_ALG_RSA	0x0001
#define TPM_ALG_SHA256	0x000b
#define TPM_ALG_NULL	0x0010

/* Part 2, 6.9: TPM_ST_ATTEST_CERTIFY */
#define TPM_ST_CERTIFY	0x8017

/* Part 2, 8.3: TPMA_OBJECT */
#define TPMA_RESERVED	0xfff8f309	/* reserved bits; must be zero */
#define TPMA_FIXED	0x00000002	/* object has fixed hierarchy */
#define TPMA_CLEAR	0x00000004	/* object persists */
#define TPMA_FIXED_P	0x00000010	/* object has fixed parent */
#define TPMA_SENSITIVE	0x00000020	/* data originates within tpm */
#define TPMA_SIGN	0x00020000	/* object may sign */

static void
putbe16(unsigned char *buf, uint16_t val)
{
	buf[0] = (unsigned char)(val >> 8 & 0xff);
	buf[1] = (unsigned char)(val & 0xff);
}

static void
putbe32(unsigned char *buf, uint32_t val)
{
	buf[0] = (unsigned char)(val >> 24 & 0xff);
	buf[1] = (unsigned char)(val >> 16 & 0xff);
	buf[2] = (unsigned char)(val >> 8 & 0xff);
	buf[3] = (unsigned char)(val & 0xff);
}

static uint32_t
getbe32(const unsigned char *buf)
{
	uint32_t val;

	val = (uint32_t)buf[0] << 24 | (uint32_t)buf[1] << 16
	    | (uint32_t)buf[2] << 8 | (uint32_t)buf[3];

	return val;
}

static int
check_rsa2048_pubarea(const fido_blob_t *buf, const rs256_pk_t *pk)
{
	const unsigned char	*actual;
	unsigned char		 expected[310];
	uint32_t		 attr;
	int			 ok;

	if (buf->len != sizeof(expected)) {
		fido_log_debug("%s: buf->len=%zu", __func__, buf->len);
		return -1;
	}
	actual = buf->ptr;

	/* Part 2, 12.2.4: TPMT_PUBLIC */
	putbe16(&expected[0], TPM_ALG_RSA);
	putbe16(&expected[2], TPM_ALG_SHA256);
	attr = getbe32(&actual[4]);
	attr &= ~(TPMA_RESERVED|TPMA_CLEAR);
	attr |= (TPMA_FIXED|TPMA_FIXED_P|TPMA_SENSITIVE|TPMA_SIGN);
	putbe32(&expected[4], attr);

	/* Part 2, 10.4.2: TPM2B_DIGEST */
	putbe16(&expected[8], 32);
	memcpy(&expected[10], &actual[10], 32);

	/* Part 2, 12.2.3.5: TPMS_RSA_PARMS */
	putbe16(&expected[42], TPM_ALG_NULL);
	putbe16(&expected[44], TPM_ALG_NULL);
	putbe16(&expected[46], 2048);
	putbe32(&expected[48], 0); /* meaning 2^16+1 */

	/* Part 2, 11.2.4.5: TPM2B_PUBLIC_KEY_RSA */
	putbe16(&expected[52], 256);
	memcpy(&expected[54], &pk->n, 256);

	ok = timingsafe_bcmp(&expected, actual, sizeof(expected));
	explicit_bzero(&expected, sizeof(expected));

	return ok != 0 ? -1 : 0;
}

static int
check_sha1_certinfo(const fido_blob_t *buf, const fido_blob_t *clientdata_hash,
    const fido_blob_t *authdata_raw, const fido_blob_t *pubarea)
{
	const unsigned char	*actual;
	unsigned char		 expected[161];
	br_sha1_context		 sha1;
	br_sha256_context	 sha256;
	int			 ok = -1;

	if (buf->len != sizeof(expected)) {
		fido_log_debug("%s: buf->len=%zu", __func__, buf->len);
		goto fail;
	}
	actual = buf->ptr;

	/* Part 2, 10.12.8 TPMS_ATTEST */
	putbe32(&expected[0], TPM_MAGIC);
	putbe16(&expected[4], TPM_ST_CERTIFY);

	/* Part 2, 10.5.3: TPM2B_NAME */
	putbe16(&expected[6], 34);
	memcpy(&expected[8], &actual[8], 34);

	/* Part 2, 10.4.3: TPM2B_DATA */
	putbe16(&expected[42], 20);
	br_sha1_init(&sha1);
	br_sha1_update(&sha1, authdata_raw->ptr, authdata_raw->len);
	br_sha1_update(&sha1, clientdata_hash->ptr, clientdata_hash->len);
	br_sha1_out(&sha1, &expected[44]);

	/* Part 2, 10.11.1: TPMS_CLOCK_INFO */
	memcpy(&expected[64], &actual[64], 16);
	expected[80] = 1;

	memcpy(&expected[81], &actual[81], 8);

	/* Part 2, 10.5.3: TPM2B_NAME */
	putbe16(&expected[89], 34);
	putbe16(&expected[91], TPM_ALG_SHA256);
	br_sha256_init(&sha256);
	br_sha256_update(&sha256, pubarea->ptr, pubarea->len);
	br_sha256_out(&sha256, &expected[93]);

	/* Part 2, 10.5.3: TPM2B_NAME */
	memcpy(&expected[125], &actual[125], 36);

	ok = timingsafe_bcmp(&expected, actual, sizeof(expected));
fail:
	explicit_bzero(&expected, sizeof(expected));
	explicit_bzero(&sha1, sizeof(sha1));
	explicit_bzero(&sha256, sizeof(sha256));

	return ok != 0 ? -1 : 0;
}

int
fido_get_signed_hash_tpm(fido_blob_t *dgst, const fido_blob_t *clientdata_hash,
    const fido_blob_t *authdata_raw, const fido_attstmt_t *attstmt,
    const fido_attcred_t *attcred)
{
	br_sha1_context sha1;
	const fido_blob_t *pubarea = &attstmt->pubarea;
	const fido_blob_t *certinfo = &attstmt->certinfo;

	if (attstmt->alg != COSE_RS1 || attcred->type != COSE_RS256) {
		fido_log_debug("%s: unsupported alg %d, type %d", __func__,
		    attstmt->alg, attcred->type);
		return -1;
	}

	if (check_rsa2048_pubarea(pubarea, &attcred->pubkey.rs256) < 0) {
		fido_log_debug("%s: check_rsa2048_pubarea", __func__);
		return -1;
	}

	if (check_sha1_certinfo(certinfo, clientdata_hash, authdata_raw,
	    pubarea) < 0) {
		fido_log_debug("%s: check_sha1_certinfo", __func__);
		return -1;
	}

	if (dgst->len < br_sha1_SIZE) {
		fido_log_debug("%s: sha1", __func__);
		return -1;
	}
	br_sha1_init(&sha1);
	br_sha1_update(&sha1, certinfo->ptr, certinfo->len);
	br_sha1_out(&sha1, dgst->ptr);
	dgst->len = br_sha1_SIZE;

	explicit_bzero(&sha1, sizeof(sha1));

	return 0;
}

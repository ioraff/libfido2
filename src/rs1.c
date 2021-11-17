/*
 * Copyright (c) 2021 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <bearssl.h>

#include "fido.h"

int
rs1_verify_sig(const fido_blob_t *dgst, const br_rsa_public_key *pkey,
    const fido_blob_t *sig)
{
	unsigned char	hash[br_sha1_SIZE];
	int		ok = -1;

	/* RS1 verify needs SHA1-sized hash */
	if (dgst->len != br_sha1_SIZE) {
		fido_log_debug("%s: dgst->len=%zu", __func__, dgst->len);
		return (-1);
	}

	if (br_rsa_pkcs1_vrfy_get_default()(sig->ptr, sig->len,
	    BR_HASH_OID_SHA1, dgst->len, pkey, hash) != 1 ||
	    memcmp(dgst->ptr, hash, sizeof(hash)) != 0) {
		fido_log_debug("%s: RSA verify", __func__);
		goto fail;
	}

	ok = 0;
fail:
	return (ok);
}

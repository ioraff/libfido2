/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _FIDO_EDDSA_H
#define _FIDO_EDDSA_H

#include <stdint.h>
#include <stdlib.h>

#ifdef _FIDO_INTERNAL
#include "types.h"
#else
#include <fido.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

eddsa_pk_t *eddsa_pk_new(void);
void eddsa_pk_free(eddsa_pk_t **);

int eddsa_pk_from_ptr(eddsa_pk_t *, const void *, size_t);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* !_FIDO_EDDSA_H */

/*
 * Copyright (c) 2019-2021 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <cbor.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "mutator_aux.h"

extern int prng_up;

/*
 * Build wrappers around functions of interest, and have them fail
 * in a pseudo-random manner.
 */

#define WRAP(type, name, args, retval, param, prob)	\
extern type __wrap_##name args;				\
extern type __real_##name args;				\
type __wrap_##name args {				\
	if (prng_up && uniform_random(400) < (prob)) {	\
		return (retval);			\
	}						\
							\
	return (__real_##name param);			\
}

WRAP(void *,
	malloc,
	(size_t size),
	NULL,
	(size),
	1
)

WRAP(void *,
	calloc,
	(size_t nmemb, size_t size),
	NULL,
	(nmemb, size),
	1
)

WRAP(void *,
	realloc,
	(void *ptr, size_t size),
	NULL,
	(ptr, size),
	1
)

WRAP(char *,
	strdup,
	(const char *s),
	NULL,
	(s),
	1
)

WRAP(cbor_item_t *,
	cbor_build_string,
	(const char *val),
	NULL,
	(val),
	1
)

WRAP(cbor_item_t *,
	cbor_build_bytestring,
	(cbor_data handle, size_t length),
	NULL,
	(handle, length),
	1
)

WRAP(cbor_item_t *,
	cbor_build_bool,
	(bool value),
	NULL,
	(value),
	1
)

WRAP(cbor_item_t *,
	cbor_build_negint8,
	(uint8_t value),
	NULL,
	(value),
	1
)

WRAP(cbor_item_t *,
	cbor_build_negint16,
	(uint16_t value),
	NULL,
	(value),
	1
)

WRAP(cbor_item_t *,
	cbor_load,
	(cbor_data source, size_t source_size, struct cbor_load_result *result),
	NULL,
	(source, source_size, result),
	1
)

WRAP(cbor_item_t *,
	cbor_build_uint8,
	(uint8_t value),
	NULL,
	(value),
	1
)

WRAP(cbor_item_t *,
	cbor_build_uint16,
	(uint16_t value),
	NULL,
	(value),
	1
)

WRAP(cbor_item_t *,
	cbor_build_uint32,
	(uint32_t value),
	NULL,
	(value),
	1
)

WRAP(cbor_item_t *,
	cbor_build_uint64,
	(uint64_t value),
	NULL,
	(value),
	1
)

WRAP(struct cbor_pair *,
	cbor_map_handle,
	(const cbor_item_t *item),
	NULL,
	(item),
	1
)

WRAP(cbor_item_t **,
	cbor_array_handle,
	(const cbor_item_t *item),
	NULL,
	(item),
	1
)

WRAP(bool,
	cbor_array_push,
	(cbor_item_t *array, cbor_item_t *pushee),
	false,
	(array, pushee),
	1
)

WRAP(bool,
	cbor_map_add,
	(cbor_item_t *item, struct cbor_pair pair),
	false,
	(item, pair),
	1
)

WRAP(cbor_item_t *,
	cbor_new_definite_map,
	(size_t size),
	NULL,
	(size),
	1
)

WRAP(cbor_item_t *,
	cbor_new_definite_array,
	(size_t size),
	NULL,
	(size),
	1
)

WRAP(cbor_item_t *,
	cbor_new_definite_bytestring,
	(void),
	NULL,
	(),
	1
)

WRAP(size_t,
	cbor_serialize_alloc,
	(const cbor_item_t *item, cbor_mutable_data *buffer,
	    size_t *buffer_size),
	0,
	(item, buffer, buffer_size),
	1
)

WRAP(int,
	fido_tx,
	(fido_dev_t *d, uint8_t cmd, const void *buf, size_t count, int *ms),
	-1,
	(d, cmd, buf, count, ms),
	1
)

WRAP(int,
	bind,
	(int sockfd, const struct sockaddr *addr, socklen_t addrlen),
	-1,
	(sockfd, addr, addrlen),
	1
)

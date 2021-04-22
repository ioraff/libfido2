/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "../openbsd-compat/openbsd-compat.h"
#include "extern.h"

int
base64_encode(const void *ptr, size_t len, char **out)
{
	static const char b64[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const unsigned char	*src = ptr;
	char			*dst;
	size_t			 i;
	unsigned long		 x;

	if (ptr == NULL || out == NULL ||
	    (*out = dst = calloc(1, (len + 2) / 3 * 4 + 1)) == NULL)
		return (-1);

	for (i = 0; i < len; i += 3, dst += 4) {
		x = (unsigned long)src[i] << 16;
		dst[3] = i + 2 >= len ? '=' : b64[(x |= src[i + 2]) & 0x3f];
		dst[2] = i + 1 >= len ? '=' :
		    b64[(x |= (unsigned long)src[i + 1] << 8) >> 6 & 0x3f];
		dst[1] = b64[x >> 12 & 0x3f];
		dst[0] = b64[x >> 18];
	}
	*dst = '\0';

	return (0);
}

int
base64_decode(const char *src, void **ptr, size_t *len)
{
	static const unsigned char b64[] = {
		['A'] =  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12,
		        13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
		['a'] = 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
		        39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
		['0'] = 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
		['+'] = 62,
		['/'] = 63,
	};
	unsigned char	*dst;
	size_t		 src_len, i;
	unsigned long	 x;
	unsigned	 pad = 0, c;
	int		 ok = -1;

	if (src == NULL || ptr == NULL || len == NULL)
		return (-1);
	if ((src_len = strlen(src)) && src[src_len - 1] == '\n')
		--src_len;
	if (src_len % 4 != 0 ||
	    (*ptr = dst = calloc(1, src_len / 4 * 3)) == NULL)
		return (-1);

	for (i = 0, x = 0; i < src_len; ++i) {
		c = (unsigned char)src[i];
		if (c == '=' && (i + 1 == src_len || (src[i + 1] == '=' &&
		    i + 2 == src_len)))
			++pad;
		else if (c >= sizeof(b64) || (!b64[c] && c != 'A'))
			goto fail;
		x = x << 6 | b64[c];
		if (i % 4 == 3) {
			dst[2] = x & 0xff; x >>= 8;
			dst[1] = x & 0xff; x >>= 8;
			dst[0] = x & 0xff;
			dst += 3;
		}
	}

	*len = src_len / 4 * 3 - pad;
	ok = 0;

fail:
	if (ok < 0) {
		free(*ptr);
		*ptr = NULL;
		*len = 0;
	}

	return (ok);
}

int
base64_read(FILE *f, struct blob *out)
{
	char *line = NULL;
	size_t linesize = 0;
	ssize_t n;

	out->ptr = NULL;
	out->len = 0;

	if ((n = getline(&line, &linesize, f)) <= 0 ||
	    (size_t)n != strlen(line)) {
		free(line); /* XXX should be free'd _even_ if getline() fails */
		return (-1);
	}

	if (base64_decode(line, (void **)&out->ptr, &out->len) < 0) {
		free(line);
		return (-1);
	}

	free(line);

	return (0);
}

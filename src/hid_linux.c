/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <sys/types.h>

#include <sys/ioctl.h>
#include <linux/hidraw.h>

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "fido.h"

#define REPORT_LEN	65

static int
get_key_len(uint8_t tag, uint8_t *key, size_t *key_len)
{
	*key = tag & 0xfc;
	if ((*key & 0xf0) == 0xf0) {
		fido_log_debug("%s: *key=0x%02x", __func__, *key);
		return (-1);
	}

	*key_len = tag & 0x3;
	if (*key_len == 3) {
		*key_len = 4;
	}

	return (0);
}

static int
get_key_val(const void *body, size_t key_len, uint32_t *val)
{
	const uint8_t *ptr = body;

	switch (key_len) {
	case 0:
		*val = 0;
		break;
	case 1:
		*val = ptr[0];
		break;
	case 2:
		*val = (uint32_t)((ptr[1] << 8) | ptr[0]);
		break;
	default:
		fido_log_debug("%s: key_len=%zu", __func__, key_len);
		return (-1);
	}

	return (0);
}

static int
get_usage_info(const struct hidraw_report_descriptor *hrd, uint32_t *usage_page,
    uint32_t *usage)
{
	const uint8_t	*ptr;
	size_t		 len;

	ptr = hrd->value;
	len = hrd->size;

	while (len > 0) {
		const uint8_t tag = ptr[0];
		ptr++;
		len--;

		uint8_t  key;
		size_t   key_len;
		uint32_t key_val;

		if (get_key_len(tag, &key, &key_len) < 0 || key_len > len ||
		    get_key_val(ptr, key_len, &key_val) < 0) {
			return (-1);
		}

		if (key == 0x4) {
			*usage_page = key_val;
		} else if (key == 0x8) {
			*usage = key_val;
		}

		ptr += key_len;
		len -= key_len;
	}

	return (0);
}

static int
get_report_descriptor(const char *path, struct hidraw_report_descriptor *hrd)
{
	int	s = -1;
	int	fd;
	int	ok = -1;

	if ((fd = open(path, O_RDONLY)) < 0) {
		fido_log_debug("%s: open", __func__);
		return (-1);
	}

	if (ioctl(fd, HIDIOCGRDESCSIZE, &s) < 0 || s < 0 ||
	    (unsigned)s > HID_MAX_DESCRIPTOR_SIZE) {
		fido_log_debug("%s: ioctl HIDIOCGRDESCSIZE", __func__);
		goto fail;
	}

	hrd->size = s;

	if (ioctl(fd, HIDIOCGRDESC, hrd) < 0) {
		fido_log_debug("%s: ioctl HIDIOCGRDESC", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (fd != -1)
		close(fd);

	return (ok);
}

static bool
is_fido(const char *path)
{
	uint32_t			usage = 0;
	uint32_t			usage_page = 0;
	struct hidraw_report_descriptor	hrd;

	memset(&hrd, 0, sizeof(hrd));

	if (get_report_descriptor(path, &hrd) < 0 ||
	    get_usage_info(&hrd, &usage_page, &usage) < 0) {
		return (false);
	}

	return (usage_page == 0xf1d0);
}

static int
parse_uevent(const char *path, int16_t *vendor_id, int16_t *product_id)
{
	FILE			*fp;
	char			*p = NULL;
	size_t			 n = 0;
	int			 ok = -1;
	short unsigned int	 x;
	short unsigned int	 y;

	fp = fopen(path, "r");
	if (!fp)
		return (-1);

	while (getline(&p, &n, fp) >= 0) {
		if (strncmp(p, "HID_ID=", 7) == 0) {
			if (sscanf(p + 7, "%*x:%hx:%hx", &x, &y) == 2) {
				*vendor_id = (int16_t)x;
				*product_id = (int16_t)y;
				ok = 0;
			}
			break;
		}
	}

	free(p);
	fclose(fp);
	return (ok);
}

static int
copy_info(fido_dev_info_t *di, const char *name)
{
	char path[PATH_MAX];
	int r, ok = -1;

	memset(di, 0, sizeof(*di));

	r = snprintf(path, sizeof(path), "/dev/%s", name);
	if (r < 0 || (size_t)r >= sizeof(path))
		goto fail;
	if (is_fido(path) == 0)
		goto fail;
	di->path = strdup(path);

	r = snprintf(path, sizeof(path), "/sys/class/hidraw/%s/device/uevent", name);
	if (r < 0 || (size_t)r >= sizeof(path))
		goto fail;
	if (parse_uevent(path, &di->vendor_id, &di->product_id) < 0)
		goto fail;

	di->manufacturer = strdup("unknown");
	di->product = strdup("unknown");

	if (di->path == NULL ||
	    di->manufacturer == NULL ||
	    di->product == NULL)
		goto fail;

	ok = 0;
fail:
	if (ok < 0) {
		free(di->path);
		free(di->manufacturer);
		free(di->product);
		explicit_bzero(di, sizeof(*di));
	}

	return (ok);
}

static int
filter_hidraw(const struct dirent *d)
{
	return strncmp(d->d_name, "hidraw", 6) == 0;
}

int
fido_hid_manifest(fido_dev_info_t *devlist, size_t ilen, size_t *olen)
{
	struct dirent **entries;
	int i, n, r = FIDO_ERR_INTERNAL;

	*olen = 0;

	if (ilen == 0)
		return (FIDO_OK); /* nothing to do */

	if (devlist == NULL)
		return (FIDO_ERR_INVALID_ARGUMENT);

	n = scandir("/sys/class/hidraw", &entries, filter_hidraw, alphasort);
	if (n == -1)
		goto fail;
	for (i = 0; i < n; ++i) {
		if (copy_info(&devlist[*olen], entries[i]->d_name) == 0) {
			devlist[*olen].io = (fido_dev_io_t) {
				fido_hid_open,
				fido_hid_close,
				fido_hid_read,
				fido_hid_write,
			};
			if (++(*olen) == ilen)
				break;
		}
		free(entries[i]);
	}
	for (; i < n; ++i)
		free(entries[i]);
	free(entries);

	r = FIDO_OK;
fail:
	return (r);
}

void *
fido_hid_open(const char *path)
{
	int *fd;

	if ((fd = malloc(sizeof(*fd))) == NULL ||
	    (*fd = open(path, O_RDWR)) < 0) {
		free(fd);
		return (NULL);
	}

	return (fd);
}

void
fido_hid_close(void *handle)
{
	int *fd = handle;

	close(*fd);
	free(fd);
}

int
fido_hid_read(void *handle, unsigned char *buf, size_t len, int ms)
{
	int	*fd = handle;
	ssize_t	 r;

	(void)ms; /* XXX */

	if (len != REPORT_LEN - 1) {
		fido_log_debug("%s: invalid len", __func__);
		return (-1);
	}

	if ((r = read(*fd, buf, len)) < 0 || r != REPORT_LEN - 1)
		return (-1);

	return (REPORT_LEN - 1);
}

int
fido_hid_write(void *handle, const unsigned char *buf, size_t len)
{
	int	*fd = handle;
	ssize_t	 r;

	if (len != REPORT_LEN) {
		fido_log_debug("%s: invalid len", __func__);
		return (-1);
	}

	if ((r = write(*fd, buf, len)) < 0 || r != REPORT_LEN) {
		fido_log_debug("%s: write", __func__);
		return (-1);
	}

	return (REPORT_LEN);
}

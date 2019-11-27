/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fido.h"

/* CTAP section 8.1.4 */
enum {
	CID,

	INIT_CMD = 4,
	INIT_BCNTH,
	INIT_BCNTL,
	INIT_DATA,

	CONT_SEQ = 4,
	CONT_DATA,
};

#ifndef MIN
#define MIN(x, y) ((x) > (y) ? (y) : (x))
#endif

static int
tx_empty(fido_dev_t *d, uint8_t cmd)
{
	uint8_t	pkt[1 + CTAP_RPT_SIZE] = {0};
	int	n;

	memcpy(pkt + 1 + CID, &d->cid, 4);
	pkt[1 + INIT_CMD] = CTAP_FRAME_INIT | cmd;

	n = d->io.write(d->io_handle, pkt, sizeof(pkt));
	if (n < 0 || (size_t)n != sizeof(pkt))
		return (-1);

	return (0);
}

static size_t
tx_preamble(fido_dev_t *d, uint8_t cmd, const void *buf, size_t count)
{
	uint8_t	pkt[1 + CTAP_RPT_SIZE] = {0};
	int	n;

	memcpy(pkt + 1 + CID, &d->cid, 4);
	pkt[1 + INIT_CMD] = CTAP_FRAME_INIT | cmd;
	pkt[1 + INIT_BCNTH] = (count >> 8) & 0xff;
	pkt[1 + INIT_BCNTL] = count & 0xff;
	count = MIN(count, CTAP_RPT_SIZE - INIT_DATA);
	memcpy(pkt + 1 + INIT_DATA, buf, count);

	n = d->io.write(d->io_handle, pkt, sizeof(pkt));
	if (n < 0 || (size_t)n != sizeof(pkt))
		return (0);

	return (count);
}

static size_t
tx_frame(fido_dev_t *d, uint8_t seq, const void *buf, size_t count)
{
	uint8_t	pkt[1 + CTAP_RPT_SIZE] = {0};
	int	n;

	memcpy(pkt + 1 + CID, &d->cid, 4);
	pkt[1 + CONT_SEQ] = seq;
	count = MIN(count, CTAP_RPT_SIZE - CONT_DATA);
	memcpy(pkt + 1 + CONT_DATA, buf, count);

	n = d->io.write(d->io_handle, pkt, sizeof(pkt));
	if (n < 0 || (size_t)n != sizeof(pkt))
		return (0);

	return (count);
}

static int
tx(fido_dev_t *d, uint8_t cmd, const unsigned char *buf, size_t count)
{
	size_t n, sent;

	if ((sent = tx_preamble(d, cmd, buf, count)) == 0) {
		fido_log_debug("%s: tx_preamble", __func__);
		return (-1);
	}

	for (uint8_t seq = 0; sent < count; sent += n) {
		if (seq & 0x80) {
			fido_log_debug("%s: seq & 0x80", __func__);
			return (-1);
		}
		if ((n = tx_frame(d, seq++, buf + sent, count - sent)) == 0) {
			fido_log_debug("%s: tx_frame", __func__);
			return (-1);
		}
	}

	return (0);
}

int
fido_tx(fido_dev_t *d, uint8_t cmd, const void *buf, size_t count)
{
	fido_log_debug("%s: d=%p, cmd=0x%02x, buf=%p, count=%zu", __func__,
	    (void *)d, cmd, (const void *)buf, count);
	fido_log_xxd(buf, count);

	if (d->transport.tx != NULL)
		return (d->transport.tx(d, cmd, buf, count));

	if (d->io_handle == NULL || d->io.write == NULL || count > UINT16_MAX) {
		fido_log_debug("%s: invalid argument", __func__);
		return (-1);
	}

	if (count == 0)
		return (tx_empty(d, cmd));

	return (tx(d, cmd, buf, count));
}

static int
rx_frame(fido_dev_t *d, uint8_t *fp, int ms)
{
	int n;

	n = d->io.read(d->io_handle, (unsigned char *)fp, CTAP_RPT_SIZE, ms);
	if (n < 0 || (size_t)n != CTAP_RPT_SIZE)
		return (-1);

	return (0);
}

static int
rx_preamble(fido_dev_t *d, uint8_t cmd, uint8_t *fp, int ms)
{
	uint32_t cid;

	do {
		if (rx_frame(d, fp, ms) < 0)
			return (-1);
		memcpy(&cid, &fp[CID], 4);
#ifdef FIDO_FUZZ
		cid = d->cid;
#endif
	} while (cid == d->cid &&
	    fp[INIT_CMD] == (CTAP_FRAME_INIT | CTAP_KEEPALIVE));

	fido_log_debug("%s: initiation frame at %p", __func__, (void *)fp);
	fido_log_xxd(fp, CTAP_RPT_SIZE);

#ifdef FIDO_FUZZ
	fp[INIT_CMD] = (CTAP_FRAME_INIT | cmd);
#endif

	if (cid != d->cid || fp[INIT_CMD] != (CTAP_FRAME_INIT | cmd)) {
		fido_log_debug("%s: cid (0x%x, 0x%x), cmd (0x%02x, 0x%02x)",
		    __func__, cid, d->cid, fp[INIT_CMD], cmd);
		return (-1);
	}

	return (0);
}

static int
rx(fido_dev_t *d, uint8_t cmd, unsigned char *buf, size_t count, int ms)
{
	uint8_t		f[CTAP_RPT_SIZE];
	uint32_t	cid;
	uint16_t	r, payload_len;

	if (rx_preamble(d, cmd, f, ms) < 0) {
		fido_log_debug("%s: rx_preamble", __func__);
		return (-1);
	}

	payload_len = (f[INIT_BCNTH] << 8) | f[INIT_BCNTL];
	fido_log_debug("%s: payload_len=%zu", __func__, (size_t)payload_len);

	if (count < (size_t)payload_len) {
		fido_log_debug("%s: count < payload_len", __func__);
		return (-1);
	}

	if (payload_len < CTAP_RPT_SIZE - INIT_DATA) {
		memcpy(buf, f + INIT_DATA, payload_len);
		return (payload_len);
	}

	memcpy(buf, f + INIT_DATA, CTAP_RPT_SIZE - INIT_DATA);
	r = CTAP_RPT_SIZE - INIT_DATA;

	for (int seq = 0; (size_t)r < payload_len; seq++) {
		if (rx_frame(d, f, ms) < 0) {
			fido_log_debug("%s: rx_frame", __func__);
			return (-1);
		}

		fido_log_debug("%s: continuation frame at %p", __func__,
		    (void *)&f);
		fido_log_xxd(&f, sizeof(f));

		memcpy(&cid, f + CID, 4);

#ifdef FIDO_FUZZ
		cid = d->cid;
		f[CONT_SEQ] = seq;
#endif

		if (cid != d->cid || f[CONT_SEQ] != seq) {
			fido_log_debug("%s: cid (0x%x, 0x%x), seq (%d, %d)",
			    __func__, cid, d->cid, f[CONT_SEQ], seq);
			return (-1);
		}

		if ((size_t)(payload_len - r) > CTAP_RPT_SIZE - CONT_DATA) {
			memcpy(buf + r, f + CONT_DATA,
			    CTAP_RPT_SIZE - CONT_DATA);
			r += CTAP_RPT_SIZE - CONT_DATA;
		} else {
			memcpy(buf + r, f + CONT_DATA, payload_len - r);
			r += (payload_len - r); /* break */
		}
	}

	return (r);
}

int
fido_rx(fido_dev_t *d, uint8_t cmd, void *buf, size_t count, int ms)
{
	int n;

	fido_log_debug("%s: d=%p, cmd=0x%02x, buf=%p, count=%zu, ms=%d",
	    __func__, (void *)d, cmd, (const void *)buf, count, ms);

	if (d->transport.rx != NULL)
		return (d->transport.rx(d, cmd, buf, count, ms));

	if (d->io_handle == NULL || d->io.read == NULL || count > UINT16_MAX) {
		fido_log_debug("%s: invalid argument", __func__);
		return (-1);
	}

	if ((n = rx(d, cmd, buf, count, ms)) >= 0) {
		fido_log_debug("%s: buf=%p, len=%d", __func__, (void *)buf, n);
		fido_log_xxd(buf, n);
	}

	return (n);
}

int
fido_rx_cbor_status(fido_dev_t *d, int ms)
{
	unsigned char	reply[FIDO_MAXMSG];
	int		reply_len;

	if ((reply_len = fido_rx(d, CTAP_CMD_CBOR, &reply, sizeof(reply),
	    ms)) < 0 || (size_t)reply_len < 1) {
		fido_log_debug("%s: fido_rx", __func__);
		return (FIDO_ERR_RX);
	}

	return (reply[0]);
}

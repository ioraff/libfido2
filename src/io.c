/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

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
	uint8_t		 pkt[1 + CTAP_MAX_REPORT_LEN] = {0};
	const size_t	 len = d->tx_len + 1;
	int		 n;

	memcpy(pkt + 1 + CID, &d->cid, 4);
	pkt[1 + INIT_CMD] = CTAP_FRAME_INIT | cmd;

	if (len > sizeof(pkt) || (n = d->io.write(d->io_handle, pkt,
	    len)) < 0 || (size_t)n != len)
		return (-1);

	return (0);
}

static size_t
tx_preamble(fido_dev_t *d, uint8_t cmd, const void *buf, size_t count)
{
	uint8_t		 pkt[1 + CTAP_MAX_REPORT_LEN] = {0};
	const size_t	 len = d->tx_len + 1;
	int		 n;

	if (d->tx_len > CTAP_MAX_REPORT_LEN)
		return (0);

	memcpy(pkt + 1 + CID, &d->cid, 4);
	pkt[1 + INIT_CMD] = CTAP_FRAME_INIT | cmd;
	pkt[1 + INIT_BCNTH] = (count >> 8) & 0xff;
	pkt[1 + INIT_BCNTL] = count & 0xff;
	count = MIN(count, d->tx_len - CTAP_INIT_HEADER_LEN);
	memcpy(pkt + 1 + INIT_DATA, buf, count);

	if (len > sizeof(pkt) || (n = d->io.write(d->io_handle, pkt,
	    len)) < 0 || (size_t)n != len)
		return (0);

	return (count);
}

static size_t
tx_frame(fido_dev_t *d, uint8_t seq, const void *buf, size_t count)
{
	uint8_t		 pkt[1 + CTAP_MAX_REPORT_LEN] = {0};
	const size_t 	 len = d->tx_len + 1;
	int		 n;

	if (d->tx_len > CTAP_MAX_REPORT_LEN)
		return (0);

	memcpy(pkt + 1 + CID, &d->cid, 4);
	pkt[1 + CONT_SEQ] = seq;
	count = MIN(count, CTAP_MAX_REPORT_LEN - CTAP_CONT_HEADER_LEN);
	memcpy(pkt + 1 + CONT_DATA, buf, count);

	if (len > sizeof(pkt) || (n = d->io.write(d->io_handle, pkt,
	    len)) < 0 || (size_t)n != len)
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
	fido_log_debug("%s: dev=%p, cmd=0x%02x", __func__, (void *)d, cmd);
	fido_log_xxd(buf, count, "%s", __func__);

	if (d->transport.tx != NULL)
		return (d->transport.tx(d, cmd, buf, count));
	if (d->io_handle == NULL || d->io.write == NULL || count > UINT16_MAX) {
		fido_log_debug("%s: invalid argument", __func__);
		return (-1);
	}

	return (count == 0 ? tx_empty(d, cmd) : tx(d, cmd, buf, count));
}

static int
rx_frame(fido_dev_t *d, uint8_t *fp, int ms)
{
	int n;

	memset(fp, 0, CTAP_MAX_REPORT_LEN);

	if (d->rx_len > CTAP_MAX_REPORT_LEN || (n = d->io.read(d->io_handle,
	    (unsigned char *)fp, d->rx_len, ms)) < 0 || (size_t)n != d->rx_len)
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

	if (d->rx_len > CTAP_MAX_REPORT_LEN)
		return (-1);

	fido_log_xxd(fp, d->rx_len, "%s", __func__);
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
	uint8_t	f[CTAP_MAX_REPORT_LEN];
	uint32_t cid;
	size_t r, payload_len, init_data_len, cont_data_len;

	if (d->rx_len <= CTAP_INIT_HEADER_LEN ||
	    d->rx_len <= CTAP_CONT_HEADER_LEN)
		return (-1);

	init_data_len = d->rx_len - CTAP_INIT_HEADER_LEN;
	cont_data_len = d->rx_len - CTAP_CONT_HEADER_LEN;

	if (d->rx_len > CTAP_MAX_REPORT_LEN)
		return (-1);

	if (rx_preamble(d, cmd, f, ms) < 0) {
		fido_log_debug("%s: rx_preamble", __func__);
		return (-1);
	}

	payload_len = (size_t)((f[INIT_BCNTH] << 8) | f[INIT_BCNTL]);
	fido_log_debug("%s: payload_len=%zu", __func__, payload_len);

	if (count < payload_len) {
		fido_log_debug("%s: count < payload_len", __func__);
		return (-1);
	}

	if (payload_len < init_data_len) {
		memcpy(buf, f + CTAP_INIT_HEADER_LEN, payload_len);
		return ((int)payload_len);
	}

	memcpy(buf, f + CTAP_INIT_HEADER_LEN, init_data_len);
	r = init_data_len;

	for (int seq = 0; r < payload_len; seq++) {
		if (rx_frame(d, f, ms) < 0) {
			fido_log_debug("%s: rx_frame", __func__);
			return (-1);
		}

		fido_log_xxd(&f, d->rx_len, "%s", __func__);

		memcpy(&cid, f + CID, 4);
#ifdef FIDO_FUZZ
		cid = d->cid;
		f[CONT_SEQ] = (uint8_t)seq;
#endif

		if (cid != d->cid || f[CONT_SEQ] != seq) {
			fido_log_debug("%s: cid (0x%x, 0x%x), seq (%d, %d)",
			    __func__, cid, d->cid, f[CONT_SEQ], seq);
			return (-1);
		}

		if (payload_len - r > cont_data_len) {
			memcpy(buf + r, f + CTAP_CONT_HEADER_LEN, cont_data_len);
			r += cont_data_len;
		} else {
			memcpy(buf + r, f + CTAP_CONT_HEADER_LEN, payload_len - r);
			r += payload_len - r; /* break */
		}
	}

	return ((int)r);
}

int
fido_rx(fido_dev_t *d, uint8_t cmd, void *buf, size_t count, int ms)
{
	int n;

	fido_log_debug("%s: dev=%p, cmd=0x%02x, ms=%d", __func__, (void *)d,
	    cmd, ms);

	if (d->transport.rx != NULL)
		return (d->transport.rx(d, cmd, buf, count, ms));
	if (d->io_handle == NULL || d->io.read == NULL || count > UINT16_MAX) {
		fido_log_debug("%s: invalid argument", __func__);
		return (-1);
	}
	if ((n = rx(d, cmd, buf, count, ms)) >= 0)
		fido_log_xxd(buf, (size_t)n, "%s", __func__);

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

/*
 * libdivecomputer
 *
 * Copyright (C) 2026 Jef Driesen
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "suunto_nautic.h"
#include "context-private.h"
#include "device-private.h"
#include "platform.h"
#include "checksum.h"
#include "array.h"
#include "hdlc.h"
#include "heatshrink/heatshrink_decoder.h"

// See suunto_nautic.h for the full picture of what is/isn't understood.

#define RPC_OP_GET           0x0A
#define RPC_OP_STREAM_FETCH1 0x0B
#define RPC_OP_STREAM_FETCH2 0x10

#define RPC_HEADER_SIZE 10 // magic(1) + opcode(1) + sublen(2) + seq(2) + 0x01 + 0x80 + 0x00 + pathlen(1)
#define RPC_CRC_SIZE     4

#define MAX_PATH    240
#define MAX_PACKET  512

// Number of PMT-style chunks to accept before giving up. This is a safety
// cap, not a protocol constant — the real termination condition (how the
// watch signals "no more chunks") is unknown, so we stop on the first read
// timeout instead.
#define MAX_CHUNKS 4096

// The Suunto "MDS" chunk header wrapping each compressed block. Verified
// against a real capture (see suunto_nautic.h): the header is 28 bytes,
// NOT 20 as an earlier version of this file assumed — the 8 bytes at
// offset 20-27 are MDS metadata (including the true payload size at
// offset 20-21), not part of the compressed payload. Reading from offset
// 20 instead of 28 injects 8 bytes of garbage into the decompressor's
// LZSS window and corrupts everything after the first block.
#define MDS_HEADER_SIZE     28
#define MDS_CHUNK_SIZE_OFFSET 20

// Heatshrink (LZSS) parameters used by the Nautic/Ocean's MDS stream.
#define HEATSHRINK_WINDOW_SZ2    7
#define HEATSHRINK_LOOKAHEAD_SZ2 5
#define HEATSHRINK_INPUT_BUFFER_SIZE 256

static const unsigned char SBEM_MAGIC[8] = {'S','B','E','M','0','1','0','3'};

typedef struct suunto_nautic_device_t {
	dc_device_t base;
	dc_iostream_t *iostream; // HDLC-framed
	unsigned int sequence;
} suunto_nautic_device_t;

static dc_status_t suunto_nautic_device_foreach (dc_device_t *abstract, dc_dive_callback_t callback, void *userdata);
static dc_status_t suunto_nautic_device_close (dc_device_t *abstract);

static const dc_device_vtable_t suunto_nautic_device_vtable = {
	sizeof(suunto_nautic_device_t),
	DC_FAMILY_SUUNTO_NAUTIC,
	NULL, /* set_fingerprint */
	NULL, /* read */
	NULL, /* write */
	NULL, /* dump */
	suunto_nautic_device_foreach, /* foreach */
	NULL, /* timesync */
	suunto_nautic_device_close, /* close */
};

/*
 * Captured verbatim from a real BLE sniff (libdivecomputer issue #70). The
 * EVA payload negotiates capabilities before any endpoint can be reached;
 * we don't know how to construct it generically, so it is replayed as-is.
 * Whether it is universal across all Nautic/Ocean units or session-
 * specific is unconfirmed.
 */
static const unsigned char suunto_nautic_eva_handshake[] = {
	0xA5, 0x12, 0x20, 0x00, 0x00, 0x00, 0x09, 0x09, 0x20, 0x16, 0x45, 0x56,
	0x41, 0x10, 0x04, 0x41, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x04, 0x01, 0x02,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x63, 0x1B, 0x47, 0x1B
};

/*
 * Also captured verbatim. The sequence-number field (bytes 4-5) is known
 * to be "the previous request's sequence + 1" (see
 * suunto_nautic_build_stream_fetch below), but the remaining fields do not
 * match a pattern we can derive from the single available sample, so the
 * rest of the frame is replayed literally. This is a best-effort probe,
 * not a verified mechanism — expect it to need correction once real
 * captures from other sessions/devices are available.
 */
static const unsigned char suunto_nautic_fetch1_tail[] = {
	0x00, 0x24, 0x12, 0x01, 0x80, 0x00
};
static const unsigned char suunto_nautic_fetch2_tail[] = {
	0x00, 0x24, 0x0E, 0x01, 0x80, 0x00, 0x00
};

// Build a generic path-addressed GET request. Verified byte-for-byte
// against three independent captured samples (/System/Mode,
// /Logbook/byId/<id>/Data, and the stream-fetch acknowledgement), so this
// generalizes to arbitrary endpoint paths, not just the ones seen so far.
static dc_status_t
suunto_nautic_build_get (unsigned char packet[], unsigned int size, unsigned int *out_len, unsigned int seq, const char *path)
{
	size_t pathlen = strlen (path);
	if (pathlen == 0 || pathlen > MAX_PATH)
		return DC_STATUS_INVALIDARGS;

	unsigned int len = RPC_HEADER_SIZE + (unsigned int) pathlen + RPC_CRC_SIZE;
	if (len > size)
		return DC_STATUS_INVALIDARGS;

	unsigned int sublen = (unsigned int) pathlen + 4;

	packet[0] = 0xA5;
	packet[1] = RPC_OP_GET;
	array_uint16_le_set (packet + 2, (unsigned short) sublen);
	array_uint16_le_set (packet + 4, (unsigned short) seq);
	packet[6] = 0x01;
	packet[7] = 0x80;
	packet[8] = 0x00;
	packet[9] = (unsigned char) pathlen;
	memcpy (packet + 10, path, pathlen);

	unsigned int crc = checksum_crc32r (packet, RPC_HEADER_SIZE + (unsigned int) pathlen);
	array_uint32_le_set (packet + RPC_HEADER_SIZE + (unsigned int) pathlen, crc);

	*out_len = len;
	return DC_STATUS_SUCCESS;
}

// Build a stream-fetch trigger frame. Only the opcode and sequence number
// are derived; the tail is a literal replay (see the caveats above the
// suunto_nautic_fetch{1,2}_tail tables).
static dc_status_t
suunto_nautic_build_stream_fetch (unsigned char packet[], unsigned int size, unsigned int *out_len,
	unsigned int seq, unsigned char opcode, const unsigned char tail[], unsigned int tail_size)
{
	unsigned int len = RPC_HEADER_SIZE - 4 + tail_size + RPC_CRC_SIZE; // magic+opcode+sublen+seq (6) + tail + crc
	if (len > size)
		return DC_STATUS_INVALIDARGS;

	packet[0] = 0xA5;
	packet[1] = opcode;
	array_uint16_le_set (packet + 2, (unsigned short) tail_size);
	array_uint16_le_set (packet + 4, (unsigned short) seq);
	memcpy (packet + 6, tail, tail_size);

	unsigned int crc = checksum_crc32r (packet, 6 + tail_size);
	array_uint32_le_set (packet + 6 + tail_size, crc);

	*out_len = len;
	return DC_STATUS_SUCCESS;
}

static dc_status_t
suunto_nautic_transfer (suunto_nautic_device_t *device, const unsigned char req[], unsigned int rsize, dc_buffer_t *response)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	dc_device_t *abstract = (dc_device_t *) device;

	if (device_is_cancelled (abstract))
		return DC_STATUS_CANCELLED;

	status = dc_iostream_write (device->iostream, req, rsize, NULL);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to send the RPC request.");
		return status;
	}

	if (response) {
		unsigned char packet[MAX_PACKET] = {0};
		size_t len = 0;
		status = dc_iostream_read (device->iostream, packet, sizeof (packet), &len);
		if (status != DC_STATUS_SUCCESS) {
			ERROR (abstract->context, "Failed to receive the RPC response.");
			return status;
		}

		HEXDUMP (abstract->context, DC_LOGLEVEL_DEBUG, "RPC RSP", packet, len);

		dc_buffer_clear (response);
		if (!dc_buffer_append (response, packet, len)) {
			ERROR (abstract->context, "Failed to allocate memory.");
			return DC_STATUS_NOMEMORY;
		}
	}

	return DC_STATUS_SUCCESS;
}

dc_status_t
suunto_nautic_device_open (dc_device_t **out, dc_context_t *context, dc_iostream_t *iostream)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	suunto_nautic_device_t *device = NULL;

	if (out == NULL)
		return DC_STATUS_INVALIDARGS;

	device = (suunto_nautic_device_t *) dc_device_allocate (context, &suunto_nautic_device_vtable);
	if (device == NULL) {
		ERROR (context, "Failed to allocate memory.");
		return DC_STATUS_NOMEMORY;
	}

	device->sequence = 1;

	status = dc_hdlc_open (&device->iostream, context, iostream, 244, 244);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to open the HDLC layer.");
		goto error_free;
	}

	status = dc_iostream_set_timeout (device->iostream, 5000);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to set the timeout.");
		goto error_close;
	}

	dc_iostream_purge (device->iostream, DC_DIRECTION_ALL);

	// Best-effort EVA handshake. We can't validate the response content
	// (its format isn't understood), so we only require that the I/O
	// round-trip succeeds.
	status = dc_iostream_write (device->iostream, suunto_nautic_eva_handshake, sizeof (suunto_nautic_eva_handshake), NULL);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to send the EVA handshake.");
		goto error_close;
	}

	unsigned char handshake_rsp[MAX_PACKET] = {0};
	size_t handshake_len = 0;
	status = dc_iostream_read (device->iostream, handshake_rsp, sizeof (handshake_rsp), &handshake_len);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to receive the EVA handshake response. The device may not "
			"support this protocol, or the handshake payload may need updating "
			"(see suunto_nautic.h).");
		goto error_close;
	}

	HEXDUMP (context, DC_LOGLEVEL_DEBUG, "EVA RSP", handshake_rsp, handshake_len);

	*out = (dc_device_t *) device;

	return DC_STATUS_SUCCESS;

error_close:
	dc_iostream_close (device->iostream);
error_free:
	dc_device_deallocate ((dc_device_t *) device);
	return status;
}

static dc_status_t
suunto_nautic_device_close (dc_device_t *abstract)
{
	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;

	return dc_iostream_close (device->iostream);
}

dc_status_t
suunto_nautic_device_request (dc_device_t *abstract, const char *path, dc_buffer_t *response)
{
	if (abstract == NULL || abstract->vtable->type != DC_FAMILY_SUUNTO_NAUTIC || path == NULL)
		return DC_STATUS_INVALIDARGS;

	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;

	unsigned char packet[RPC_HEADER_SIZE + MAX_PATH + RPC_CRC_SIZE];
	unsigned int len = 0;
	dc_status_t status = suunto_nautic_build_get (packet, sizeof (packet), &len, device->sequence, path);
	if (status != DC_STATUS_SUCCESS)
		return status;
	device->sequence++;

	return suunto_nautic_transfer (device, packet, len, response);
}

// Decompress a Heatshrink (LZSS) stream, per the parameters documented
// above. Verified byte-for-byte against a reference implementation using
// real captured data (see suunto_nautic.h).
static dc_status_t
suunto_nautic_heatshrink_decompress (dc_context_t *context, const unsigned char *input, size_t input_size, dc_buffer_t *output)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	unsigned char outbuf[HEATSHRINK_INPUT_BUFFER_SIZE];

	heatshrink_decoder *hsd = heatshrink_decoder_alloc (HEATSHRINK_INPUT_BUFFER_SIZE, HEATSHRINK_WINDOW_SZ2, HEATSHRINK_LOOKAHEAD_SZ2);
	if (hsd == NULL) {
		ERROR (context, "Failed to allocate the heatshrink decoder.");
		return DC_STATUS_NOMEMORY;
	}

	dc_buffer_clear (output);

	size_t sunk_total = 0;
	while (sunk_total < input_size) {
		size_t sunk = 0;
		HSD_sink_res sres = heatshrink_decoder_sink (hsd, (uint8_t *) input + sunk_total, input_size - sunk_total, &sunk);
		if (sres < 0) {
			ERROR (context, "Heatshrink sink error (%d).", sres);
			status = DC_STATUS_DATAFORMAT;
			goto done;
		}
		sunk_total += sunk;

		HSD_poll_res pres;
		do {
			size_t polled = 0;
			pres = heatshrink_decoder_poll (hsd, outbuf, sizeof (outbuf), &polled);
			if (pres < 0) {
				ERROR (context, "Heatshrink poll error (%d).", pres);
				status = DC_STATUS_DATAFORMAT;
				goto done;
			}
			if (polled && !dc_buffer_append (output, outbuf, polled)) {
				ERROR (context, "Failed to allocate memory.");
				status = DC_STATUS_NOMEMORY;
				goto done;
			}
		} while (pres == HSDR_POLL_MORE);
	}

	HSD_finish_res fres = heatshrink_decoder_finish (hsd);
	while (fres == HSDR_FINISH_MORE) {
		HSD_poll_res pres;
		do {
			size_t polled = 0;
			pres = heatshrink_decoder_poll (hsd, outbuf, sizeof (outbuf), &polled);
			if (pres < 0) {
				ERROR (context, "Heatshrink poll error (%d).", pres);
				status = DC_STATUS_DATAFORMAT;
				goto done;
			}
			if (polled && !dc_buffer_append (output, outbuf, polled)) {
				ERROR (context, "Failed to allocate memory.");
				status = DC_STATUS_NOMEMORY;
				goto done;
			}
		} while (pres == HSDR_POLL_MORE);
		fres = heatshrink_decoder_finish (hsd);
	}

done:
	heatshrink_decoder_free (hsd);
	return status;
}

dc_status_t
suunto_nautic_device_download (dc_device_t *abstract, const char *logbook_id, dc_buffer_t *raw)
{
	if (abstract == NULL || abstract->vtable->type != DC_FAMILY_SUUNTO_NAUTIC || logbook_id == NULL || raw == NULL)
		return DC_STATUS_INVALIDARGS;

	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;
	dc_status_t status = DC_STATUS_SUCCESS;

	char path[128];
	int n = snprintf (path, sizeof (path), "/Logbook/byId/%s/Data", logbook_id);
	if (n < 0 || (size_t) n >= sizeof (path))
		return DC_STATUS_INVALIDARGS;

	// 1. Request the file. The watch acknowledges but does not send data yet.
	dc_buffer_t *ack = dc_buffer_new (0);
	if (ack == NULL)
		return DC_STATUS_NOMEMORY;

	status = suunto_nautic_device_request (abstract, path, ack);
	dc_buffer_free (ack);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to request the logbook entry.");
		return status;
	}

	// 2. Trigger the stream (best-effort; see suunto_nautic_fetch*_tail).
	unsigned char fetch[32];
	unsigned int fetch_len = 0;

	status = suunto_nautic_build_stream_fetch (fetch, sizeof (fetch), &fetch_len, device->sequence,
		RPC_OP_STREAM_FETCH1, suunto_nautic_fetch1_tail, sizeof (suunto_nautic_fetch1_tail));
	if (status != DC_STATUS_SUCCESS)
		return status;
	device->sequence++;

	status = dc_iostream_write (device->iostream, fetch, fetch_len, NULL);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to send the first stream-fetch trigger.");
		return status;
	}

	status = suunto_nautic_build_stream_fetch (fetch, sizeof (fetch), &fetch_len, device->sequence,
		RPC_OP_STREAM_FETCH2, suunto_nautic_fetch2_tail, sizeof (suunto_nautic_fetch2_tail));
	if (status != DC_STATUS_SUCCESS)
		return status;
	device->sequence++;

	status = dc_iostream_write (device->iostream, fetch, fetch_len, NULL);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to send the second stream-fetch trigger.");
		return status;
	}

	// 3. Capture the MDS chunk frames (opcode 0x01) and pull out each
	// one's true compressed sub-payload: the MDS header is 28 bytes, and
	// the payload size is a little-endian u16 at offset 20-21 (see the
	// MDS_HEADER_SIZE comment above). The concatenation of these
	// sub-payloads across all chunks is one continuous Heatshrink stream
	// — chunk boundaries are purely a BLE/transport artifact, not
	// boundaries in the compressed data.
	//
	// A ~2400-chunk real single-dive capture (see suunto_nautic.h) shows
	// the chunk stream ending with one RX opcode 0x09 frame right before
	// the client moves on to its next request, so we treat that as a
	// likely end-of-stream marker and stop there. A read timeout is kept
	// as a fallback in case 0x09 turns out to be something else.
	dc_buffer_t *compressed = dc_buffer_new (0);
	if (compressed == NULL)
		return DC_STATUS_NOMEMORY;

	for (unsigned int i = 0; i < MAX_CHUNKS; i++) {
		unsigned char packet[MAX_PACKET] = {0};
		size_t len = 0;
		status = dc_iostream_read (device->iostream, packet, sizeof (packet), &len);
		if (status != DC_STATUS_SUCCESS) {
			if (status == DC_STATUS_TIMEOUT)
				break;
			ERROR (abstract->context, "Failed to receive a stream chunk.");
			dc_buffer_free (compressed);
			return status;
		}

		if (len == 0)
			break;

		if (len >= 2 && packet[0] == 0xA5 && packet[1] == 0x09)
			break;

		if (len >= 2 && packet[0] == 0xA5 && packet[1] == 0x01) {
			if (len < MDS_HEADER_SIZE) {
				WARNING (abstract->context, "MDS chunk shorter than the header (" DC_PRINTF_SIZE ").", len);
				continue;
			}

			unsigned int chunk_size = array_uint16_le (packet + MDS_CHUNK_SIZE_OFFSET);
			if (MDS_HEADER_SIZE + chunk_size > len) {
				WARNING (abstract->context, "MDS chunk size (%u) exceeds the frame (" DC_PRINTF_SIZE ").", chunk_size, len);
				continue;
			}

			if (!dc_buffer_append (compressed, packet + MDS_HEADER_SIZE, chunk_size)) {
				ERROR (abstract->context, "Failed to allocate memory.");
				dc_buffer_free (compressed);
				return DC_STATUS_NOMEMORY;
			}
		}
	}

	DEBUG (abstract->context, "Captured " DC_PRINTF_SIZE " compressed bytes for logbook entry %s.",
		dc_buffer_get_size (compressed), logbook_id);

	// 4. Decompress and verify the SBEM0103 magic.
	status = suunto_nautic_heatshrink_decompress (abstract->context,
		dc_buffer_get_data (compressed), dc_buffer_get_size (compressed), raw);
	dc_buffer_free (compressed);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to decompress the logbook entry.");
		return status;
	}

	if (dc_buffer_get_size (raw) < sizeof (SBEM_MAGIC) ||
		memcmp (dc_buffer_get_data (raw), SBEM_MAGIC, sizeof (SBEM_MAGIC)) != 0) {
		ERROR (abstract->context, "Unexpected magic in the decompressed data.");
		return DC_STATUS_DATAFORMAT;
	}

	DEBUG (abstract->context, "Decompressed " DC_PRINTF_SIZE " bytes for logbook entry %s.",
		dc_buffer_get_size (raw), logbook_id);

	return DC_STATUS_SUCCESS;
}

static dc_status_t
suunto_nautic_device_foreach (dc_device_t *abstract, dc_dive_callback_t callback, void *userdata)
{
	dc_status_t status = DC_STATUS_SUCCESS;

	dc_event_progress_t progress = EVENT_PROGRESS_INITIALIZER;
	progress.maximum = 2;
	device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

	// Connectivity/auth check. Any path works here; /System/Mode is a
	// fixed, id-less endpoint so it works identically on every unit.
	dc_buffer_t *mode = dc_buffer_new (0);
	if (mode == NULL)
		return DC_STATUS_NOMEMORY;

	status = suunto_nautic_device_request (abstract, "/System/Mode", mode);
	if (status != DC_STATUS_SUCCESS) {
		dc_buffer_free (mode);
		ERROR (abstract->context, "Failed to reach /System/Mode. The EVA handshake or RPC "
			"framing may need updating for this device (see suunto_nautic.h).");
		return status;
	}

	dc_event_vendor_t vendor;
	vendor.data = dc_buffer_get_data (mode);
	vendor.size = (unsigned int) dc_buffer_get_size (mode);
	device_event_emit (abstract, DC_EVENT_VENDOR, &vendor);
	dc_buffer_free (mode);

	progress.current = 2;
	device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

	// dc_device_foreach()'s contract is "enumerate real, decodable dives".
	// We deliberately do NOT invoke callback() here: enumerating real
	// logbook entries requires the /Logbook/Entries response format
	// (unknown — no sample exists anywhere as of this writing), and
	// synthesizing a placeholder "dive" would either need a fabricated
	// datetime or would silently fail further down the parser pipeline.
	// Client applications that want raw diagnostic captures (e.g. to
	// reverse-engineer /Logbook/Entries, or to download a specific known
	// dive ID) should call suunto_nautic_device_request() /
	// suunto_nautic_device_download() directly instead of going through
	// this generic enumeration entry point.
	(void) callback;
	(void) userdata;

	return DC_STATUS_SUCCESS;
}

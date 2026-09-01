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

// Logged (INFO) on every device open so a log proves which C driver build
// is running (this submodule can lag the Swift package if a pull doesn't
// update it).
#define SUUNTO_NAUTIC_DRIVER_TAG "2026-09-01-summary-paginated-fetch"

#define RPC_OP_GET           0x0A
#define RPC_OP_STREAM_FETCH1 0x0B
#define RPC_OP_FETCH         0x0D
#define RPC_OP_STREAM_FETCH2 0x10
#define RPC_OP_DATA          0x05

#define RPC_HEADER_SIZE 10 // magic(1) + opcode(1) + sublen(2) + seq(2) + 0x01 + 0x80 + 0x00 + pathlen(1)
#define RPC_CRC_SIZE     4

// Offset of the 3-byte session handle inside an ACK (0x02) or DATA (0x05)
// frame: magic(1) + opcode(1) + sublen(2) + msgid(2).
#define RPC_HANDLE_OFFSET 6
// Offset of the 16-bit LE HTTP-like status inside a DATA (0x05) frame:
// magic(1) + opcode(1) + sublen(2) + msgid(2) + handle(3) + flags(3).
#define RPC_STATUS_OFFSET 12
#define RPC_STATUS_OK       200
#define RPC_STATUS_CONTINUE 100 // more pages follow (paginated fetch)

#define MAX_PATH    240
#define MAX_PACKET  512

// Dive IDs are UNIX timestamps. /Logbook/Entries embeds them as 4-aligned
// little-endian uint32 values in a small SBEM payload among handle/flag/
// count/CRC fields; filtering to a plausible timestamp window (2017 .. 2036)
// isolates them. Must scan 4-aligned -- the IDs are packed adjacently, so an
// unaligned read straddling two can invent a phantom dive.
#define DIVE_ID_MIN 1500000000u
#define DIVE_ID_MAX 2100000000u

// Entry count in the /Logbook/Entries response, a little-endian uint32 at
// this offset into the returned frame content (10-byte REST sub-header +
// SBEM offset 6). Used to cap ID extraction before the SBEM tail bytes.
#define ENTRIES_COUNT_OFFSET 16

// Number of PMT-style chunks to accept before giving up. This is a safety
// cap, not a protocol constant — the real termination condition (how the
// watch signals "no more chunks") is unknown, so we stop on the first read
// timeout instead.
#define MAX_CHUNKS 4096

// Safety cap on paginated-fetch pages (a Summary is a handful of pages).
#define MAX_PAGES 64

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
	// The dive ID (a UNIX timestamp, see suunto_nautic_device_foreach) of
	// the most recently downloaded dive, little-endian, as returned via
	// dc_dive_callback_t's fingerprint parameter. All-zero means "no
	// fingerprint set" (a real dive ID is never 0 -- that would be a
	// 1970 timestamp), matching every other driver's convention.
	unsigned char fingerprint[4];
} suunto_nautic_device_t;

static dc_status_t suunto_nautic_device_set_fingerprint (dc_device_t *abstract, const unsigned char data[], unsigned int size);
static dc_status_t suunto_nautic_device_foreach (dc_device_t *abstract, dc_dive_callback_t callback, void *userdata);
static dc_status_t suunto_nautic_device_close (dc_device_t *abstract);

static const dc_device_vtable_t suunto_nautic_device_vtable = {
	sizeof(suunto_nautic_device_t),
	DC_FAMILY_SUUNTO_NAUTIC,
	suunto_nautic_device_set_fingerprint, /* set_fingerprint */
	NULL, /* read */
	NULL, /* write */
	NULL, /* dump */
	suunto_nautic_device_foreach, /* foreach */
	NULL, /* timesync */
	suunto_nautic_device_close, /* close */
};

static dc_status_t
suunto_nautic_device_set_fingerprint (dc_device_t *abstract, const unsigned char data[], unsigned int size)
{
	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;

	if (size && size != sizeof (device->fingerprint))
		return DC_STATUS_INVALIDARGS;

	if (size)
		memcpy (device->fingerprint, data, sizeof (device->fingerprint));
	else
		memset (device->fingerprint, 0, sizeof (device->fingerprint));

	return DC_STATUS_SUCCESS;
}

/*
 * The "EVA" handshake is really the Whiteboard protocol's own Hello
 * message (message type 0x12; a peer replying in kind, rather than a
 * fixed ack, is what "EVA" was originally mistaken for a no-ack magic
 * blob). Decompiling whiteboard::WhiteboardCommunication::sendHandshake()
 * and whiteboard::SuuntoSerial::{isValid,pack,unpack}() out of the
 * official Android app's libmds.so (build 6.7.12-6007012) showed that
 * every field in this payload is derivable rather than borrowed from
 * whoever's phone captured the original session:
 *
 *   - SuuntoSerial::isValid() accepts any 1-16 character string drawn
 *     from [0-9A-Z] -- there is no cryptographic tie to a specific
 *     phone or account. suunto_nautic_pack_serial() below reimplements
 *     SuuntoSerial::pack()'s bit layout so this driver can use its own
 *     identity (SUUNTO_NAUTIC_OWN_SERIAL) instead of impersonating the
 *     phone that produced the originally captured bytes.
 *   - The Whiteboard protocol-version bytes (offsets 21-28 below) come
 *     from GetWhiteboardVersion(), which in this build parses a
 *     hardcoded "00000000" string rather than anything session-
 *     specific -- a fixed build constant, confirmed byte-for-byte
 *     against the real captured handshake (04 01 02 00 00 00 00 00).
 *   - The capability-flags byte (offset 29) is derived from a *static*
 *     BleAdapter::Traits table baked into the binary (byte value 0x0F)
 *     via a small bit formula in sendHandshake(); running 0x0F through
 *     that formula yields 0x03, which likewise matches the real
 *     captured byte exactly.
 *
 * One region is NOT re-derived and is still replayed as a literal
 * constant from the original capture: offset 8. Decompiling
 * whiteboard::RoutingTable::addRoute() resolved what it is --
 * `pSVar12[0x24] = pool_slot + 1`, where pool_slot comes from
 * Pool::allocate() on the sender's own internal connection-pool
 * allocator. It is never sent for the watch's benefit and nothing
 * validates it, so unlike the identity bytes there is no "correct"
 * value to derive here -- any byte works identically, which is why it
 * is left as a literal constant rather than computed. (The header
 * framing itself -- sync byte, message type, length encoding -- was
 * already understood before this and isn't "unknown," just not
 * dynamically recomputed since none of it varies for this fixed-size
 * payload.) suunto_nautic_build_eva_handshake() rebuilds only the
 * two regions now known to carry the sender's own SuuntoSerial (the 8
 * bytes at offset 9, and a 4-byte second copy of serial bytes 1-4 at
 * offset 17, per sendHandshake()'s own logic) using our own identity,
 * then recomputes the trailing CRC32. This has not been tested against
 * real hardware -- see the request to testers in NauticTestApp/README.md.
 */
#define SUUNTO_NAUTIC_OWN_SERIAL "LIBDIVECOMPUTER"

static const unsigned char suunto_nautic_eva_handshake_template[] = {
	0xA5, 0x12, 0x20, 0x00, 0x00, 0x00, 0x09, 0x09, 0x20, 0x16, 0x45, 0x56,
	0x41, 0x10, 0x04, 0x41, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x04, 0x01, 0x02,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x63, 0x1B, 0x47, 0x1B
};

#define EVA_HANDSHAKE_SIZE       (sizeof (suunto_nautic_eva_handshake_template))
#define EVA_SERIAL_OFFSET        9  // 8 bytes: own SuuntoSerial, raw
#define EVA_SERIAL_ECHO_OFFSET   17 // 4 bytes: own SuuntoSerial bytes 1-4, again
#define EVA_CRC_OFFSET           38 // 4 bytes, LE, over bytes [0, EVA_CRC_OFFSET)

// Packs an uppercase-alphanumeric serial string into the 12-byte
// SuuntoSerial wire representation, reimplementing
// whiteboard::SuuntoSerial::pack() from libmds.so: four characters at a
// time, each mapped to a 6-bit value (char - '/'), three bytes per
// group:
//   byte0 = v0 | (v1 << 6)
//   byte1 = (v1 >> 2) | (v2 << 4)
//   byte2 = (v2 >> 4) | (v3 << 2)
// A group with fewer than 4 remaining characters treats the missing
// ones as 0, matching the real implementation.
static void
suunto_nautic_pack_serial (const char *serial, unsigned char out[12])
{
	memset (out, 0, 12);

	size_t len = strlen (serial);
	for (size_t i = 0; i < 16 && i < len; i += 4) {
		unsigned int v[4] = {0, 0, 0, 0};
		for (size_t j = 0; j < 4 && i + j < len; j++)
			v[j] = (unsigned char) serial[i + j] - 0x2F;

		unsigned char *dst = out + (i / 4) * 3;
		dst[0] = (unsigned char) (v[0] | (v[1] << 6));
		dst[1] = (unsigned char) ((v[1] >> 2) | (v[2] << 4));
		dst[2] = (unsigned char) ((v[2] >> 4) | (v[3] << 2));
	}
}

// Builds the EVA/Hello handshake. Sends the original captured template
// verbatim rather than substituting this driver's own identity: real
// hardware only responds to the verbatim bytes, while the decompiled
// "any valid identity works" theory (see the comment above) is unverified
// on a device. suunto_nautic_pack_serial() is kept below to re-enable the
// self-built identity once that's confirmed.
static void
suunto_nautic_build_eva_handshake (unsigned char packet[EVA_HANDSHAKE_SIZE])
{
	memcpy (packet, suunto_nautic_eva_handshake_template, EVA_HANDSHAKE_SIZE);
}

/*
 * Also captured verbatim. The sequence-number field (bytes 4-5) is the
 * watch's own "Watch Magic" for this transfer plus 1 (FETCH1) or plus 2
 * (FETCH2), read from the ACK response to the preceding GET request --
 * see suunto_nautic_device_download(). The remaining fields do not
 * match a pattern we can derive from the single available sample, so
 * the rest of the frame is replayed literally. This is a best-effort
 * probe, not a verified mechanism — expect it to need correction once
 * real captures from other sessions/devices are available.
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

// Build the "short" fetch (opcode 0x0D) the official app uses to read a
// small whole resource in one shot, e.g. /Logbook/Entries. Payload is
// [seq:2 LE][handle:3][01 80 00 00] -- the trailing 01 80 00 00 is the
// no-range form. NOT the ranged fetch used for large paginated resources
// (Summary/Data), whose payload ends 01 80 00 01 06 00 [offset:4]; sending
// that ranged form to /Logbook/Entries makes the watch reject it with a
// 400 Bad Request.
static dc_status_t
suunto_nautic_build_short_fetch (unsigned char packet[], unsigned int size, unsigned int *out_len,
	unsigned int seq, const unsigned char handle[3])
{
	static const unsigned char tail[] = { 0x01, 0x80, 0x00, 0x00 };
	unsigned int payload = 3 + (unsigned int) sizeof (tail); // handle(3) + tail
	unsigned int len = 4 + 2 + payload + RPC_CRC_SIZE;        // magic+opcode+sublen(4) + seq(2) + payload + crc
	if (len > size)
		return DC_STATUS_INVALIDARGS;

	packet[0] = 0xA5;
	packet[1] = RPC_OP_FETCH;
	// sublen counts seq(2)+payload minus 2, i.e. payload itself.
	array_uint16_le_set (packet + 2, (unsigned short) payload);
	array_uint16_le_set (packet + 4, (unsigned short) seq);
	memcpy (packet + 6, handle, 3);
	memcpy (packet + 9, tail, sizeof (tail));

	unsigned int crc = checksum_crc32r (packet, 6 + payload);
	array_uint32_le_set (packet + 6 + payload, crc);

	*out_len = len;
	return DC_STATUS_SUCCESS;
}

// Build a paginated fetch (opcode 0x0D) for a resource the watch returns
// across multiple pages, e.g. /Logbook/byId/<id>/Summary. Payload is
// [seq:2 LE][handle:3][01 80 00 01 06 00][offset:4 LE] -- the ranged form.
// The watch answers each page with HTTP status 100 (more pages) or 200
// (last page). (Confirmed on real hardware, issue #29.)
static dc_status_t
suunto_nautic_build_paginated_fetch (unsigned char packet[], unsigned int size, unsigned int *out_len,
	unsigned int seq, const unsigned char handle[3], unsigned int offset)
{
	static const unsigned char flags[] = { 0x01, 0x80, 0x00, 0x01, 0x06, 0x00 };
	unsigned int payload = 3 + (unsigned int) sizeof (flags) + 4; // handle(3) + flags(6) + offset(4)
	unsigned int len = 4 + 2 + payload + RPC_CRC_SIZE;
	if (len > size)
		return DC_STATUS_INVALIDARGS;

	packet[0] = 0xA5;
	packet[1] = RPC_OP_FETCH;
	array_uint16_le_set (packet + 2, (unsigned short) payload);
	array_uint16_le_set (packet + 4, (unsigned short) seq);
	memcpy (packet + 6, handle, 3);
	memcpy (packet + 9, flags, sizeof (flags));
	array_uint32_le_set (packet + 9 + (unsigned int) sizeof (flags), offset);

	unsigned int crc = checksum_crc32r (packet, 6 + payload);
	array_uint32_le_set (packet + 6 + payload, crc);

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

	INFO (context, "Suunto Nautic C driver build %s", SUUNTO_NAUTIC_DRIVER_TAG);

	device->sequence = 1;
	memset (device->fingerprint, 0, sizeof (device->fingerprint));

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

	// Best-effort EVA handshake, carrying this driver's own identity
	// (see the comment above suunto_nautic_build_eva_handshake()). We
	// can't validate the response content (its format isn't understood),
	// so we only require that the I/O round-trip succeeds.
	unsigned char eva_handshake[EVA_HANDSHAKE_SIZE];
	suunto_nautic_build_eva_handshake (eva_handshake);

	HEXDUMP (context, DC_LOGLEVEL_DEBUG, "EVA REQ", eva_handshake, sizeof (eva_handshake));

	status = dc_iostream_write (device->iostream, eva_handshake, sizeof (eva_handshake), NULL);
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

// Performs the GET -> ACK(watch magic) -> FETCH1 -> FETCH2 -> stream-collect
// sequence used to pull a large paginated resource (dive data). Returns the
// raw, MDS-chunk-stripped, still-Heatshrink-compressed bytes. Small listing
// endpoints use suunto_nautic_device_short_fetch() instead.
static dc_status_t
suunto_nautic_device_stream_fetch (dc_device_t *abstract, const char *path, dc_buffer_t *raw)
{
	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;
	dc_status_t status = DC_STATUS_SUCCESS;

	// 1. Request the resource. The watch's ACK carries a "Watch Magic"
	// session id (little-endian UInt32 at offset 5) that authorizes this
	// transfer; the two stream-fetch triggers below use Watch_Magic+1/+2.
	dc_buffer_t *ack = dc_buffer_new (0);
	if (ack == NULL)
		return DC_STATUS_NOMEMORY;

	status = suunto_nautic_device_request (abstract, path, ack);
	if (status != DC_STATUS_SUCCESS) {
		dc_buffer_free (ack);
		ERROR (abstract->context, "Failed to request %s.", path);
		return status;
	}

	const unsigned char *ack_data = dc_buffer_get_data (ack);
	size_t ack_size = dc_buffer_get_size (ack);
	if (ack_size < 9) {
		dc_buffer_free (ack);
		ERROR (abstract->context, "ACK response too short to contain the watch magic (" DC_PRINTF_SIZE ").", ack_size);
		return DC_STATUS_DATAFORMAT;
	}
	unsigned int watch_magic = array_uint32_le (ack_data + 5);
	dc_buffer_free (ack);

	// 2. Trigger the stream using Watch_Magic+1/+2.
	unsigned char fetch[32];
	unsigned int fetch_len = 0;

	status = suunto_nautic_build_stream_fetch (fetch, sizeof (fetch), &fetch_len, watch_magic + 1,
		RPC_OP_STREAM_FETCH1, suunto_nautic_fetch1_tail, sizeof (suunto_nautic_fetch1_tail));
	if (status != DC_STATUS_SUCCESS)
		return status;

	status = dc_iostream_write (device->iostream, fetch, fetch_len, NULL);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to send the first stream-fetch trigger.");
		return status;
	}

	status = suunto_nautic_build_stream_fetch (fetch, sizeof (fetch), &fetch_len, watch_magic + 2,
		RPC_OP_STREAM_FETCH2, suunto_nautic_fetch2_tail, sizeof (suunto_nautic_fetch2_tail));
	if (status != DC_STATUS_SUCCESS)
		return status;

	status = dc_iostream_write (device->iostream, fetch, fetch_len, NULL);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to send the second stream-fetch trigger.");
		return status;
	}

	// 3. Capture the MDS chunk frames (opcode 0x01) and pull out each
	// one's true sub-payload: the MDS header is 28 bytes, and the payload
	// size is a little-endian u16 at offset 20-21 (see the MDS_HEADER_SIZE
	// comment above). For a compressed endpoint, the concatenation of
	// these sub-payloads across all chunks is one continuous Heatshrink
	// stream — chunk boundaries are purely a BLE/transport artifact, not
	// boundaries in the compressed data.
	//
	// Per the issue's follow-up report, the watch does not need to be
	// ACKed per chunk: once FETCH2 is sent it blasts the entire stream
	// continuously, and the host is expected to buffer until a 2.0s
	// silence timeout. We also still stop early on an RX opcode 0x09
	// frame (observed ending a ~2400-chunk real capture) as a belt-and-
	// suspenders check, but the 2.0s timeout is the documented mechanism.
	status = dc_iostream_set_timeout (device->iostream, 2000);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to set the stream timeout.");
		return status;
	}

	for (unsigned int i = 0; i < MAX_CHUNKS; i++) {
		unsigned char packet[MAX_PACKET] = {0};
		size_t len = 0;
		status = dc_iostream_read (device->iostream, packet, sizeof (packet), &len);
		if (status != DC_STATUS_SUCCESS) {
			if (status == DC_STATUS_TIMEOUT)
				break;
			ERROR (abstract->context, "Failed to receive a stream chunk.");
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

			if (!dc_buffer_append (raw, packet + MDS_HEADER_SIZE, chunk_size)) {
				ERROR (abstract->context, "Failed to allocate memory.");
				return DC_STATUS_NOMEMORY;
			}
		}
	}

	return DC_STATUS_SUCCESS;
}

// Fetch a resource the watch paginates (e.g. /Logbook/byId/<id>/Summary):
// GET -> ACK(handle) -> repeated ranged 0x0D fetch, looping while the page
// status is 100 (more pages) until 200 (last page), stripping the 10-byte
// REST sub-header from each page and accumulating the raw (uncompressed)
// SBEM bytes into `response`. The per-page REST sub-header (at packet+4) is
// [msgid:2][handle:3][flags:3][status:2 LE].
static dc_status_t
suunto_nautic_device_paginated_fetch (dc_device_t *abstract, const char *path, dc_buffer_t *response)
{
	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;
	dc_status_t status = DC_STATUS_SUCCESS;

	dc_buffer_t *ack = dc_buffer_new (0);
	if (ack == NULL)
		return DC_STATUS_NOMEMORY;

	status = suunto_nautic_device_request (abstract, path, ack);
	if (status != DC_STATUS_SUCCESS) {
		dc_buffer_free (ack);
		ERROR (abstract->context, "Failed to request %s.", path);
		return status;
	}

	const unsigned char *ack_data = dc_buffer_get_data (ack);
	size_t ack_size = dc_buffer_get_size (ack);
	if (ack_size < RPC_HANDLE_OFFSET + 3) {
		dc_buffer_free (ack);
		ERROR (abstract->context, "ACK too short for a handle (" DC_PRINTF_SIZE ").", ack_size);
		return DC_STATUS_DATAFORMAT;
	}
	unsigned char handle[3];
	memcpy (handle, ack_data + RPC_HANDLE_OFFSET, sizeof (handle));
	dc_buffer_free (ack);

	dc_buffer_clear (response);
	unsigned int offset = 0;
	const unsigned int header = 4 + 10; // A5 05 sublen(2) + 10-byte REST sub-header

	for (unsigned int page = 0; page < MAX_PAGES; page++) {
		unsigned char fetch[32];
		unsigned int fetch_len = 0;
		status = suunto_nautic_build_paginated_fetch (fetch, sizeof (fetch), &fetch_len,
			device->sequence, handle, offset);
		if (status != DC_STATUS_SUCCESS)
			return status;
		device->sequence++;

		status = dc_iostream_write (device->iostream, fetch, fetch_len, NULL);
		if (status != DC_STATUS_SUCCESS) {
			ERROR (abstract->context, "Failed to send paginated fetch (offset=%u) for %s.", offset, path);
			return status;
		}

		unsigned char packet[MAX_PACKET] = {0};
		size_t len = 0;
		status = dc_iostream_read (device->iostream, packet, sizeof (packet), &len);
		if (status != DC_STATUS_SUCCESS) {
			ERROR (abstract->context, "Failed to receive page %u for %s.", page, path);
			return status;
		}

		HEXDUMP (abstract->context, DC_LOGLEVEL_DEBUG, "PFETCH RSP", packet, len);

		if (len < RPC_STATUS_OFFSET + 2 || packet[0] != 0xA5 || packet[1] != RPC_OP_DATA) {
			ERROR (abstract->context, "Unexpected frame for %s page %u (" DC_PRINTF_SIZE " bytes).", path, page, len);
			return DC_STATUS_DATAFORMAT;
		}

		unsigned int frame_status = array_uint16_le (packet + RPC_STATUS_OFFSET);
		if (frame_status != RPC_STATUS_OK && frame_status != RPC_STATUS_CONTINUE) {
			ERROR (abstract->context, "Watch returned status %u for %s page %u.", frame_status, path, page);
			return DC_STATUS_PROTOCOL;
		}

		if (len > header) {
			if (!dc_buffer_append (response, packet + header, len - header)) {
				ERROR (abstract->context, "Failed to allocate memory.");
				return DC_STATUS_NOMEMORY;
			}
			offset += (unsigned int) (len - header);
		}

		if (frame_status == RPC_STATUS_OK) {
			DEBUG (abstract->context, "Paginated fetch done: %u page(s), " DC_PRINTF_SIZE " bytes for %s.",
				page + 1, dc_buffer_get_size (response), path);
			return DC_STATUS_SUCCESS;
		}
	}

	WARNING (abstract->context, "Paginated fetch hit the page limit for %s -- data may be truncated.", path);
	return DC_STATUS_SUCCESS;
}

// Fetch a small whole resource (e.g. /Logbook/Entries) via the official
// app's GET -> ACK(handle) -> SHORT-FETCH(0x0D) -> DATA(0x05) flow. The
// listing endpoints don't answer the 0x0B/0x10 stream-fetch triggers, only
// this no-range 0x0D form. `response` receives the raw DATA-frame content
// (everything after the A5 05 sublen header). Assumes the resource fits in
// one DATA frame, which holds for a normal logbook.
static dc_status_t
suunto_nautic_device_short_fetch (dc_device_t *abstract, const char *path, dc_buffer_t *response)
{
	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;
	dc_status_t status = DC_STATUS_SUCCESS;

	// 1. GET the resource; the ACK carries the 3-byte session handle.
	dc_buffer_t *ack = dc_buffer_new (0);
	if (ack == NULL)
		return DC_STATUS_NOMEMORY;

	status = suunto_nautic_device_request (abstract, path, ack);
	if (status != DC_STATUS_SUCCESS) {
		dc_buffer_free (ack);
		ERROR (abstract->context, "Failed to request %s.", path);
		return status;
	}

	const unsigned char *ack_data = dc_buffer_get_data (ack);
	size_t ack_size = dc_buffer_get_size (ack);
	if (ack_size < RPC_HANDLE_OFFSET + 3) {
		dc_buffer_free (ack);
		ERROR (abstract->context, "ACK too short for a handle (" DC_PRINTF_SIZE ").", ack_size);
		return DC_STATUS_DATAFORMAT;
	}
	unsigned char handle[3];
	memcpy (handle, ack_data + RPC_HANDLE_OFFSET, sizeof (handle));
	dc_buffer_free (ack);

	// 2. SHORT fetch (no range header) reads the whole small resource.
	unsigned char fetch[32];
	unsigned int fetch_len = 0;
	status = suunto_nautic_build_short_fetch (fetch, sizeof (fetch), &fetch_len, device->sequence, handle);
	if (status != DC_STATUS_SUCCESS)
		return status;
	device->sequence++;

	status = dc_iostream_write (device->iostream, fetch, fetch_len, NULL);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to send the short fetch for %s.", path);
		return status;
	}

	// 3. Read the single DATA (0x05) frame.
	unsigned char packet[MAX_PACKET] = {0};
	size_t len = 0;
	status = dc_iostream_read (device->iostream, packet, sizeof (packet), &len);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to receive the data for %s.", path);
		return status;
	}

	HEXDUMP (abstract->context, DC_LOGLEVEL_DEBUG, "FETCH RSP", packet, len);

	if (len < RPC_STATUS_OFFSET + 2 || packet[0] != 0xA5 || packet[1] != RPC_OP_DATA) {
		ERROR (abstract->context, "Unexpected data frame for %s (" DC_PRINTF_SIZE " bytes).", path, len);
		return DC_STATUS_DATAFORMAT;
	}

	unsigned int frame_status = array_uint16_le (packet + RPC_STATUS_OFFSET);
	if (frame_status != RPC_STATUS_OK) {
		ERROR (abstract->context, "Watch returned status %u for %s (200 expected).", frame_status, path);
		return DC_STATUS_PROTOCOL;
	}

	// Return the frame content (everything after A5 05 sublen).
	dc_buffer_clear (response);
	if (!dc_buffer_append (response, packet + 4, len - 4)) {
		ERROR (abstract->context, "Failed to allocate memory.");
		return DC_STATUS_NOMEMORY;
	}

	return DC_STATUS_SUCCESS;
}

dc_status_t
suunto_nautic_device_fetch (dc_device_t *abstract, const char *path, dc_buffer_t *response)
{
	if (abstract == NULL || abstract->vtable->type != DC_FAMILY_SUUNTO_NAUTIC || path == NULL || response == NULL)
		return DC_STATUS_INVALIDARGS;

	return suunto_nautic_device_short_fetch (abstract, path, response);
}

dc_status_t
suunto_nautic_device_download_summary (dc_device_t *abstract, const char *logbook_id, dc_buffer_t *summary)
{
	if (abstract == NULL || abstract->vtable->type != DC_FAMILY_SUUNTO_NAUTIC || logbook_id == NULL || summary == NULL)
		return DC_STATUS_INVALIDARGS;

	char path[128];
	int n = snprintf (path, sizeof (path), "/Logbook/byId/%s/Summary", logbook_id);
	if (n < 0 || (size_t) n >= sizeof (path))
		return DC_STATUS_INVALIDARGS;

	// /Summary uses the paginated 0x0D fetch and is NOT compressed -- the
	// result is raw SBEM0103 (the caller locates the signature and reads
	// its fields, e.g. gradient factors and gas mix).
	return suunto_nautic_device_paginated_fetch (abstract, path, summary);
}

dc_status_t
suunto_nautic_device_download (dc_device_t *abstract, const char *logbook_id, dc_buffer_t *raw)
{
	if (abstract == NULL || abstract->vtable->type != DC_FAMILY_SUUNTO_NAUTIC || logbook_id == NULL || raw == NULL)
		return DC_STATUS_INVALIDARGS;

	dc_status_t status = DC_STATUS_SUCCESS;

	char path[128];
	int n = snprintf (path, sizeof (path), "/Logbook/byId/%s/Data", logbook_id);
	if (n < 0 || (size_t) n >= sizeof (path))
		return DC_STATUS_INVALIDARGS;

	dc_buffer_t *compressed = dc_buffer_new (0);
	if (compressed == NULL)
		return DC_STATUS_NOMEMORY;

	status = suunto_nautic_device_stream_fetch (abstract, path, compressed);
	if (status != DC_STATUS_SUCCESS) {
		dc_buffer_free (compressed);
		return status;
	}

	DEBUG (abstract->context, "Captured " DC_PRINTF_SIZE " compressed bytes for logbook entry %s.",
		dc_buffer_get_size (compressed), logbook_id);

	// Decompress and verify the SBEM0103 magic.
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
	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;

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

	progress.current = 1;
	device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

	// /Logbook/Entries returns a small SBEM payload embedding each dive's
	// LogId (a UNIX timestamp) as a 4-aligned little-endian uint32 among
	// handle/flag/count/CRC fields; a timestamp-window filter (DIVE_ID_MIN/
	// MAX) isolates the IDs. Uses the short 0x0D fetch -- the watch rejects
	// the ranged stream-fetch (used for dive data) here.
	dc_buffer_t *entries = dc_buffer_new (0);
	if (entries == NULL)
		return DC_STATUS_NOMEMORY;

	status = suunto_nautic_device_short_fetch (abstract, "/Logbook/Entries", entries);
	if (status != DC_STATUS_SUCCESS) {
		dc_buffer_free (entries);
		ERROR (abstract->context, "Failed to fetch /Logbook/Entries.");
		return status;
	}

	const unsigned char *entries_data = dc_buffer_get_data (entries);
	size_t entries_size = dc_buffer_get_size (entries);

	unsigned int count = 0;
	unsigned int *ids = NULL;
	if (entries_size >= 4) {
		// Cap extraction at the SBEM entry count. The payload ends with a
		// per-request rolling token that can itself fall in the dive-ID
		// window; stopping after `expected` values keeps that tail from
		// being misread as a phantom entry.
		size_t max_ids = entries_size / 4; // at most one id per 4 bytes
		unsigned int expected = (unsigned int) max_ids;
		if (entries_size >= ENTRIES_COUNT_OFFSET + 4) {
			unsigned int n = array_uint32_le (entries_data + ENTRIES_COUNT_OFFSET);
			if (n <= max_ids)
				expected = n;
		}

		ids = (unsigned int *) malloc (max_ids * sizeof (unsigned int));
		if (ids == NULL) {
			dc_buffer_free (entries);
			return DC_STATUS_NOMEMORY;
		}
		for (size_t i = 0; i + 4 <= entries_size && count < expected; i += 4) {
			unsigned int v = array_uint32_le (entries_data + i);
			if (v >= DIVE_ID_MIN && v <= DIVE_ID_MAX)
				ids[count++] = v;
		}
	}
	dc_buffer_free (entries);

	// Sort descending (newest first). The endpoint's own ordering isn't
	// documented; since every ID is itself a UNIX timestamp, sorting
	// ourselves guarantees correct newest-first fingerprint-stop
	// semantics below regardless of what order the watch actually
	// returns them in. A plain insertion sort is fine here -- a dive
	// computer's logbook is realistically dozens to low hundreds of
	// entries, not a scale where O(n^2) matters.
	for (unsigned int i = 1; i < count; i++) {
		unsigned int key = ids[i];
		int j = (int) i - 1;
		while (j >= 0 && ids[j] < key) {
			ids[j + 1] = ids[j];
			j--;
		}
		ids[j + 1] = key;
	}

	progress.maximum = (count + 1) * 2;
	device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

	dc_buffer_t *raw = dc_buffer_new (0);
	if (raw == NULL) {
		free (ids);
		return DC_STATUS_NOMEMORY;
	}

	for (unsigned int i = 0; i < count; i++) {
		unsigned char fingerprint[4] = {
			(unsigned char) (ids[i] & 0xFF),
			(unsigned char) ((ids[i] >> 8) & 0xFF),
			(unsigned char) ((ids[i] >> 16) & 0xFF),
			(unsigned char) ((ids[i] >> 24) & 0xFF),
		};

		// Walking newest-first, so the first fingerprint match means
		// everything from here on was already downloaded in a
		// previous session.
		if (memcmp (fingerprint, device->fingerprint, sizeof (fingerprint)) == 0)
			break;

		char logbook_id[16];
		int n = snprintf (logbook_id, sizeof (logbook_id), "%u", ids[i]);
		if (n < 0 || (size_t) n >= sizeof (logbook_id))
			continue;

		dc_buffer_clear (raw);
		status = suunto_nautic_device_download (abstract, logbook_id, raw);
		if (status != DC_STATUS_SUCCESS) {
			// A logbook can contain empty/aborted entries (a zero-length
			// session is listed in /Logbook/Entries but downloads to no
			// profile data and fails the SBEM magic check). Skip with a
			// warning rather than aborting the whole enumeration.
			WARNING (abstract->context, "Skipping logbook entry %s (download failed, likely an empty/aborted dive).", logbook_id);
			status = DC_STATUS_SUCCESS;
			continue;
		}

		progress.current += 2;
		device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

		if (callback && !callback (dc_buffer_get_data (raw), (unsigned int) dc_buffer_get_size (raw),
			fingerprint, sizeof (fingerprint), userdata))
			break;
	}

	dc_buffer_free (raw);
	free (ids);

	return DC_STATUS_SUCCESS;
}

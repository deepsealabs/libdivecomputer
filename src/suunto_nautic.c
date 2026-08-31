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

// Builds the EVA/Hello handshake. Temporarily sends the original captured
// template verbatim instead of substituting this driver's own identity
// (SUUNTO_NAUTIC_OWN_SERIAL, via suunto_nautic_pack_serial() below): a real
// Suunto Nautic (issue #29, tester urbamax) failed to respond at all to the
// self-built identity, while that same tester's independently-written
// Python client authenticates successfully against that same watch by
// replaying this exact template unmodified. The decompiled "any valid
// identity works" theory (see the comment above) is therefore unverified
// against real hardware where it counts, and the verbatim bytes are
// empirically proven to work -- until the self-built identity is confirmed
// against a real device, sending it is a regression, not an improvement.
// suunto_nautic_pack_serial() is left in place to re-enable once that
// happens; see suunto_nautic.h for tracking.
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
// sequence common to every endpoint whose payload doesn't fit in a single
// ACK (dive data, and now logbook entries -- see suunto_nautic_device_foreach()).
// suunto_nautic_device_request() alone only performs the GET and reads the
// ACK; treating that ACK as the payload (as /Logbook/Entries used to) reads
// Handle/session bytes as if they were the real response, which is why
// entries used to come back as a couple of nonsense IDs instead of the
// actual logbook.
//
// Returns the raw, MDS-chunk-stripped bytes -- still Heatshrink-compressed
// for endpoints known to compress their payload (Data/Summary); Entries is
// not documented as compressed, so callers use the bytes directly. This
// path (the FETCH1/FETCH2 stream-fetch, not just the GET+ACK) has only ever
// been exercised for /Logbook/byId/.../Data via an offline replay of a
// captured stream, and for /Logbook/Entries not at all yet -- see issue #29.
static dc_status_t
suunto_nautic_device_stream_fetch (dc_device_t *abstract, const char *path, dc_buffer_t *raw)
{
	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;
	dc_status_t status = DC_STATUS_SUCCESS;

	// 1. Request the resource. The watch acknowledges with its own "Watch
	// Magic": a session id it generates specifically to authorize this
	// transfer, returned as a little-endian UInt32 at offset 5 in the ACK
	// response. The stream-fetch triggers below need Watch_Magic+1 and
	// +2, not our own request sequence -- confirmed independently on
	// issue #29. Previously the Data path used device->sequence for both,
	// which only worked because it happened to match the watch's magic in
	// the one captured session this was originally derived from.
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

	// /Logbook/Entries returns a flat array of 4-byte little-endian
	// UInt32 dive IDs -- each one is also a UNIX timestamp (the dive
	// start time; see suunto_nautic_parser.c's file header for why no
	// chunk in the decoded profile carries one).
	dc_buffer_t *entries = dc_buffer_new (0);
	if (entries == NULL)
		return DC_STATUS_NOMEMORY;

	status = suunto_nautic_device_stream_fetch (abstract, "/Logbook/Entries", entries);
	if (status != DC_STATUS_SUCCESS) {
		dc_buffer_free (entries);
		ERROR (abstract->context, "Failed to fetch /Logbook/Entries.");
		return status;
	}

	const unsigned char *entries_data = dc_buffer_get_data (entries);
	size_t entries_size = dc_buffer_get_size (entries);
	if (entries_size % 4 != 0) {
		WARNING (abstract->context, "Unexpected /Logbook/Entries size (" DC_PRINTF_SIZE "), truncating to a multiple of 4.", entries_size);
		entries_size -= entries_size % 4;
	}
	unsigned int count = (unsigned int) (entries_size / 4);

	unsigned int *ids = NULL;
	if (count > 0) {
		ids = (unsigned int *) malloc (count * sizeof (unsigned int));
		if (ids == NULL) {
			dc_buffer_free (entries);
			return DC_STATUS_NOMEMORY;
		}
		for (unsigned int i = 0; i < count; i++)
			ids[i] = array_uint32_le (entries_data + i * 4);
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
			ERROR (abstract->context, "Failed to download logbook entry %s.", logbook_id);
			dc_buffer_free (raw);
			free (ids);
			return status;
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

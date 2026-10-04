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

// See suunto_nautic.h for a description of the transport and format.

#define RPC_OP_GET           0x0A
#define RPC_OP_STREAM_FETCH1 0x0B
#define RPC_OP_FETCH         0x0D
#define RPC_OP_STREAM_FETCH2 0x10
#define RPC_OP_STREAM_STOP   0x11 // host -> watch: close the stream and release its handle
#define RPC_OP_STREAM_CHUNK  0x01
#define RPC_OP_ACK           0x02
#define RPC_OP_ACK_ALT       0x03
#define RPC_OP_DATA          0x05
#define RPC_OP_STREAM_START  0x08 // watch -> host: stream accepted (200) or refused (e.g. 423 Locked)
#define RPC_OP_STREAM_END    0x09 // watch -> host: the stream is closed (answers STREAM_STOP)

// Fetch parameter types (Whiteboard type ids): the paged /Summary offset is an
// int32, /Logbook/Entries' StartAfterId a uint32.
#define RPC_PARAM_INT32  0x06
#define RPC_PARAM_UINT32 0x07

#define RPC_HEADER_SIZE 10 // magic(1) + opcode(1) + sublen(2) + seq(2) + 0x01 + 0x80 + 0x00 + pathlen(1)
#define RPC_CRC_SIZE     4

// Offset of the 16-bit LE message id; a reply echoes its request's.
#define RPC_MSGID_OFFSET 4
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

// Each entry stores start then end timestamp adjacently; an end is always
// within a day of its start. Used to pair (start, end) so a dive's end isn't
// listed as a second dive.
#define DIVE_ENTRY_MAX_PAIR_GAP 86400u

// Runaway guard on stream frames, not a protocol limit: the stream ends on
// inter-frame silence or STREAM_END. ~278 B per chunk, so 65536 is ~18 MB; the
// old 4096 cap (~1.14 MB) truncated the end of most real dives.
#define MAX_CHUNKS 65536

// How many times to issue a dive's stream when the watch refuses it (423).
#define STREAM_ATTEMPTS 3

// How many times to download a dive whose size doesn't match its listing.
#define DOWNLOAD_ATTEMPTS 2

// Each /Summary page is [header:11][data][crc:4]; the header carries the data
// length as a u16 at offset 3, and the paging offset counts data bytes only.
#define SUMMARY_PAGE_HEADER_SIZE 11
#define SUMMARY_PAGE_LENGTH_OFFSET 3

// A /Summary is ~2-2.4 KB; bounds the listed-size check when it is missing.
#define SUMMARY_MAX_SIZE 8192

// A /Logbook/Entries record is [start][end][w1][w2][size][pad] (u32 LE each);
// size = compressed /Data + /Summary data bytes, exactly.
#define ENTRY_SIZE_OFFSET 16

// Safety cap on paginated-fetch pages (a Summary is a handful of pages, and
// /Logbook/Entries one page per ~18 dives).
#define MAX_PAGES 64

// The Suunto "MDS" chunk header wrapping each compressed block: 28 bytes,
// with the true payload size as a u16 LE at offset 20 and the compressed
// payload starting at offset 28.
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
 * The "EVA" handshake is the Whiteboard protocol's Hello message (message
 * type 0x12). The payload carries a SuuntoSerial identity, a fixed
 * protocol-version block, a capability-flags byte and a trailing CRC32.
 * The identity has no cryptographic tie to a specific phone, and the watch
 * has only been confirmed to answer the captured template, so it is sent
 * verbatim.
 */
static const unsigned char suunto_nautic_eva_handshake[] = {
	0xA5, 0x12, 0x20, 0x00, 0x00, 0x00, 0x09, 0x09, 0x20, 0x16, 0x45, 0x56,
	0x41, 0x10, 0x04, 0x41, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x04, 0x01, 0x02,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x63, 0x1B, 0x47, 0x1B
};

#define EVA_HANDSHAKE_SIZE (sizeof (suunto_nautic_eva_handshake))

/*
 * Stream-fetch trigger tails, captured verbatim. The sequence-number field
 * (bytes 4-5) is the watch's session handle for this transfer plus 1
 * (FETCH1) or plus 2 (FETCH2), read from the ACK to the preceding GET
 * request; see suunto_nautic_device_download(). The remaining tail bytes
 * are replayed literally.
 */
static const unsigned char suunto_nautic_fetch1_tail[] = {
	0x00, 0x24, 0x12, 0x01, 0x80, 0x00
};
static const unsigned char suunto_nautic_fetch2_tail[] = {
	0x00, 0x24, 0x0E, 0x01, 0x80, 0x00, 0x00
};

// Build a generic path-addressed GET request for an arbitrary endpoint.
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

// Build a 0x0D fetch carrying one 4-byte parameter. Payload is
// [seq:2 LE][handle:3][01 80 00][count=01][type:2 LE][value:4 LE]. Used for the
// paged /Summary (int32 offset, in data bytes) and for /Logbook/Entries pages
// after the first (uint32 StartAfterId). The watch answers each page with
// status 100 (more pages) or 200 (last page).
static dc_status_t
suunto_nautic_build_param_fetch (unsigned char packet[], unsigned int size, unsigned int *out_len,
	unsigned int seq, const unsigned char handle[3], unsigned int type, unsigned int value)
{
	unsigned char flags[] = { 0x01, 0x80, 0x00, 0x01, (unsigned char) type, 0x00 };
	unsigned int payload = 3 + (unsigned int) sizeof (flags) + 4; // handle(3) + flags(6) + value(4)
	unsigned int len = 4 + 2 + payload + RPC_CRC_SIZE;
	if (len > size)
		return DC_STATUS_INVALIDARGS;

	packet[0] = 0xA5;
	packet[1] = RPC_OP_FETCH;
	array_uint16_le_set (packet + 2, (unsigned short) payload);
	array_uint16_le_set (packet + 4, (unsigned short) seq);
	memcpy (packet + 6, handle, 3);
	memcpy (packet + 9, flags, sizeof (flags));
	array_uint32_le_set (packet + 9 + (unsigned int) sizeof (flags), value);

	unsigned int crc = checksum_crc32r (packet, 6 + payload);
	array_uint32_le_set (packet + 6 + payload, crc);

	*out_len = len;
	return DC_STATUS_SUCCESS;
}

// A well-formed RPC frame from the watch starts with the 0xA5 magic and is long
// enough to carry an opcode. Anything shorter is line noise or a truncated read.
static int
suunto_nautic_frame_wellformed (const unsigned char *packet, size_t len)
{
	return len >= 2 && packet[0] == 0xA5;
}

// The reply to a GET: an ACK echoing the request's message id. Anything else
// (a leftover 0x01 chunk of an unfinished stream, another client's traffic) is
// not ours, and taking its handle would address the wrong resource.
static int
suunto_nautic_frame_is_reply (const unsigned char *packet, size_t len, unsigned int msgid)
{
	return len >= RPC_HANDLE_OFFSET + 3 && packet[0] == 0xA5 &&
		(packet[1] == RPC_OP_ACK || packet[1] == RPC_OP_ACK_ALT) &&
		array_uint16_le (packet + RPC_MSGID_OFFSET) == msgid;
}

// The DATA (0x05) frame a fetch is waiting for: our opcode, carrying the 3-byte
// session handle this fetch was issued against.
static int
suunto_nautic_frame_is_our_data (const unsigned char *packet, size_t len, const unsigned char handle[3])
{
	return len >= RPC_HANDLE_OFFSET + 3 &&
		packet[0] == 0xA5 && packet[1] == RPC_OP_DATA &&
		memcmp (packet + RPC_HANDLE_OFFSET, handle, 3) == 0;
}

// A single BLE link is shared: another client (most often the official Suunto
// app holding a live logbook subscription) can flood it with its own frames --
// notably Whiteboard 0x07 subscribe-result traffic on a different handle. Those
// are well-formed frames that just aren't ours, so skip them freely rather than
// treating them as a data error. This cap only guards against an unbounded loop;
// in practice the read below times out first (a clean DC_STATUS_TIMEOUT) when
// our DATA frame never gets a turn on the contended link.
#define MAX_FOREIGN_SKIPS 256
// A tight cap on genuinely malformed/truncated frames: those do signal a real
// data-format problem, so give up quickly with DC_STATUS_DATAFORMAT.
#define MAX_MALFORMED_SKIPS 8

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
		unsigned int msgid = array_uint16_le (req + RPC_MSGID_OFFSET);
		unsigned char packet[MAX_PACKET] = {0};
		size_t len = 0;
		unsigned int foreign_skips = 0;
		unsigned int malformed_skips = 0;
		for (;;) {
			status = dc_iostream_read (device->iostream, packet, sizeof (packet), &len);
			if (status != DC_STATUS_SUCCESS) {
				ERROR (abstract->context, "Failed to receive the RPC response.");
				return status;
			}

			HEXDUMP (abstract->context, DC_LOGLEVEL_DEBUG, "RPC RSP", packet, len);

			if (suunto_nautic_frame_is_reply (packet, len, msgid))
				break;
			if (suunto_nautic_frame_wellformed (packet, len)) {
				if (++foreign_skips >= MAX_FOREIGN_SKIPS) {
					ERROR (abstract->context, "No reply to message %u among the frames on the link.", msgid);
					return DC_STATUS_TIMEOUT;
				}
				WARNING (abstract->context, "Skipping a frame that is not the reply to message %u (op 0x%02x).",
					msgid, packet[1]);
				continue;
			}
			if (++malformed_skips >= MAX_MALFORMED_SKIPS) {
				ERROR (abstract->context, "Too many malformed frames waiting for the reply to message %u.", msgid);
				return DC_STATUS_DATAFORMAT;
			}
			WARNING (abstract->context, "Skipping a malformed frame (" DC_PRINTF_SIZE " bytes).", len);
		}

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

	// Best-effort EVA handshake. The response content can't be validated
	// (its format isn't understood), so only the I/O round-trip is required.
	HEXDUMP (context, DC_LOGLEVEL_DEBUG, "EVA REQ", suunto_nautic_eva_handshake, EVA_HANDSHAKE_SIZE);

	status = dc_iostream_write (device->iostream, suunto_nautic_eva_handshake, EVA_HANDSHAKE_SIZE, NULL);
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

// Append one MDS chunk frame's sub-payload to `raw`. A short or inconsistent
// frame is skipped with a warning; only an allocation failure is fatal.
static dc_status_t
suunto_nautic_append_chunk (dc_context_t *context, dc_buffer_t *raw, const unsigned char *packet, size_t len)
{
	if (len < MDS_HEADER_SIZE) {
		WARNING (context, "MDS chunk shorter than the header (" DC_PRINTF_SIZE ").", len);
		return DC_STATUS_SUCCESS;
	}

	unsigned int chunk_size = array_uint16_le (packet + MDS_CHUNK_SIZE_OFFSET);
	if (MDS_HEADER_SIZE + chunk_size > len) {
		WARNING (context, "MDS chunk size (%u) exceeds the frame (" DC_PRINTF_SIZE ").", chunk_size, len);
		return DC_STATUS_SUCCESS;
	}

	if (!dc_buffer_append (raw, packet + MDS_HEADER_SIZE, chunk_size)) {
		ERROR (context, "Failed to allocate memory.");
		return DC_STATUS_NOMEMORY;
	}

	return DC_STATUS_SUCCESS;
}

// Performs the GET -> ACK(watch magic) -> FETCH1 -> FETCH2 -> stream-collect ->
// STREAM_STOP sequence used to pull a large paginated resource (dive data).
// Returns the raw, MDS-chunk-stripped, still-Heatshrink-compressed bytes. Small
// listing endpoints use suunto_nautic_device_short_fetch() instead. Returns
// DC_STATUS_PROTOCOL when the watch refuses the stream (e.g. 423 Locked), so
// the caller can back off and retry.
static dc_status_t
suunto_nautic_device_stream_fetch (dc_device_t *abstract, const char *path, dc_buffer_t *raw)
{
	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;
	dc_status_t status = DC_STATUS_SUCCESS;

	// 1. Request the resource. The watch's ACK carries a "Watch Magic"
	// session id (little-endian UInt32 at offset 5) that authorizes this
	// transfer; the stream triggers below use Watch_Magic+1/+2 and the
	// STREAM_STOP Watch_Magic+3.
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

	// 3. Capture the MDS chunk frames (opcode 0x01). For a compressed
	// endpoint, the concatenation of their sub-payloads is one continuous
	// Heatshrink stream; chunk boundaries are a transport artifact.
	//
	// The watch is not ACKed per chunk: once FETCH2 is sent it streams the
	// entire response continuously, and the host buffers until a 2.0s
	// inter-frame silence. MAX_CHUNKS is only a runaway guard.
	status = dc_iostream_set_timeout (device->iostream, 2000);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to set the stream timeout.");
		return status;
	}

	unsigned int nframes = 0;
	for (nframes = 0; nframes < MAX_CHUNKS; nframes++) {
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

		if (len >= 2 && packet[0] == 0xA5 && packet[1] == RPC_OP_STREAM_END)
			break;

		// A non-200 stream-start frame is a refusal, notably 423 Locked when
		// the previous stream's handle hasn't been released yet.
		if (len >= RPC_STATUS_OFFSET + 2 && packet[0] == 0xA5 && packet[1] == RPC_OP_STREAM_START) {
			unsigned int frame_status = array_uint16_le (packet + RPC_STATUS_OFFSET);
			if (frame_status != RPC_STATUS_OK) {
				ERROR (abstract->context, "Watch refused the stream for %s (status %u).", path, frame_status);
				return DC_STATUS_PROTOCOL;
			}
		}

		if (len >= 2 && packet[0] == 0xA5 && packet[1] == RPC_OP_STREAM_CHUNK) {
			status = suunto_nautic_append_chunk (abstract->context, raw, packet, len);
			if (status != DC_STATUS_SUCCESS)
				return status;
		}
	}

	if (nframes >= MAX_CHUNKS)
		WARNING (abstract->context, "Stream for %s hit the %u-frame guard; the dive may be truncated.", path, MAX_CHUNKS);

	// 4. Close the stream. Without STREAM_STOP the watch keeps the stream open
	// on its handle, so the next GET can be answered by a leftover chunk or
	// refused with 423. The watch answers with STREAM_END; a trailing chunk
	// or two can still arrive first and belongs to this dive.
	unsigned char stop[32];
	unsigned int stop_len = 0;
	if (suunto_nautic_build_stream_fetch (stop, sizeof (stop), &stop_len, watch_magic + 3,
			RPC_OP_STREAM_STOP, suunto_nautic_fetch2_tail, sizeof (suunto_nautic_fetch2_tail)) == DC_STATUS_SUCCESS &&
		dc_iostream_write (device->iostream, stop, stop_len, NULL) == DC_STATUS_SUCCESS) {
		for (unsigned int i = 0; i < 16; i++) {
			unsigned char packet[MAX_PACKET] = {0};
			size_t len = 0;
			if (dc_iostream_read (device->iostream, packet, sizeof (packet), &len) != DC_STATUS_SUCCESS || len == 0)
				break;
			if (len >= 2 && packet[0] == 0xA5 && packet[1] == RPC_OP_STREAM_END)
				break;
			if (len >= 2 && packet[0] == 0xA5 && packet[1] == RPC_OP_STREAM_CHUNK) {
				status = suunto_nautic_append_chunk (abstract->context, raw, packet, len);
				if (status != DC_STATUS_SUCCESS)
					return status;
			}
		}
	} else {
		WARNING (abstract->context, "Failed to send the stream stop for %s.", path);
	}

	status = dc_iostream_set_timeout (device->iostream, 5000);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to restore the timeout.");
		return status;
	}

	return DC_STATUS_SUCCESS;
}

// GET `path` and return the 3-byte session handle from its ACK; the fetches
// that read the resource are issued against that handle.
static dc_status_t
suunto_nautic_get_handle (dc_device_t *abstract, const char *path, unsigned char handle[3])
{
	dc_buffer_t *ack = dc_buffer_new (0);
	if (ack == NULL)
		return DC_STATUS_NOMEMORY;

	dc_status_t status = suunto_nautic_device_request (abstract, path, ack);
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
	memcpy (handle, ack_data + RPC_HANDLE_OFFSET, 3);
	dc_buffer_free (ack);

	return DC_STATUS_SUCCESS;
}

// Send a fetch frame, then read until the DATA (0x05) frame for `handle`
// arrives. The watch multiplexes unsolicited frames (a re-sent Hello, an
// analytics stream) on the link, and another client (the Suunto app's logbook
// subscription) can flood it, so anything else is skipped rather than spliced
// in. With skip_non_data == 0 the first frame is returned as-is (raw capture).
static dc_status_t
suunto_nautic_fetch_frame (dc_device_t *abstract, const char *path, const unsigned char fetch[], unsigned int fetch_len,
	const unsigned char handle[3], int skip_non_data, unsigned char packet[MAX_PACKET], size_t *out_len)
{
	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;

	dc_status_t status = dc_iostream_write (device->iostream, fetch, fetch_len, NULL);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to send the fetch for %s.", path);
		return status;
	}

	size_t len = 0;
	unsigned int foreign_skips = 0;
	unsigned int malformed_skips = 0;
	for (;;) {
		status = dc_iostream_read (device->iostream, packet, MAX_PACKET, &len);
		if (status != DC_STATUS_SUCCESS) {
			// A contended link means our DATA never gets a turn and this read
			// times out; surface DC_STATUS_TIMEOUT rather than DATAFORMAT.
			ERROR (abstract->context, "Failed to receive the data for %s.", path);
			return status;
		}
		HEXDUMP (abstract->context, DC_LOGLEVEL_DEBUG, "FETCH RSP", packet, len);
		if (!skip_non_data)
			break;
		if (suunto_nautic_frame_is_our_data (packet, len, handle))
			break;
		if (suunto_nautic_frame_wellformed (packet, len)) {
			if (++foreign_skips >= MAX_FOREIGN_SKIPS) {
				ERROR (abstract->context, "Link saturated by another client while fetching %s; giving up.", path);
				return DC_STATUS_TIMEOUT;
			}
			WARNING (abstract->context, "Skipping frame from another client while fetching %s (op 0x%02x).",
				path, packet[1]);
			continue;
		}
		if (++malformed_skips >= MAX_MALFORMED_SKIPS) {
			ERROR (abstract->context, "Too many malformed frames while fetching %s (" DC_PRINTF_SIZE " bytes).", path, len);
			return DC_STATUS_DATAFORMAT;
		}
		WARNING (abstract->context, "Skipping malformed frame while fetching %s (" DC_PRINTF_SIZE " bytes).", path, len);
	}

	*out_len = len;
	return DC_STATUS_SUCCESS;
}

// Status of a DATA frame: 200 (complete / last page) or 100 (more pages).
static dc_status_t
suunto_nautic_data_status (dc_device_t *abstract, const char *path, const unsigned char *packet, size_t len, unsigned int *out)
{
	if (len < RPC_STATUS_OFFSET + 2 || packet[0] != 0xA5 || packet[1] != RPC_OP_DATA) {
		ERROR (abstract->context, "Unexpected data frame for %s (" DC_PRINTF_SIZE " bytes).", path, len);
		return DC_STATUS_DATAFORMAT;
	}

	unsigned int frame_status = array_uint16_le (packet + RPC_STATUS_OFFSET);
	if (frame_status != RPC_STATUS_OK && frame_status != RPC_STATUS_CONTINUE) {
		ERROR (abstract->context, "Watch returned status %u for %s (200/100 expected).", frame_status, path);
		return DC_STATUS_PROTOCOL;
	}

	*out = frame_status;
	return DC_STATUS_SUCCESS;
}

// Fetch a resource the watch paginates (e.g. /Logbook/byId/<id>/Summary):
// GET -> ACK(handle) -> repeated ranged 0x0D fetch, looping while the page
// status is 100 (more pages) until 200 (last page). Each DATA frame is
// [A5 05 sublen:2][msgid:2][handle:3][flags:3][status:2] followed by a page
// [header:11][data][crc:4]; only the data is kept, and the next offset
// advances by the data length (the watch's offset counts data bytes only).
static dc_status_t
suunto_nautic_device_paginated_fetch (dc_device_t *abstract, const char *path, dc_buffer_t *response)
{
	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;
	dc_status_t status = DC_STATUS_SUCCESS;

	unsigned char handle[3];
	status = suunto_nautic_get_handle (abstract, path, handle);
	if (status != DC_STATUS_SUCCESS)
		return status;

	dc_buffer_clear (response);
	unsigned int offset = 0;
	const unsigned int header = 4 + 10; // A5 05 sublen(2) + 10-byte REST sub-header

	for (unsigned int page = 0; page < MAX_PAGES; page++) {
		unsigned char fetch[32];
		unsigned int fetch_len = 0;
		status = suunto_nautic_build_param_fetch (fetch, sizeof (fetch), &fetch_len,
			device->sequence, handle, RPC_PARAM_INT32, offset);
		if (status != DC_STATUS_SUCCESS)
			return status;
		device->sequence++;

		unsigned char packet[MAX_PACKET] = {0};
		size_t len = 0;
		status = suunto_nautic_fetch_frame (abstract, path, fetch, fetch_len, handle, 1, packet, &len);
		if (status != DC_STATUS_SUCCESS)
			return status;

		unsigned int frame_status = 0;
		status = suunto_nautic_data_status (abstract, path, packet, len, &frame_status);
		if (status != DC_STATUS_SUCCESS)
			return status;

		if (len < header + SUMMARY_PAGE_HEADER_SIZE + RPC_CRC_SIZE) {
			ERROR (abstract->context, "Page %u of %s too short for its header (" DC_PRINTF_SIZE " bytes).", page, path, len);
			return DC_STATUS_DATAFORMAT;
		}

		const unsigned char *page_data = packet + header + SUMMARY_PAGE_HEADER_SIZE;
		unsigned int available = (unsigned int) (len - header - SUMMARY_PAGE_HEADER_SIZE - RPC_CRC_SIZE);
		unsigned int length = array_uint16_le (packet + header + SUMMARY_PAGE_LENGTH_OFFSET);
		if (length != available) {
			WARNING (abstract->context, "Page %u of %s: header length %u, frame holds %u.", page, path, length, available);
			if (length > available)
				length = available;
		}

		if (!dc_buffer_append (response, page_data, length)) {
			ERROR (abstract->context, "Failed to allocate memory.");
			return DC_STATUS_NOMEMORY;
		}
		offset += length;

		if (frame_status == RPC_STATUS_OK) {
			DEBUG (abstract->context, "Paginated fetch done: %u page(s), " DC_PRINTF_SIZE " bytes for %s.",
				page + 1, dc_buffer_get_size (response), path);
			return DC_STATUS_SUCCESS;
		}

		if (length == 0) {
			ERROR (abstract->context, "Empty page %u of %s with more pages pending.", page, path);
			return DC_STATUS_PROTOCOL;
		}
	}

	WARNING (abstract->context, "Paginated fetch hit the page limit for %s -- data may be truncated.", path);
	return DC_STATUS_SUCCESS;
}

// GET -> ACK(handle) -> 0x0D short fetch (no range) -> one DATA frame, returned
// whole in `frame`. The listing endpoints don't answer the 0x0B/0x10 stream
// triggers, only this form. With skip_non_data == 0 the very first frame is
// returned, whatever it is, so a tester can export what the watch sent.
static dc_status_t
suunto_nautic_short_fetch_frame (dc_device_t *abstract, const char *path, dc_buffer_t *frame, int skip_non_data)
{
	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;

	unsigned char handle[3];
	dc_status_t status = suunto_nautic_get_handle (abstract, path, handle);
	if (status != DC_STATUS_SUCCESS)
		return status;

	unsigned char fetch[32];
	unsigned int fetch_len = 0;
	status = suunto_nautic_build_short_fetch (fetch, sizeof (fetch), &fetch_len, device->sequence, handle);
	if (status != DC_STATUS_SUCCESS)
		return status;
	device->sequence++;

	unsigned char packet[MAX_PACKET] = {0};
	size_t len = 0;
	status = suunto_nautic_fetch_frame (abstract, path, fetch, fetch_len, handle, skip_non_data, packet, &len);
	if (status != DC_STATUS_SUCCESS)
		return status;

	dc_buffer_clear (frame);
	if (!dc_buffer_append (frame, packet, len)) {
		ERROR (abstract->context, "Failed to allocate memory.");
		return DC_STATUS_NOMEMORY;
	}

	return DC_STATUS_SUCCESS;
}

// Fetch a small whole resource and return its content (everything after
// A5 05 sublen). A status-100 answer is only its first page; /Logbook/Entries
// is paged by suunto_nautic_device_list_entries() instead.
static dc_status_t
suunto_nautic_device_short_fetch (dc_device_t *abstract, const char *path, dc_buffer_t *response)
{
	dc_buffer_t *frame = dc_buffer_new (0);
	if (frame == NULL)
		return DC_STATUS_NOMEMORY;

	dc_status_t status = suunto_nautic_short_fetch_frame (abstract, path, frame, 1);
	if (status != DC_STATUS_SUCCESS) {
		dc_buffer_free (frame);
		return status;
	}

	const unsigned char *packet = dc_buffer_get_data (frame);
	size_t len = dc_buffer_get_size (frame);

	unsigned int frame_status = 0;
	status = suunto_nautic_data_status (abstract, path, packet, len, &frame_status);
	if (status != DC_STATUS_SUCCESS) {
		dc_buffer_free (frame);
		return status;
	}

	dc_buffer_clear (response);
	int ok = dc_buffer_append (response, packet + 4, len - 4);
	dc_buffer_free (frame);
	if (!ok) {
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
suunto_nautic_device_fetch_raw (dc_device_t *abstract, const char *path, dc_buffer_t *response)
{
	if (abstract == NULL || abstract->vtable->type != DC_FAMILY_SUUNTO_NAUTIC || path == NULL || response == NULL)
		return DC_STATUS_INVALIDARGS;

	// Diagnostic: the whole first DATA frame of the short fetch, without
	// status validation. The ranged form is for /Summary only; /Entries
	// rejects it.
	return suunto_nautic_short_fetch_frame (abstract, path, response, 1);
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

// Dive ids and their listed sizes from /Logbook/Entries.
typedef struct suunto_nautic_entries_t {
	unsigned int *ids;
	unsigned int *sizes;
	unsigned int count;
	unsigned int capacity;
} suunto_nautic_entries_t;

static void
suunto_nautic_entries_free (suunto_nautic_entries_t *entries)
{
	free (entries->ids);
	free (entries->sizes);
	memset (entries, 0, sizeof (*entries));
}

static int
suunto_nautic_entries_add (suunto_nautic_entries_t *entries, unsigned int id, unsigned int size)
{
	for (unsigned int i = 0; i < entries->count; i++) {
		if (entries->ids[i] == id)
			return 1;
	}

	if (entries->count == entries->capacity) {
		unsigned int capacity = entries->capacity ? entries->capacity * 2 : 32;
		unsigned int *ids = (unsigned int *) realloc (entries->ids, capacity * sizeof (unsigned int));
		if (ids == NULL)
			return 0;
		entries->ids = ids;
		unsigned int *sizes = (unsigned int *) realloc (entries->sizes, capacity * sizeof (unsigned int));
		if (sizes == NULL)
			return 0;
		entries->sizes = sizes;
		entries->capacity = capacity;
	}

	entries->ids[entries->count] = id;
	entries->sizes[entries->count] = size;
	entries->count++;
	return 1;
}

// Scan one /Logbook/Entries page for (start, end) pairs, in wire order. Each
// record is [start][end][w1][w2][size][pad]: start and end are 4-aligned LE
// uint32s in the dive-ID window, end within a day after start. A lone in-range
// value with no paired end is a header field (the response's own "current
// time"), not a dive. `sizes` may be NULL; a size past the buffer reads as 0.
static unsigned int
suunto_nautic_scan_entries (const unsigned char *data, size_t size,
	unsigned int *ids, unsigned int *sizes, unsigned int max_ids)
{
	unsigned int count = 0;
	for (size_t i = 0; i + 8 <= size && count < max_ids; i += 4) {
		unsigned int v = array_uint32_le (data + i);
		if (v < DIVE_ID_MIN || v > DIVE_ID_MAX)
			continue;
		unsigned int next = array_uint32_le (data + i + 4);
		if (next >= DIVE_ID_MIN && next <= DIVE_ID_MAX &&
				next > v && next - v <= DIVE_ENTRY_MAX_PAIR_GAP) {
			if (sizes)
				sizes[count] = i + ENTRY_SIZE_OFFSET + 4 <= size ? array_uint32_le (data + i + ENTRY_SIZE_OFFSET) : 0;
			ids[count++] = v;
			i += 4; // skip the paired end timestamp
		}
	}
	return count;
}

// Extract dive-start ids from a /Logbook/Entries page, newest-first.
unsigned int
suunto_nautic_extract_entry_ids (const unsigned char *data, size_t size,
	unsigned int *ids, unsigned int max_ids)
{
	unsigned int count = suunto_nautic_scan_entries (data, size, ids, NULL, max_ids);
	// Sort descending (newest first); insertion sort is fine at logbook scale.
	for (unsigned int a = 1; a < count; a++) {
		unsigned int key = ids[a];
		int b = (int) a - 1;
		while (b >= 0 && ids[b] < key) { ids[b + 1] = ids[b]; b--; }
		ids[b + 1] = key;
	}
	return count;
}

// List every dive on the watch, newest-first, with its listed size. The list
// is served oldest-first in pages: a status-100 page is followed by a fetch
// with StartAfterId = the last id received, until a status-200 page. Taking
// page 1 alone drops the newest dives.
static dc_status_t
suunto_nautic_device_list_entries (dc_device_t *abstract, suunto_nautic_entries_t *entries)
{
	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;
	const char *path = "/Logbook/Entries";

	memset (entries, 0, sizeof (*entries));

	unsigned char handle[3];
	dc_status_t status = suunto_nautic_get_handle (abstract, path, handle);
	if (status != DC_STATUS_SUCCESS)
		return status;

	unsigned int start_after = 0;
	for (unsigned int page = 0; page < MAX_PAGES; page++) {
		unsigned char fetch[32];
		unsigned int fetch_len = 0;
		if (page == 0)
			status = suunto_nautic_build_short_fetch (fetch, sizeof (fetch), &fetch_len, device->sequence, handle);
		else
			status = suunto_nautic_build_param_fetch (fetch, sizeof (fetch), &fetch_len,
				device->sequence, handle, RPC_PARAM_UINT32, start_after);
		if (status != DC_STATUS_SUCCESS)
			goto error;
		device->sequence++;

		unsigned char packet[MAX_PACKET] = {0};
		size_t len = 0;
		status = suunto_nautic_fetch_frame (abstract, path, fetch, fetch_len, handle, 1, packet, &len);
		if (status != DC_STATUS_SUCCESS)
			goto error;

		unsigned int frame_status = 0;
		status = suunto_nautic_data_status (abstract, path, packet, len, &frame_status);
		if (status != DC_STATUS_SUCCESS)
			goto error;

		unsigned int ids[MAX_PACKET / 8];
		unsigned int sizes[MAX_PACKET / 8];
		unsigned int count = suunto_nautic_scan_entries (packet + 4, len - 4, ids, sizes, MAX_PACKET / 8);
		for (unsigned int i = 0; i < count; i++) {
			if (!suunto_nautic_entries_add (entries, ids[i], sizes[i])) {
				ERROR (abstract->context, "Failed to allocate memory.");
				status = DC_STATUS_NOMEMORY;
				goto error;
			}
		}

		if (frame_status == RPC_STATUS_OK)
			break;

		if (count == 0 || ids[count - 1] == start_after) {
			WARNING (abstract->context, "%s page %u has no new entries; stopping the listing.", path, page + 1);
			break;
		}
		start_after = ids[count - 1];

		if (page + 1 == MAX_PAGES)
			WARNING (abstract->context, "%s hit the page limit; the newest dives may be missing.", path);
	}

	// Sort descending (newest first), keeping each size with its id.
	for (unsigned int a = 1; a < entries->count; a++) {
		unsigned int id = entries->ids[a], size = entries->sizes[a];
		int b = (int) a - 1;
		while (b >= 0 && entries->ids[b] < id) {
			entries->ids[b + 1] = entries->ids[b];
			entries->sizes[b + 1] = entries->sizes[b];
			b--;
		}
		entries->ids[b + 1] = id;
		entries->sizes[b + 1] = size;
	}

	return DC_STATUS_SUCCESS;

error:
	suunto_nautic_entries_free (entries);
	return status;
}

// Public: list dive ids (each a UNIX-timestamp LogId) newest-first, without
// downloading the dives. Writes the ids as packed little-endian uint32 into
// `out`; the caller reads them as a plain array (no protocol knowledge needed).
dc_status_t
suunto_nautic_device_list (dc_device_t *abstract, dc_buffer_t *out)
{
	if (abstract == NULL || abstract->vtable->type != DC_FAMILY_SUUNTO_NAUTIC || out == NULL)
		return DC_STATUS_INVALIDARGS;

	suunto_nautic_entries_t entries;
	dc_status_t status = suunto_nautic_device_list_entries (abstract, &entries);
	if (status != DC_STATUS_SUCCESS)
		return status;

	dc_buffer_clear (out);
	for (unsigned int i = 0; i < entries.count; i++) {
		unsigned char le[4];
		array_uint32_le_set (le, entries.ids[i]);
		if (!dc_buffer_append (out, le, sizeof (le))) {
			suunto_nautic_entries_free (&entries);
			return DC_STATUS_NOMEMORY;
		}
	}

	suunto_nautic_entries_free (&entries);
	return DC_STATUS_SUCCESS;
}

// Download one dive: the compressed /Data stream (retried while the watch
// refuses it), decompressed, with the /Summary appended. When `listed_size`
// is known (non-zero) the download is checked against it: the listed size is
// compressed /Data + /Summary data bytes, exactly. A mismatch is retried once
// and then reported through `*incomplete`, with the dive left in `raw`.
static dc_status_t
suunto_nautic_device_download_dive (dc_device_t *abstract, const char *logbook_id, unsigned int listed_size,
	dc_buffer_t *raw, int *incomplete)
{
	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;
	dc_status_t status = DC_STATUS_SUCCESS;

	*incomplete = 0;

	char path[128];
	int n = snprintf (path, sizeof (path), "/Logbook/byId/%s/Data", logbook_id);
	if (n < 0 || (size_t) n >= sizeof (path))
		return DC_STATUS_INVALIDARGS;

	dc_buffer_t *compressed = dc_buffer_new (0);
	dc_buffer_t *summary = dc_buffer_new (0);
	if (compressed == NULL || summary == NULL) {
		status = DC_STATUS_NOMEMORY;
		goto done;
	}

	for (unsigned int attempt = 0; attempt < DOWNLOAD_ATTEMPTS; attempt++) {
		for (unsigned int s = 0; s < STREAM_ATTEMPTS; s++) {
			if (s > 0) {
				WARNING (abstract->context, "Retrying the stream of %s (attempt %u/%u).", logbook_id, s + 1, STREAM_ATTEMPTS);
				dc_iostream_sleep (device->iostream, 1500 * s);
			}
			dc_buffer_clear (compressed);
			status = suunto_nautic_device_stream_fetch (abstract, path, compressed);
			if (status != DC_STATUS_PROTOCOL)
				break;
		}
		if (status != DC_STATUS_SUCCESS)
			goto done;

		DEBUG (abstract->context, "Captured " DC_PRINTF_SIZE " compressed bytes for logbook entry %s.",
			dc_buffer_get_size (compressed), logbook_id);

		// Best-effort: the profile alone is still a valid dive without it.
		size_t summary_size = 0;
		if (suunto_nautic_device_download_summary (abstract, logbook_id, summary) == DC_STATUS_SUCCESS)
			summary_size = dc_buffer_get_size (summary);
		else {
			dc_buffer_clear (summary);
			WARNING (abstract->context, "Failed to fetch the Summary for %s; GF/gas will be unavailable.", logbook_id);
		}

		if (listed_size == 0)
			break;

		size_t data_size = dc_buffer_get_size (compressed);
		if (summary_size)
			*incomplete = data_size + summary_size != listed_size;
		else
			*incomplete = data_size > listed_size || listed_size - data_size > SUMMARY_MAX_SIZE;
		if (!*incomplete)
			break;

		WARNING (abstract->context, "Incomplete download of %s: /Data " DC_PRINTF_SIZE " + /Summary " DC_PRINTF_SIZE
			" bytes, listed %u (attempt %u/%u).", logbook_id, data_size, summary_size, listed_size,
			attempt + 1, DOWNLOAD_ATTEMPTS);
	}

	status = suunto_nautic_heatshrink_decompress (abstract->context,
		dc_buffer_get_data (compressed), dc_buffer_get_size (compressed), raw);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to decompress the logbook entry.");
		goto done;
	}

	if (dc_buffer_get_size (raw) < sizeof (SBEM_MAGIC) ||
		memcmp (dc_buffer_get_data (raw), SBEM_MAGIC, sizeof (SBEM_MAGIC)) != 0) {
		ERROR (abstract->context, "Unexpected magic in the decompressed data.");
		status = DC_STATUS_DATAFORMAT;
		goto done;
	}

	DEBUG (abstract->context, "Decompressed " DC_PRINTF_SIZE " bytes for logbook entry %s.",
		dc_buffer_get_size (raw), logbook_id);

	// The /Summary SBEM (gradient factors, gas mix) goes after the profile
	// so the parser can expose them; they aren't in the profile stream.
	if (dc_buffer_get_size (summary) &&
		!dc_buffer_append (raw, dc_buffer_get_data (summary), dc_buffer_get_size (summary)))
		WARNING (abstract->context, "Failed to append the Summary; GF/gas will be unavailable.");

done:
	if (status != DC_STATUS_SUCCESS)
		dc_buffer_clear (raw);
	dc_buffer_free (summary);
	dc_buffer_free (compressed);
	return status;
}

dc_status_t
suunto_nautic_device_download (dc_device_t *abstract, const char *logbook_id, dc_buffer_t *raw)
{
	if (abstract == NULL || abstract->vtable->type != DC_FAMILY_SUUNTO_NAUTIC || logbook_id == NULL || raw == NULL)
		return DC_STATUS_INVALIDARGS;

	// Look up the listed size to verify against; best-effort, since an
	// unlisted or unlistable dive can still be downloaded.
	unsigned int listed_size = 0;
	suunto_nautic_entries_t entries;
	if (suunto_nautic_device_list_entries (abstract, &entries) == DC_STATUS_SUCCESS) {
		unsigned long id = strtoul (logbook_id, NULL, 10);
		for (unsigned int i = 0; i < entries.count; i++) {
			if (entries.ids[i] == id)
				listed_size = entries.sizes[i];
		}
		suunto_nautic_entries_free (&entries);
	}

	int incomplete = 0;
	dc_status_t status = suunto_nautic_device_download_dive (abstract, logbook_id, listed_size, raw, &incomplete);
	if (status == DC_STATUS_SUCCESS && incomplete)
		return DC_STATUS_DATAFORMAT;
	return status;
}

// True for a token that is exactly "<digits>.<digits>.<digits>", each part
// < 256; on success fills a/b/c.
static int
suunto_nautic_parse_version (const char *tok, size_t len, unsigned int *a, unsigned int *b, unsigned int *c)
{
	unsigned int part[3] = {0}, idx = 0, digits = 0;
	for (size_t i = 0; i < len; i++) {
		char ch = tok[i];
		if (ch >= '0' && ch <= '9') {
			part[idx] = part[idx] * 10 + (unsigned int) (ch - '0');
			if (part[idx] > 255 || ++digits > 3)
				return 0;
		} else if (ch == '.') {
			if (digits == 0 || ++idx > 2)
				return 0;
			digits = 0;
		} else {
			return 0;
		}
	}
	if (idx != 2 || digits == 0)
		return 0;
	*a = part[0]; *b = part[1]; *c = part[2];
	return 1;
}

// True for a token that is exactly 12 chars, all [0-9A-F] -- the watch serial
// form, e.g. "2604C3003306".
static int
suunto_nautic_is_serial (const char *tok, size_t len)
{
	if (len != 12)
		return 0;
	for (size_t i = 0; i < len; i++) {
		char ch = tok[i];
		if (!((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F')))
			return 0;
	}
	return 1;
}

/*
 * Best-effort device info. A short fetch of /Info returns a device-identity
 * record: a run of NUL-separated strings mixed in with binary framing bytes,
 *
 *   Suunto\0 Nautic\0 Vaasa\0 T\0 2604C3003306\0 01385D42<hwpart><...>\0
 *     2.55.46\0 <hwpart>\0 ... SIM\0 <mac>\0 BID\0 <build>\0
 *     BLE Mac Address\0 <mac>\0 WiFi Mac Address\0 <mac>\0
 *
 * (confirmed on a live Nautic, firmware 2.55.46, via fetch_device_info.py).
 * The watch serial is the first 12-char uppercase-hex token and the firmware
 * the first "N.N.N" token; the serial always precedes the firmware, and the
 * BLE/WiFi MACs (also 12 hex) come after it -- so stop looking for a serial
 * once the firmware token is seen. Layered on top of the download; every
 * failure path here is non-fatal.
 *
 * dc_event_devinfo_t carries unsigned ints only: the firmware is packed
 * (a << 16) | (b << 8) | c and the hex serial truncated to its low 32 bits.
 * A consumer wanting the faithful strings should read the BLE advertised
 * name (serial) or GET /Info directly (firmware).
 */
static void
suunto_nautic_emit_devinfo (dc_device_t *abstract)
{
	dc_buffer_t *info = dc_buffer_new (0);
	if (info == NULL)
		return;

	if (suunto_nautic_device_short_fetch (abstract, "/Info", info) != DC_STATUS_SUCCESS) {
		dc_buffer_free (info);
		return; // not fatal -- just no device info this time
	}

	const unsigned char *d = dc_buffer_get_data (info);
	size_t n = dc_buffer_get_size (info);

	dc_event_devinfo_t devinfo;
	memset (&devinfo, 0, sizeof (devinfo));

	// Walk NUL-delimited tokens; the record's strings are NUL-terminated, and
	// the binary framing bytes between them fail both tests.
	size_t start = 0;
	for (size_t i = 0; i < n; i++) {
		if (d[i] != 0)
			continue;
		const char *tok = (const char *) (d + start);
		size_t toklen = i - start;
		unsigned int a, b, c;
		if (!devinfo.firmware && suunto_nautic_parse_version (tok, toklen, &a, &b, &c))
			devinfo.firmware = (a << 16) | (b << 8) | c;
		else if (!devinfo.firmware && !devinfo.serial && suunto_nautic_is_serial (tok, toklen)) {
			char buf[13];
			memcpy (buf, tok, 12);
			buf[12] = 0;
			devinfo.serial = (unsigned int) strtoul (buf, NULL, 16);
		}
		start = i + 1;
	}

	dc_buffer_free (info);

	if (devinfo.firmware || devinfo.serial) {
		INFO (abstract->context, "Device info: firmware=%u.%u.%u serial=0x%08x",
			(devinfo.firmware >> 16) & 0xFF, (devinfo.firmware >> 8) & 0xFF,
			devinfo.firmware & 0xFF, devinfo.serial);
		device_event_emit (abstract, DC_EVENT_DEVINFO, &devinfo);
	}
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

	// Best-effort firmware / serial via DC_EVENT_DEVINFO; never fatal.
	suunto_nautic_emit_devinfo (abstract);

	progress.current = 1;
	device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

	// Every listed dive, newest-first, with its listed size (all pages).
	suunto_nautic_entries_t entries;
	status = suunto_nautic_device_list_entries (abstract, &entries);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to fetch /Logbook/Entries.");
		return status;
	}
	unsigned int count = entries.count;

	progress.maximum = (count + 1) * 2;
	device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

	dc_buffer_t *raw = dc_buffer_new (0);
	if (raw == NULL) {
		suunto_nautic_entries_free (&entries);
		return DC_STATUS_NOMEMORY;
	}

	for (unsigned int i = 0; i < count; i++) {
		unsigned char fingerprint[4];
		array_uint32_le_set (fingerprint, entries.ids[i]);

		// Walking newest-first, so the first fingerprint match means
		// everything from here on was already downloaded in a
		// previous session.
		if (memcmp (fingerprint, device->fingerprint, sizeof (fingerprint)) == 0)
			break;

		char logbook_id[16];
		int n = snprintf (logbook_id, sizeof (logbook_id), "%u", entries.ids[i]);
		if (n < 0 || (size_t) n >= sizeof (logbook_id))
			continue;

		dc_buffer_clear (raw);
		int incomplete = 0;
		status = suunto_nautic_device_download_dive (abstract, logbook_id, entries.sizes[i], raw, &incomplete);
		if (status != DC_STATUS_SUCCESS) {
			// A logbook can contain empty/aborted entries (a zero-length
			// session is listed in /Logbook/Entries but downloads to no
			// profile data and fails the SBEM magic check). Skip with a
			// warning rather than aborting the whole enumeration.
			WARNING (abstract->context, "Skipping logbook entry %s (download failed, likely an empty/aborted dive).", logbook_id);
			status = DC_STATUS_SUCCESS;
			continue;
		}

		// Delivered anyway: skipping it would move the fingerprint past a
		// dive that a later sync could never fetch again.
		if (incomplete)
			WARNING (abstract->context, "Logbook entry %s does not match its listed size; the dive may be truncated.", logbook_id);

		progress.current += 2;
		device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

		if (callback && !callback (dc_buffer_get_data (raw), (unsigned int) dc_buffer_get_size (raw),
			fingerprint, sizeof (fingerprint), userdata))
			break;
	}

	dc_buffer_free (raw);
	suunto_nautic_entries_free (&entries);

	return DC_STATUS_SUCCESS;
}

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
#include <libdivecomputer/suunto_nautic.h>
#include "context-private.h"
#include "device-private.h"
#include "platform.h"
#include "checksum.h"
#include "array.h"
#include "hdlc.h"
#include "heatshrink/heatshrink_decoder.h"

#include <libdivecomputer/datetime.h>

// See suunto_nautic.h for a description of the transport and format.

#define RPC_OP_NOTIFICATION      0x01 // watch -> host: one chunk of a subscribed stream
#define RPC_OP_GET_REPLY         0x02
#define RPC_OP_RELEASE_REPLY     0x03
#define RPC_OP_DATA              0x05 // watch -> host: answers FETCH
#define RPC_OP_SUBSCRIBE_REPLY   0x08
#define RPC_OP_UNSUBSCRIBE_REPLY 0x09
#define RPC_OP_GET               0x0A // host -> watch: resolve a path to a handle
#define RPC_OP_RELEASE           0x0B // host -> watch: release a handle bound by a GET
#define RPC_OP_FETCH             0x0D
#define RPC_OP_SUBSCRIBE         0x10
#define RPC_OP_UNSUBSCRIBE       0x11
#define RPC_OP_HELLO             0x12
#define RPC_OP_HELLO_REPLY       0x13

// Packet: 0xA5 OPCODE LENGTH(2) SEQNUM(2) PAYLOAD(LENGTH) CRC32(4)
#define RPC_START    0xA5
#define RPC_OVERHEAD 10
#define MAX_PAYLOAD  512
#define MAX_PATH     240

// HTTP-like status codes carried in the replies.
#define STATUS_OK       200
#define STATUS_CONTINUE 100 // more pages follow

// A GET of a per-id path (/Logbook/byId/<id>/...) binds the id to one of the
// resource's handle slots, [00|10] 24 <resource>, until a RELEASE frees it. A
// second GET while the 00 slot is still bound gets the 10 slot. Static paths
// answer with an F0 handle and an unknown path with FF FF FF; neither is
// released. The slot is the first byte on the wire.
#define HANDLE_SLOT(handle) ((handle) & 0xFF)
#define SLOT_DEFAULT 0x00
#define SLOT_ALT     0x10
#define SLOT_STATIC  0xF0
#define SLOT_UNKNOWN 0xFF

// Fetch parameter types: the /Summary page offset is an int32, the
// /Logbook/Entries start id a uint32.
#define PARAM_INT32  0x06
#define PARAM_UINT32 0x07

// Reply payloads start with HANDLE(3) FLAGS(3) STATUS(2); a DATA reply then
// carries the content.
#define REPLY_STATUS  6
#define REPLY_CONTENT 8

// Stream notification payload:
// HANDLE(3) FLAGS(3) UNKNOWN(4) OFFSET(4) LENGTH(2) UNKNOWN(6) DATA(LENGTH)
// OFFSET is the position of the chunk in the stream. The last chunk has a
// zero length, at an offset equal to the total size.
#define CHUNK_OFFSET 10
#define CHUNK_LENGTH 14
#define CHUNK_DATA   22

// A /Summary page is HEADER(11) DATA, with the data length at offset 3 of
// the header. The paging offset counts data bytes only.
#define PAGE_HEADER 11
#define PAGE_LENGTH 3

// /Logbook/Entries is HEADER(18) RECORD(24) x COUNT, with the count at offset
// 6 of the header. A record is START(4) END(4) UNKNOWN(8) SIZE(4) UNKNOWN(4):
// the start time is the dive id, and the size is the compressed /Data plus
// the /Summary data bytes. An empty logbook can omit the end of the header.
#define ENTRIES_HEADER 18
#define ENTRIES_COUNT  6
#define ENTRY_SIZE     24
#define ENTRY_START    0
#define ENTRY_LENGTH   16

// A /Summary is about 2.3 KB; bounds the size check when it is missing.
#define SUMMARY_MAX_SIZE 8192

// How many times to issue a dive's stream when the watch refuses it with
// status 423 (Locked), and to download a dive whose size doesn't match the
// listing.
#define STREAM_ATTEMPTS   3
#define DOWNLOAD_ATTEMPTS 2

// Coexisting with another app (the Suunto app) on the shared BLE link. When the
// other app opens its own session, the watch answers its hello on the link we
// share and ends our stream (a torn chunk, or UNSUBSCRIBE_REPLY with status
// 404). The driver then steps aside: it stops sending, reads until the other
// app's traffic has been quiet for YIELD_QUIET_MS, and restarts the dive
// without a new hello (the Suunto app answers a hello by re-opening its own
// session, a ping-pong). Our session survives the other app's hello.
#define YIELD_POLL_MS  1000
#define YIELD_QUIET_MS 15000 // longer than the Suunto app's ~10.6 s hello retry, so it gets in
#define YIELD_MAX_S    3600 // wait as long as the other app stays busy (cancellable); quiet ends it sooner
#define MAX_YIELDS     5
#define OPEN_LISTEN_MS 1500
// Before our own hello, a request without one: the watch answers it only when
// another app already has a session on the link (a fresh link stays silent).
// Then we use that session: a hello of ours would take it over, and a Suunto
// app that doesn't answer with a hello of its own stops getting its replies.
#define OPEN_PROBE_MS  1500
#define OPEN_PROBE_PATH "/Logbook/Entries"

#define TIMEOUT_DEFAULT 5000
#define TIMEOUT_STREAM  4000 // the gap between two chunks reaches about 2s

// Heatshrink (LZSS) parameters used by the Nautic/Ocean's MDS stream.
#define HEATSHRINK_WINDOW_SZ2    7
#define HEATSHRINK_LOOKAHEAD_SZ2 5
#define HEATSHRINK_INPUT_BUFFER_SIZE 256

static const unsigned char SBEM_MAGIC[8] = {'S','B','E','M','0','1','0','3'};

// The sequence number to continue from on the next connection. The Suunto
// app's carry on across connections too, so a reconnect never repeats one
// the watch still holds from the dropped session.
static unsigned int g_suunto_nautic_seqnum = 0;

typedef struct suunto_nautic_device_t {
	dc_device_t base;
	dc_iostream_t *iostream; // HDLC-framed
	unsigned int seqnum;
	// Whether the watch answered the hello (extension API).
	int acknowledged;
	// The dive id (a UNIX timestamp) of the most recently downloaded dive,
	// little-endian. All-zero means no fingerprint.
	unsigned char fingerprint[4];
	// Another app opened a session on the shared link while we were
	// streaming; cleared once we've stepped aside.
	int contended;
	// The handle of a stream left open by a takeover, stopped and released
	// once the link is quiet again (0 = none).
	unsigned int stale_handle;
	// Set once a download has stepped aside for another app: a 423 (Locked)
	// after that means the other app is still streaming, so pause again.
	int yielded;
	// The handle of the stream in progress (0 = none). The watch has one
	// handle for streaming a dive's /Data, shared by every client: another
	// app's GET of a dive's /Data re-points it, and our subscription then
	// carries that app's dive.
	unsigned int stream_handle;
	// The takeover was another app binding the stream handle to its own
	// dive, i.e. it is downloading dives: wait it out, don't count it.
	int rebound;
	// Packets for other requests or streams skipped since last cleared.
	unsigned int skipped;
} suunto_nautic_device_t;

// Dive ids and their listed sizes, newest first.
typedef struct suunto_nautic_entries_t {
	unsigned int *ids;
	unsigned int *sizes;
	unsigned int count;
	unsigned int capacity;
} suunto_nautic_entries_t;

static dc_status_t suunto_nautic_device_set_fingerprint (dc_device_t *abstract, const unsigned char data[], unsigned int size);
static dc_status_t suunto_nautic_device_foreach (dc_device_t *abstract, dc_dive_callback_t callback, void *userdata);
static dc_status_t suunto_nautic_device_close (dc_device_t *abstract);
static dc_status_t suunto_nautic_wait_quiet (suunto_nautic_device_t *device, unsigned int *packets);

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

// The Hello payload: the protocol versions (9, 9), the host identity (the one
// the Suunto app sends, a packed 12-byte serial), the Whiteboard version
// (4.1.2) and capability flags. The watch answers with the same fields for
// itself.
static const unsigned char suunto_nautic_hello[] = {
	0x09, 0x09, 0x20, 0x16, 0x45, 0x56, 0x41, 0x10,
	0x04, 0x41, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x04,
	0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const unsigned char suunto_nautic_noparams[] = {0x00};

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

static unsigned int
suunto_nautic_seqnum (suunto_nautic_device_t *device)
{
	// Zero is the sequence number of the stream notifications.
	device->seqnum = (device->seqnum + 1) & 0xFFFF;
	if (device->seqnum == 0)
		device->seqnum = 1;

	return device->seqnum;
}

static dc_status_t
suunto_nautic_send (suunto_nautic_device_t *device, unsigned char opcode, unsigned int seqnum, const unsigned char data[], size_t size)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	unsigned char packet[RPC_OVERHEAD + MAX_PAYLOAD] = {0};

	if (size > MAX_PAYLOAD)
		return DC_STATUS_INVALIDARGS;

	packet[0] = RPC_START;
	packet[1] = opcode;
	array_uint16_le_set (packet + 2, size);
	array_uint16_le_set (packet + 4, seqnum);
	if (size)
		memcpy (packet + 6, data, size);

	unsigned int crc = checksum_crc32r (packet, 6 + size);
	array_uint32_le_set (packet + 6 + size, crc);

	status = dc_iostream_write (device->iostream, packet, RPC_OVERHEAD + size, NULL);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (device->base.context, "Failed to send the packet.");
		return status;
	}

	return status;
}

// Receive the packet with the given opcode and sequence number. The watch
// serves every app connected to it over the same link, so the replies to
// another app's requests can arrive in between. Those are recognized by their
// sequence number and skipped.
static dc_status_t
suunto_nautic_recv (suunto_nautic_device_t *device, unsigned char opcode, unsigned int seqnum, unsigned char data[], size_t size, size_t *actual)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	unsigned char packet[RPC_OVERHEAD + MAX_PAYLOAD] = {0};
	size_t length = 0;

	if (size > MAX_PAYLOAD)
		return DC_STATUS_INVALIDARGS;

	while (1) {
		status = dc_iostream_read (device->iostream, packet, sizeof(packet), &length);
		if (status != DC_STATUS_SUCCESS) {
			ERROR (device->base.context, "Failed to receive the packet.");
			return status;
		}

		if (length == 0) {
			// Two flags in a row, e.g. after the tail of a packet that was
			// cut off when an earlier link dropped.
			continue;
		}

		// While streaming, a packet cut short is the watch abandoning our
		// chunk mid-frame to answer another app's hello. That hello reply is
		// usually lost with it: its opening flag closed the torn packet.
		int streaming = opcode == RPC_OP_NOTIFICATION;

		if (length < RPC_OVERHEAD) {
			ERROR (device->base.context, "Unexpected packet size (" DC_PRINTF_SIZE ").", length);
			device->contended |= streaming;
			return DC_STATUS_PROTOCOL;
		}

		unsigned int crc = array_uint32_le (packet + length - 4);
		unsigned int ccrc = checksum_crc32r (packet, length - 4);
		if (crc != ccrc) {
			ERROR (device->base.context, "Unexpected packet checksum (%08x %08x).", crc, ccrc);
			device->contended |= streaming;
			return DC_STATUS_PROTOCOL;
		}

		if (packet[0] != RPC_START) {
			ERROR (device->base.context, "Unexpected packet start byte (%02x).", packet[0]);
			return DC_STATUS_PROTOCOL;
		}

		unsigned int rsp_length = array_uint16_le (packet + 2);
		if (rsp_length != length - RPC_OVERHEAD) {
			ERROR (device->base.context, "Unexpected packet payload length (%u " DC_PRINTF_SIZE ").", rsp_length, length - RPC_OVERHEAD);
			device->contended |= streaming;
			return DC_STATUS_PROTOCOL;
		}

		unsigned int rsp_opcode = packet[1];
		unsigned int rsp_seqnum = array_uint16_le (packet + 4);
		if (rsp_opcode != opcode || rsp_seqnum != seqnum) {
			// Another app said hello: its session now has the link. A
			// request keeps waiting for its reply (the watch still answers
			// it); a stream is about to be ended, so give it up.
			if (rsp_opcode == RPC_OP_HELLO_REPLY && opcode != RPC_OP_HELLO_REPLY) {
				WARNING (device->base.context, "Another app opened a session on the link.");
				device->skipped++;
				if (streaming) {
					device->contended = 1;
					return DC_STATUS_PROTOCOL;
				}
				continue;
			}
			// Another app is using our stream's handle: a GET or SUBSCRIBE
			// binds it to its own dive (our subscription then carries its
			// data), an UNSUBSCRIBE ends our stream, a FETCH reads through it.
			if (streaming && device->stream_handle && rsp_length >= 3 &&
				rsp_opcode != RPC_OP_NOTIFICATION && rsp_opcode != RPC_OP_HELLO_REPLY &&
				(array_uint24_le (packet + 6) & ~0xFFu) == (device->stream_handle & ~0xFFu)) {
				WARNING (device->base.context, "Another app took over the stream's handle (%06x).", array_uint24_le (packet + 6));
				device->contended = 1;
				device->rebound = 1;
				return DC_STATUS_PROTOCOL;
			}
			// The watch ended our stream itself (status 404) for that session.
			if (streaming && rsp_opcode == RPC_OP_UNSUBSCRIBE_REPLY && rsp_length >= REPLY_CONTENT &&
				array_uint16_le (packet + 6 + REPLY_STATUS) != STATUS_OK) {
				WARNING (device->base.context, "The watch ended the stream (status %u).",
					array_uint16_le (packet + 6 + REPLY_STATUS));
				device->contended = 1;
				return DC_STATUS_PROTOCOL;
			}
			device->skipped++;
			if (rsp_opcode == RPC_OP_NOTIFICATION) {
				// A leftover chunk of a stream that was stopped.
				DEBUG (device->base.context, "Skipping a stream notification.");
			} else {
				WARNING (device->base.context, "Skipping a packet for another request (%02x %u).", rsp_opcode, rsp_seqnum);
			}
			continue;
		}

		if (rsp_length > size) {
			ERROR (device->base.context, "Unexpected packet payload length (%u " DC_PRINTF_SIZE ").", rsp_length, size);
			return DC_STATUS_PROTOCOL;
		}

		memcpy (data, packet + 6, rsp_length);
		*actual = rsp_length;

		return status;
	}
}

// Send a request on a handle and receive its reply: the payload is the handle
// and its 01 80 00 resource flags, followed by the parameters, if any.
static dc_status_t
suunto_nautic_transfer (suunto_nautic_device_t *device, unsigned char opcode, unsigned char rsp_opcode,
	unsigned int handle, const unsigned char params[], size_t nparams, unsigned char data[], size_t size, size_t *actual)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	unsigned char request[6 + 7] = {0};

	if (nparams > sizeof(request) - 6)
		return DC_STATUS_INVALIDARGS;

	array_uint24_le_set (request, handle);
	request[3] = 0x01;
	request[4] = 0x80;
	request[5] = 0x00;
	if (nparams)
		memcpy (request + 6, params, nparams);

	unsigned int seqnum = suunto_nautic_seqnum (device);
	status = suunto_nautic_send (device, opcode, seqnum, request, 6 + nparams);
	if (status != DC_STATUS_SUCCESS)
		return status;

	status = suunto_nautic_recv (device, rsp_opcode, seqnum, data, size, actual);
	if (status != DC_STATUS_SUCCESS)
		return status;

	if (*actual < REPLY_CONTENT) {
		ERROR (device->base.context, "Unexpected reply size (" DC_PRINTF_SIZE ").", *actual);
		return DC_STATUS_PROTOCOL;
	}

	return status;
}

static dc_status_t suunto_nautic_get (suunto_nautic_device_t *device, const char *path, unsigned int *handle, unsigned int *result);

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

	// Start at a different sequence number on every connection. After a
	// dropped link the watch can still hold the previous session, and leaves a
	// request unanswered that reuses one of its sequence numbers.
	device->seqnum = ((unsigned int) dc_datetime_now () * 2654435761u) & 0xFFFF;
	if (g_suunto_nautic_seqnum)
		device->seqnum = g_suunto_nautic_seqnum;
	memset (device->fingerprint, 0, sizeof (device->fingerprint));
	device->acknowledged = 0;
	device->contended = 0;
	device->stale_handle = 0;
	device->yielded = 0;
	device->stream_handle = 0;
	device->rebound = 0;
	device->skipped = 0;

	status = dc_hdlc_open (&device->iostream, context, iostream, 244, 244);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to open the HDLC layer.");
		goto error_free;
	}

	status = dc_iostream_set_timeout (device->iostream, TIMEOUT_DEFAULT);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to set the timeout.");
		goto error_close;
	}

	dc_iostream_purge (device->iostream, DC_DIRECTION_ALL);

	// Another app (the Suunto app) may already be using the watch on this
	// shared link. Listen briefly before the hello: if it is mid-sync, wait
	// until its traffic stops instead of cutting into it. (The host can't be
	// told yet: events are only wired up after open returns.)
	if (dc_iostream_set_timeout (device->iostream, OPEN_LISTEN_MS) == DC_STATUS_SUCCESS) {
		unsigned char probe[RPC_OVERHEAD + MAX_PAYLOAD] = {0};
		size_t probe_len = 0;
		if (dc_iostream_read (device->iostream, probe, sizeof (probe), &probe_len) == DC_STATUS_SUCCESS && probe_len) {
			INFO (context, "Another app is using the watch; waiting until it is done before the hello.");
			unsigned int packets = 0;
			status = suunto_nautic_wait_quiet (device, &packets);
			if (status != DC_STATUS_SUCCESS)
				goto error_close;
			INFO (context, "The link is quiet (%u more packets from the other app).", packets);
		}
	}
	status = dc_iostream_set_timeout (device->iostream, OPEN_PROBE_MS);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to set the timeout.");
		goto error_close;
	}
	// The watch doesn't answer it while another client's stream is running:
	// if other traffic arrived meanwhile, wait for quiet and ask again.
	int shared = 0;
	for (unsigned int round = 0; round < 2 && !shared; round++) {
		unsigned int probe_handle = 0, probe_result = 0;
		device->skipped = 0;
		shared = suunto_nautic_get (device, OPEN_PROBE_PATH, &probe_handle, &probe_result) == DC_STATUS_SUCCESS;
		if (shared || device->skipped == 0)
			break;
		INFO (context, "Another app is using the watch; waiting until it is done.");
		unsigned int packets = 0;
		status = suunto_nautic_wait_quiet (device, &packets);
		if (status != DC_STATUS_SUCCESS)
			goto error_close;
		status = dc_iostream_set_timeout (device->iostream, OPEN_PROBE_MS);
		if (status != DC_STATUS_SUCCESS) {
			ERROR (context, "Failed to set the timeout.");
			goto error_close;
		}
	}

	status = dc_iostream_set_timeout (device->iostream, TIMEOUT_DEFAULT);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to set the timeout.");
		goto error_close;
	}

	if (!shared) {
		INFO (context, "No other session on the link (the request above went unanswered, as expected); saying hello.");
	} else {
		INFO (context, "Another app has a session on the link; using it instead of a hello of our own.");
		device->acknowledged = 1;
		*out = (dc_device_t *) device;
		return DC_STATUS_SUCCESS;
	}

	status = suunto_nautic_send (device, RPC_OP_HELLO, 0, suunto_nautic_hello, sizeof (suunto_nautic_hello));
	if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to send the hello.");
		goto error_close;
	}

	unsigned char hello[sizeof (suunto_nautic_hello)] = {0};
	size_t hello_len = 0;
	status = suunto_nautic_recv (device, RPC_OP_HELLO_REPLY, 0, hello, sizeof (hello), &hello_len);
	if (status == DC_STATUS_TIMEOUT) {
		// A sleeping watch doesn't answer. Carry on, so the host can tell
		// the diver to wake it when the first request times out.
		WARNING (context, "No reply to the hello; continuing.");
		status = DC_STATUS_SUCCESS;
	} else if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to receive the hello.");
		goto error_close;
	} else {
		device->acknowledged = 1;
	}

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

	g_suunto_nautic_seqnum = device->seqnum ? device->seqnum : 1;

	return dc_iostream_close (device->iostream);
}

// Resolve a path to a handle. The GET reply is HANDLE(3) FLAGS(3) STATUS(2).
static dc_status_t
suunto_nautic_get (suunto_nautic_device_t *device, const char *path, unsigned int *handle, unsigned int *result)
{
	dc_status_t status = DC_STATUS_SUCCESS;

	size_t pathlen = strlen (path);
	if (pathlen == 0 || pathlen > MAX_PATH)
		return DC_STATUS_INVALIDARGS;

	unsigned char request[4 + MAX_PATH] = {0};
	request[0] = 0x01;
	request[1] = 0x80;
	request[2] = 0x00;
	request[3] = pathlen;
	memcpy (request + 4, path, pathlen);

	unsigned int seqnum = suunto_nautic_seqnum (device);
	status = suunto_nautic_send (device, RPC_OP_GET, seqnum, request, 4 + pathlen);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (device->base.context, "Failed to send the request for %s.", path);
		return status;
	}

	unsigned char reply[REPLY_CONTENT] = {0};
	size_t reply_len = 0;
	status = suunto_nautic_recv (device, RPC_OP_GET_REPLY, seqnum, reply, sizeof (reply), &reply_len);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (device->base.context, "Failed to receive the reply for %s.", path);
		return status;
	}

	if (reply_len != sizeof (reply)) {
		ERROR (device->base.context, "Unexpected reply size (" DC_PRINTF_SIZE ").", reply_len);
		return DC_STATUS_PROTOCOL;
	}

	*handle = array_uint24_le (reply);
	*result = array_uint16_le (reply + REPLY_STATUS);

	return status;
}

// Release a handle bound by a GET, so the next GET of the same resource binds
// its own id to the slot. A failure only leaves the slot bound.
static void
suunto_nautic_release (suunto_nautic_device_t *device, unsigned int handle)
{
	if (HANDLE_SLOT (handle) == SLOT_STATIC || HANDLE_SLOT (handle) == SLOT_UNKNOWN)
		return;

	unsigned char reply[REPLY_CONTENT] = {0};
	size_t reply_len = 0;
	dc_status_t status = suunto_nautic_transfer (device, RPC_OP_RELEASE, RPC_OP_RELEASE_REPLY,
		handle, NULL, 0, reply, sizeof (reply), &reply_len);
	if (status != DC_STATUS_SUCCESS || array_uint16_le (reply + REPLY_STATUS) != STATUS_OK)
		WARNING (device->base.context, "Failed to release handle %06x.", handle);
}

// Resolve a path that must exist.
static dc_status_t
suunto_nautic_get_handle (suunto_nautic_device_t *device, const char *path, unsigned int *handle)
{
	unsigned int result = 0;
	dc_status_t status = suunto_nautic_get (device, path, handle, &result);
	if (status != DC_STATUS_SUCCESS)
		return status;

	if (result != STATUS_OK) {
		ERROR (device->base.context, "Failed to resolve %s (status %u).", path, result);
		return DC_STATUS_PROTOCOL;
	}

	// Every handle is released before the next GET, so a still bound 00 slot
	// was left by a link that dropped during a transfer.
	if (HANDLE_SLOT (*handle) == SLOT_ALT) {
		WARNING (device->base.context, "Releasing the stale slot of %s.", path);
		suunto_nautic_release (device, (*handle & ~0xFFu) | SLOT_DEFAULT);
	}

	return status;
}

// Decompress a Heatshrink (LZSS) stream, with the parameters above.
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

// Download a streamed resource (the dive profile): GET, SUBSCRIBE, the
// notifications up to the end marker, UNSUBSCRIBE and RELEASE. Returns the
// still compressed stream. Returns DC_STATUS_PROTOCOL when the watch refuses
// the stream (status 423 while the previous stream's handle is still bound).
static dc_status_t
suunto_nautic_stream (suunto_nautic_device_t *device, const char *path, dc_buffer_t *buffer)
{
	dc_device_t *abstract = (dc_device_t *) device;
	dc_status_t status = DC_STATUS_SUCCESS;
	dc_status_t rc = DC_STATUS_SUCCESS;

	unsigned int handle = 0;
	status = suunto_nautic_get_handle (device, path, &handle);
	if (status != DC_STATUS_SUCCESS)
		return status;

	unsigned char reply[REPLY_CONTENT + 2] = {0};
	size_t reply_len = 0;
	status = suunto_nautic_transfer (device, RPC_OP_SUBSCRIBE, RPC_OP_SUBSCRIBE_REPLY,
		handle, suunto_nautic_noparams, sizeof (suunto_nautic_noparams), reply, sizeof (reply), &reply_len);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to subscribe to %s.", path);
		goto error_release;
	}

	unsigned int result = array_uint16_le (reply + REPLY_STATUS);
	if (result != STATUS_OK) {
		// After stepping aside once, 423 (Locked) means the other app is still
		// streaming its own dives: wait for it again rather than fail.
		if (result == 423 && device->yielded) {
			WARNING (abstract->context, "The watch is still busy with another app (status 423); pausing again.");
			device->contended = 1;
		} else {
			ERROR (abstract->context, "The watch refused the stream for %s (status %u).", path, result);
		}
		status = DC_STATUS_PROTOCOL;
		goto error_release;
	}

	device->stream_handle = handle;
	status = dc_iostream_set_timeout (device->iostream, TIMEOUT_STREAM);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to set the timeout.");
		goto error_unsubscribe;
	}

	// The watch streams the whole resource without acknowledgements, and
	// repeats its last chunk until the subscription ends.
	dc_buffer_clear (buffer);
	while (1) {
		if (device_is_cancelled (abstract)) {
			status = DC_STATUS_CANCELLED;
			break;
		}

		unsigned char chunk[MAX_PAYLOAD] = {0};
		size_t chunk_len = 0;
		status = suunto_nautic_recv (device, RPC_OP_NOTIFICATION, 0, chunk, sizeof (chunk), &chunk_len);
		if (status == DC_STATUS_TIMEOUT) {
			WARNING (abstract->context, "The stream for %s ended without an end marker.", path);
			status = DC_STATUS_SUCCESS;
			break;
		}
		if (status != DC_STATUS_SUCCESS) {
			ERROR (abstract->context, "Failed to receive the stream for %s.", path);
			break;
		}

		// Another app's subscriptions (the Suunto app holds several) push
		// their values on the same link, as notifications with the same
		// opcode and sequence number as our chunks but a different handle.
		// Compare without the slot byte: our chunks carry the handle with
		// slot F0, the GET reply with slot 00.
		if (chunk_len >= 3 && (array_uint24_le (chunk) & ~0xFFu) != (handle & ~0xFFu)) {
			DEBUG (abstract->context, "Skipping a notification for another subscription (%06x).", array_uint24_le (chunk));
			continue;
		}

		if (chunk_len < CHUNK_DATA) {
			ERROR (abstract->context, "Unexpected chunk size (" DC_PRINTF_SIZE ").", chunk_len);
			status = DC_STATUS_PROTOCOL;
			break;
		}

		unsigned int offset = array_uint32_le (chunk + CHUNK_OFFSET);
		unsigned int length = array_uint16_le (chunk + CHUNK_LENGTH);
		if (CHUNK_DATA + length > chunk_len) {
			ERROR (abstract->context, "Unexpected chunk length (%u " DC_PRINTF_SIZE ").", length, chunk_len);
			status = DC_STATUS_PROTOCOL;
			break;
		}

		size_t received = dc_buffer_get_size (buffer);
		if (offset < received) {
			// A repeated chunk.
			continue;
		}
		if (offset > received) {
			ERROR (abstract->context, "Missing stream data (%u " DC_PRINTF_SIZE ").", offset, received);
			status = DC_STATUS_PROTOCOL;
			break;
		}

		if (length == 0)
			break;

		if (!dc_buffer_append (buffer, chunk + CHUNK_DATA, length)) {
			ERROR (abstract->context, "Failed to allocate memory.");
			status = DC_STATUS_NOMEMORY;
			break;
		}
	}

error_unsubscribe:
	// Without the UNSUBSCRIBE the watch keeps streaming, and the next GET of a
	// stream is refused with status 423. After another app took over, our
	// stream is already gone and the request would land in its session.
	if (!device->contended) {
		rc = suunto_nautic_transfer (device, RPC_OP_UNSUBSCRIBE, RPC_OP_UNSUBSCRIBE_REPLY,
			handle, suunto_nautic_noparams, sizeof (suunto_nautic_noparams), reply, sizeof (reply), &reply_len);
		if (rc != DC_STATUS_SUCCESS)
			WARNING (abstract->context, "Failed to unsubscribe from %s.", path);
	}

	rc = dc_iostream_set_timeout (device->iostream, TIMEOUT_DEFAULT);
	if (rc != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to restore the timeout.");
		dc_status_set_error (&status, rc);
	}

error_release:
	device->stream_handle = 0;
	if (!device->contended)
		suunto_nautic_release (device, handle);
	else
		device->stale_handle = handle;
	return status;
}

// Read and discard packets until the link has been quiet for YIELD_QUIET_MS
// (or YIELD_MAX_S has passed): the other app's traffic, and the leftovers of
// the stream the watch cut short. Returns the number of packets seen.
static dc_status_t
suunto_nautic_wait_quiet (suunto_nautic_device_t *device, unsigned int *packets)
{
	dc_device_t *abstract = (dc_device_t *) device;
	dc_status_t status = DC_STATUS_SUCCESS;

	*packets = 0;
	status = dc_iostream_set_timeout (device->iostream, YIELD_POLL_MS);
	if (status != DC_STATUS_SUCCESS)
		return status;

	dc_ticks_t start = dc_datetime_now ();
	unsigned int quiet = 0;
	while (quiet < YIELD_QUIET_MS) {
		if (device_is_cancelled (abstract)) {
			status = DC_STATUS_CANCELLED;
			break;
		}
		if (dc_datetime_now () - start >= YIELD_MAX_S) {
			WARNING (abstract->context, "The link is still busy after %u s; carrying on.", YIELD_MAX_S);
			break;
		}
		unsigned char packet[RPC_OVERHEAD + MAX_PAYLOAD] = {0};
		size_t length = 0;
		dc_status_t rc = dc_iostream_read (device->iostream, packet, sizeof (packet), &length);
		if (rc == DC_STATUS_TIMEOUT) {
			quiet += YIELD_POLL_MS;
			continue;
		}
		if (rc != DC_STATUS_SUCCESS) {
			status = rc;
			break;
		}
		if (length) {
			(*packets)++;
			quiet = 0;
		}
	}

	dc_status_t rc = dc_iostream_set_timeout (device->iostream, TIMEOUT_DEFAULT);
	if (rc != DC_STATUS_SUCCESS)
		dc_status_set_error (&status, rc);
	return status;
}

// Step aside for another app: tell the host (a WAITING event, e.g. "paused:
// the Suunto app is syncing") and wait until the other app's traffic stops.
// No hello afterwards (see YIELD_QUIET_MS). `*yields` caps the pauses per dive.
static dc_status_t
suunto_nautic_yield (suunto_nautic_device_t *device, unsigned int *yields)
{
	dc_device_t *abstract = (dc_device_t *) device;

	device->contended = 0;
	// Another app downloading dives (it re-pointed our stream handle) is a
	// deliberate sync: wait it out however many dives it takes. The cap is
	// for everything else, e.g. an app stuck reconnecting.
	int counted = !device->rebound;
	device->rebound = 0;
	if (counted && ++*yields > MAX_YIELDS) {
		ERROR (abstract->context, "Another app took over the watch %u times; giving up.", MAX_YIELDS);
		return DC_STATUS_TIMEOUT;
	}

	device->yielded = 1;
	if (counted)
		INFO (abstract->context, "Another app is using the watch; pausing until it is done (pause %u/%u).",
			*yields, MAX_YIELDS);
	else
		INFO (abstract->context, "Another app is downloading dives; pausing until it is done (not counted).");
	device_event_emit (abstract, DC_EVENT_WAITING, NULL);

	unsigned int packets = 0;
	dc_status_t status = suunto_nautic_wait_quiet (device, &packets);
	if (status != DC_STATUS_SUCCESS)
		return status;

	// The takeover may not have ended our stream on the watch: stop and
	// release it now, or the restart is refused with 423 (Locked). Best
	// effort: if the watch already ended it, these just fail.
	if (device->stale_handle) {
		unsigned char reply[REPLY_CONTENT + 2] = {0};
		size_t reply_len = 0;
		if (suunto_nautic_transfer (device, RPC_OP_UNSUBSCRIBE, RPC_OP_UNSUBSCRIBE_REPLY, device->stale_handle,
			suunto_nautic_noparams, sizeof (suunto_nautic_noparams), reply, sizeof (reply), &reply_len) != DC_STATUS_SUCCESS)
			DEBUG (abstract->context, "No reply to the stop of the interrupted stream.");
		suunto_nautic_release (device, device->stale_handle);
		device->stale_handle = 0;
	}

	INFO (abstract->context, "The link is quiet again (%u packets from the other app); resuming.", packets);
	return DC_STATUS_SUCCESS;
}

// Read a paged resource (/Summary). Each page is requested by the offset of
// its data, and the last page has status 200.
static dc_status_t
suunto_nautic_fetch_pages (suunto_nautic_device_t *device, const char *path, dc_buffer_t *buffer)
{
	dc_device_t *abstract = (dc_device_t *) device;
	dc_status_t status = DC_STATUS_SUCCESS;

	unsigned int handle = 0;
	status = suunto_nautic_get_handle (device, path, &handle);
	if (status != DC_STATUS_SUCCESS)
		return status;

	dc_buffer_clear (buffer);
	unsigned int offset = 0;
	while (1) {
		unsigned char params[7] = {0x01, PARAM_INT32, 0x00};
		array_uint32_le_set (params + 3, offset);

		unsigned char reply[MAX_PAYLOAD] = {0};
		size_t reply_len = 0;
		status = suunto_nautic_transfer (device, RPC_OP_FETCH, RPC_OP_DATA,
			handle, params, sizeof (params), reply, sizeof (reply), &reply_len);
		if (status != DC_STATUS_SUCCESS) {
			ERROR (abstract->context, "Failed to fetch %s (offset %u).", path, offset);
			break;
		}

		unsigned int result = array_uint16_le (reply + REPLY_STATUS);
		if (result != STATUS_OK && result != STATUS_CONTINUE) {
			ERROR (abstract->context, "Failed to fetch %s (status %u).", path, result);
			status = DC_STATUS_PROTOCOL;
			break;
		}

		if (reply_len < REPLY_CONTENT + PAGE_HEADER) {
			ERROR (abstract->context, "Unexpected page size (" DC_PRINTF_SIZE ").", reply_len);
			status = DC_STATUS_PROTOCOL;
			break;
		}

		unsigned int length = array_uint16_le (reply + REPLY_CONTENT + PAGE_LENGTH);
		if (REPLY_CONTENT + PAGE_HEADER + length > reply_len) {
			ERROR (abstract->context, "Unexpected page length (%u " DC_PRINTF_SIZE ").", length, reply_len);
			status = DC_STATUS_PROTOCOL;
			break;
		}

		if (!dc_buffer_append (buffer, reply + REPLY_CONTENT + PAGE_HEADER, length)) {
			ERROR (abstract->context, "Failed to allocate memory.");
			status = DC_STATUS_NOMEMORY;
			break;
		}
		offset += length;

		if (result == STATUS_OK)
			break;

		if (length == 0) {
			ERROR (abstract->context, "Empty page with more pages pending.");
			status = DC_STATUS_PROTOCOL;
			break;
		}
	}

	suunto_nautic_release (device, handle);
	return status;
}

// Read a small resource that fits in a single reply (/Info).
static dc_status_t
suunto_nautic_fetch (suunto_nautic_device_t *device, const char *path, dc_buffer_t *buffer)
{
	dc_device_t *abstract = (dc_device_t *) device;
	dc_status_t status = DC_STATUS_SUCCESS;

	unsigned int handle = 0;
	status = suunto_nautic_get_handle (device, path, &handle);
	if (status != DC_STATUS_SUCCESS)
		return status;

	unsigned char reply[MAX_PAYLOAD] = {0};
	size_t reply_len = 0;
	status = suunto_nautic_transfer (device, RPC_OP_FETCH, RPC_OP_DATA,
		handle, suunto_nautic_noparams, sizeof (suunto_nautic_noparams), reply, sizeof (reply), &reply_len);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to fetch %s.", path);
		goto error_release;
	}

	unsigned int result = array_uint16_le (reply + REPLY_STATUS);
	if (result != STATUS_OK) {
		ERROR (abstract->context, "Failed to fetch %s (status %u).", path, result);
		status = DC_STATUS_PROTOCOL;
		goto error_release;
	}

	dc_buffer_clear (buffer);
	if (!dc_buffer_append (buffer, reply + REPLY_CONTENT, reply_len - REPLY_CONTENT)) {
		ERROR (abstract->context, "Failed to allocate memory.");
		status = DC_STATUS_NOMEMORY;
	}

error_release:
	suunto_nautic_release (device, handle);
	return status;
}

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

// List the dives, newest first. The list is served oldest first, in pages: a
// page with status 100 is followed by a fetch for the dives after the last id
// received, until a page with status 200.
static dc_status_t
suunto_nautic_list (suunto_nautic_device_t *device, suunto_nautic_entries_t *entries)
{
	dc_device_t *abstract = (dc_device_t *) device;
	dc_status_t status = DC_STATUS_SUCCESS;
	const char *path = "/Logbook/Entries";

	memset (entries, 0, sizeof (*entries));

	unsigned int handle = 0;
	status = suunto_nautic_get_handle (device, path, &handle);
	if (status != DC_STATUS_SUCCESS)
		return status;

	unsigned int last = 0;
	for (unsigned int page = 0; ; page++) {
		unsigned char params[7] = {0x01, PARAM_UINT32, 0x00};
		array_uint32_le_set (params + 3, last);

		unsigned char reply[MAX_PAYLOAD] = {0};
		size_t reply_len = 0;
		if (page == 0)
			status = suunto_nautic_transfer (device, RPC_OP_FETCH, RPC_OP_DATA,
				handle, suunto_nautic_noparams, sizeof (suunto_nautic_noparams), reply, sizeof (reply), &reply_len);
		else
			status = suunto_nautic_transfer (device, RPC_OP_FETCH, RPC_OP_DATA,
				handle, params, sizeof (params), reply, sizeof (reply), &reply_len);
		if (status != DC_STATUS_SUCCESS) {
			ERROR (abstract->context, "Failed to fetch %s.", path);
			break;
		}

		unsigned int result = array_uint16_le (reply + REPLY_STATUS);
		if (result != STATUS_OK && result != STATUS_CONTINUE) {
			ERROR (abstract->context, "Failed to fetch %s (status %u).", path, result);
			status = DC_STATUS_PROTOCOL;
			break;
		}

		const unsigned char *data = reply + REPLY_CONTENT;
		size_t size = reply_len - REPLY_CONTENT;
		if (size < ENTRIES_COUNT + 2) {
			ERROR (abstract->context, "Unexpected entries size (" DC_PRINTF_SIZE ").", size);
			status = DC_STATUS_PROTOCOL;
			break;
		}

		unsigned int count = array_uint16_le (data + ENTRIES_COUNT);
		if (count && ENTRIES_HEADER + count * ENTRY_SIZE > size) {
			ERROR (abstract->context, "Unexpected number of entries (%u " DC_PRINTF_SIZE ").", count, size);
			status = DC_STATUS_PROTOCOL;
			break;
		}

		unsigned int previous = last;
		for (unsigned int i = 0; i < count; i++) {
			const unsigned char *record = data + ENTRIES_HEADER + i * ENTRY_SIZE;
			last = array_uint32_le (record + ENTRY_START);
			if (!suunto_nautic_entries_add (entries, last, array_uint32_le (record + ENTRY_LENGTH))) {
				ERROR (abstract->context, "Failed to allocate memory.");
				status = DC_STATUS_NOMEMORY;
				break;
			}
		}
		if (status != DC_STATUS_SUCCESS)
			break;

		if (result == STATUS_OK)
			break;

		if (count == 0 || last == previous) {
			ERROR (abstract->context, "No new entries with more pages pending.");
			status = DC_STATUS_PROTOCOL;
			break;
		}
	}

	suunto_nautic_release (device, handle);

	if (status != DC_STATUS_SUCCESS) {
		suunto_nautic_entries_free (entries);
		return status;
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

	return status;
}

// Download one dive: the decompressed /Data stream with the /Summary
// appended. The listed size is the compressed /Data plus the /Summary data
// bytes, exactly. A mismatch is retried once and then reported through
// `incomplete`, with the dive left in `buffer`. `unreadable` is set when the
// transfer matched the listing but holds no dive (an empty or aborted
// logbook entry), so downloading it again cannot help.
static dc_status_t
suunto_nautic_download (suunto_nautic_device_t *device, unsigned int id, unsigned int listed,
	dc_buffer_t *buffer, int *incomplete, int *unreadable)
{
	dc_device_t *abstract = (dc_device_t *) device;
	dc_status_t status = DC_STATUS_SUCCESS;

	*incomplete = 0;
	*unreadable = 0;

	char data_path[64], summary_path[64];
	snprintf (data_path, sizeof (data_path), "/Logbook/byId/%u/Data", id);
	snprintf (summary_path, sizeof (summary_path), "/Logbook/byId/%u/Summary", id);

	dc_buffer_t *compressed = dc_buffer_new (0);
	dc_buffer_t *summary = dc_buffer_new (0);
	if (compressed == NULL || summary == NULL) {
		ERROR (abstract->context, "Failed to allocate memory.");
		status = DC_STATUS_NOMEMORY;
		goto error_free;
	}

	unsigned int yields = 0;
	for (unsigned int attempt = 0; attempt < DOWNLOAD_ATTEMPTS; attempt++) {
		for (unsigned int i = 0; i < STREAM_ATTEMPTS; i++) {
			if (i > 0) {
				WARNING (abstract->context, "Retrying the stream of dive %u.", id);
				dc_iostream_sleep (device->iostream, 1500 * i);
			}
			status = suunto_nautic_stream (device, data_path, compressed);
			// Taken over mid-stream: step aside, then restart this dive's
			// stream from the beginning (it can't resume partway). A pause
			// doesn't use up a retry.
			if (device->contended) {
				WARNING (abstract->context, "Stream of dive %u interrupted after " DC_PRINTF_SIZE " bytes; restarting it after the pause.",
					id, dc_buffer_get_size (compressed));
				status = suunto_nautic_yield (device, &yields);
				if (status != DC_STATUS_SUCCESS)
					goto error_free;
				i = (unsigned int) -1; // the increment brings it back to 0
				continue;
			}
			if (status != DC_STATUS_PROTOCOL)
				break;
		}
		if (status != DC_STATUS_SUCCESS)
			goto error_free;

		// The profile is still a valid dive without the /Summary.
		size_t summary_size = 0;
		if (suunto_nautic_fetch_pages (device, summary_path, summary) == DC_STATUS_SUCCESS) {
			summary_size = dc_buffer_get_size (summary);
		} else {
			WARNING (abstract->context, "Failed to fetch the summary of dive %u.", id);
			dc_buffer_clear (summary);
		}

		if (listed == 0)
			break;

		size_t data_size = dc_buffer_get_size (compressed);
		if (summary_size)
			*incomplete = data_size + summary_size != listed;
		else
			*incomplete = data_size > listed || listed - data_size > SUMMARY_MAX_SIZE;
		if (!*incomplete)
			break;

		WARNING (abstract->context, "Incomplete download of dive %u (" DC_PRINTF_SIZE " + " DC_PRINTF_SIZE " bytes, listed %u).",
			id, data_size, summary_size, listed);

		// After another app has had the watch, a wrong size most likely means
		// its traffic got into our stream: step aside again and redo the dive
		// rather than keep a truncated or mixed one.
		if (device->yielded) {
			status = suunto_nautic_yield (device, &yields);
			if (status != DC_STATUS_SUCCESS)
				goto error_free;
			attempt = (unsigned int) -1; // the increment brings it back to 0
			continue;
		}
	}

	status = suunto_nautic_heatshrink_decompress (abstract->context,
		dc_buffer_get_data (compressed), dc_buffer_get_size (compressed), buffer);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to decompress dive %u.", id);
		*unreadable = status == DC_STATUS_DATAFORMAT && !*incomplete;
		goto error_free;
	}

	if (dc_buffer_get_size (buffer) < sizeof (SBEM_MAGIC) ||
		memcmp (dc_buffer_get_data (buffer), SBEM_MAGIC, sizeof (SBEM_MAGIC)) != 0) {
		ERROR (abstract->context, "Unexpected magic in dive %u.", id);
		status = DC_STATUS_DATAFORMAT;
		*unreadable = !*incomplete;
		goto error_free;
	}

	// The /Summary goes after the profile, so the parser can read the fields
	// that are not in the profile (gradient factors, gas mixes).
	if (!dc_buffer_append (buffer, dc_buffer_get_data (summary), dc_buffer_get_size (summary))) {
		ERROR (abstract->context, "Failed to allocate memory.");
		status = DC_STATUS_NOMEMORY;
	}

error_free:
	if (status != DC_STATUS_SUCCESS)
		dc_buffer_clear (buffer);
	dc_buffer_free (summary);
	dc_buffer_free (compressed);
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

// /Info is a run of NUL-terminated strings mixed with binary fields:
//
//   Suunto\0 Nautic\0 Vaasa\0 T\0 2604C3003306\0 ... 2.55.46\0 ...
//     BLE Mac Address\0 <mac>\0 WiFi Mac Address\0 <mac>\0
//
// The serial is the first 12-character uppercase hex string, and the firmware
// the first "N.N.N" string, which follows the serial. The MAC addresses after
// it are also 12 hex characters. The serial is reported as its low 32 bits.
static dc_status_t
suunto_nautic_devinfo (suunto_nautic_device_t *device)
{
	dc_device_t *abstract = (dc_device_t *) device;
	dc_status_t status = DC_STATUS_SUCCESS;

	dc_buffer_t *info = dc_buffer_new (0);
	if (info == NULL) {
		ERROR (abstract->context, "Failed to allocate memory.");
		return DC_STATUS_NOMEMORY;
	}

	status = suunto_nautic_fetch (device, "/Info", info);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to read the device info.");
		dc_buffer_free (info);
		return status;
	}

	const unsigned char *data = dc_buffer_get_data (info);
	size_t size = dc_buffer_get_size (info);

	dc_event_devinfo_t devinfo;
	memset (&devinfo, 0, sizeof (devinfo));

	size_t start = 0;
	for (size_t i = 0; i < size; i++) {
		if (data[i] != 0)
			continue;
		const char *token = (const char *) (data + start);
		size_t length = i - start;
		unsigned int a, b, c;
		if (!devinfo.firmware && suunto_nautic_parse_version (token, length, &a, &b, &c)) {
			devinfo.firmware = (a << 16) | (b << 8) | c;
		} else if (!devinfo.firmware && !devinfo.serial && suunto_nautic_is_serial (token, length)) {
			char serial[13];
			memcpy (serial, token, 12);
			serial[12] = 0;
			devinfo.serial = (unsigned int) strtoul (serial, NULL, 16);
		}
		start = i + 1;
	}

	dc_buffer_free (info);

	if (devinfo.firmware == 0 || devinfo.serial == 0) {
		ERROR (abstract->context, "Failed to find the firmware and serial in the device info.");
		return DC_STATUS_DATAFORMAT;
	}

	device_event_emit (abstract, DC_EVENT_DEVINFO, &devinfo);

	return status;
}

static dc_status_t
suunto_nautic_device_foreach (dc_device_t *abstract, dc_dive_callback_t callback, void *userdata)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;

	dc_event_progress_t progress = EVENT_PROGRESS_INITIALIZER;
	progress.maximum = 2;
	device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

	status = suunto_nautic_devinfo (device);
	if (status != DC_STATUS_SUCCESS)
		return status;

	progress.current = 1;
	device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

	suunto_nautic_entries_t entries;
	status = suunto_nautic_list (device, &entries);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to list the dives.");
		return status;
	}

	progress.maximum = (entries.count + 1) * 2;
	device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

	dc_buffer_t *buffer = dc_buffer_new (0);
	if (buffer == NULL) {
		ERROR (abstract->context, "Failed to allocate memory.");
		suunto_nautic_entries_free (&entries);
		return DC_STATUS_NOMEMORY;
	}

	for (unsigned int i = 0; i < entries.count; i++) {
		unsigned char fingerprint[4];
		array_uint32_le_set (fingerprint, entries.ids[i]);

		// The dives are newest first, so everything from here on was
		// downloaded before.
		if (memcmp (fingerprint, device->fingerprint, sizeof (fingerprint)) == 0)
			break;

		if (device_is_cancelled (abstract)) {
			status = DC_STATUS_CANCELLED;
			break;
		}

		int incomplete = 0, unreadable = 0;
		status = suunto_nautic_download (device, entries.ids[i], entries.sizes[i], buffer, &incomplete, &unreadable);
		if (status != DC_STATUS_SUCCESS && unreadable) {
			// An empty or aborted entry: listed, but without a dive.
			WARNING (abstract->context, "Skipping dive %u without any data.", entries.ids[i]);
			status = DC_STATUS_SUCCESS;
			continue;
		}
		if (status != DC_STATUS_SUCCESS) {
			// Stop here: the fingerprint of a newer dive would mark this one
			// as downloaded.
			ERROR (abstract->context, "Failed to download dive %u.", entries.ids[i]);
			break;
		}

		// Delivered anyway: skipping it would move the fingerprint past it.
		if (incomplete)
			WARNING (abstract->context, "Dive %u doesn't match its listed size and may be truncated.", entries.ids[i]);

		progress.current += 2;
		device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

		if (callback && !callback (dc_buffer_get_data (buffer), dc_buffer_get_size (buffer), fingerprint, sizeof (fingerprint), userdata))
			break;
	}

	dc_buffer_free (buffer);
	suunto_nautic_entries_free (&entries);

	return status;
}

/*
 * Extension API (include/libdivecomputer/suunto_nautic.h): direct access for
 * tools that list, download or explore the watch outside dc_device_foreach().
 */

static int
suunto_nautic_is_device (dc_device_t *abstract)
{
	return abstract != NULL && abstract->vtable->type == DC_FAMILY_SUUNTO_NAUTIC;
}

// Rebuild a received packet around its payload. The payload passed the
// checksum, so the packet is byte for byte the one the watch sent.
static dc_status_t
suunto_nautic_packet (dc_buffer_t *buffer, unsigned char opcode, unsigned int seqnum, const unsigned char data[], size_t size)
{
	unsigned char packet[RPC_OVERHEAD + MAX_PAYLOAD] = {0};

	if (size > MAX_PAYLOAD)
		return DC_STATUS_INVALIDARGS;

	packet[0] = RPC_START;
	packet[1] = opcode;
	array_uint16_le_set (packet + 2, size);
	array_uint16_le_set (packet + 4, seqnum);
	memcpy (packet + 6, data, size);
	array_uint32_le_set (packet + 6 + size, checksum_crc32r (packet, 6 + size));

	dc_buffer_clear (buffer);
	if (!dc_buffer_append (buffer, packet, RPC_OVERHEAD + size))
		return DC_STATUS_NOMEMORY;

	return DC_STATUS_SUCCESS;
}

int
suunto_nautic_device_handshake_acknowledged (dc_device_t *abstract)
{
	if (!suunto_nautic_is_device (abstract))
		return 0;

	return ((suunto_nautic_device_t *) abstract)->acknowledged;
}

dc_status_t
suunto_nautic_device_request (dc_device_t *abstract, const char *path, dc_buffer_t *response)
{
	if (!suunto_nautic_is_device (abstract) || path == NULL || response == NULL)
		return DC_STATUS_INVALIDARGS;

	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;
	dc_status_t status = DC_STATUS_SUCCESS;

	size_t pathlen = strlen (path);
	if (pathlen == 0 || pathlen > MAX_PATH)
		return DC_STATUS_INVALIDARGS;

	unsigned char request[4 + MAX_PATH] = {0x01, 0x80, 0x00};
	request[3] = pathlen;
	memcpy (request + 4, path, pathlen);

	unsigned int seqnum = suunto_nautic_seqnum (device);
	status = suunto_nautic_send (device, RPC_OP_GET, seqnum, request, 4 + pathlen);
	if (status != DC_STATUS_SUCCESS)
		return status;

	unsigned char reply[MAX_PAYLOAD] = {0};
	size_t reply_len = 0;
	status = suunto_nautic_recv (device, RPC_OP_GET_REPLY, seqnum, reply, sizeof (reply), &reply_len);
	if (status != DC_STATUS_SUCCESS)
		return status;

	// The whole reply packet.
	return suunto_nautic_packet (response, RPC_OP_GET_REPLY, seqnum, reply, reply_len);
}

// GET, a FETCH without parameters, RELEASE. Returns the whole reply packet.
static dc_status_t
suunto_nautic_fetch_packet (suunto_nautic_device_t *device, const char *path, dc_buffer_t *packet, unsigned int *result)
{
	unsigned int handle = 0;
	dc_status_t status = suunto_nautic_get_handle (device, path, &handle);
	if (status != DC_STATUS_SUCCESS)
		return status;

	unsigned char reply[MAX_PAYLOAD] = {0};
	size_t reply_len = 0;
	status = suunto_nautic_transfer (device, RPC_OP_FETCH, RPC_OP_DATA,
		handle, suunto_nautic_noparams, sizeof (suunto_nautic_noparams), reply, sizeof (reply), &reply_len);
	unsigned int seqnum = device->seqnum;
	suunto_nautic_release (device, handle);
	if (status != DC_STATUS_SUCCESS)
		return status;

	*result = array_uint16_le (reply + REPLY_STATUS);
	return suunto_nautic_packet (packet, RPC_OP_DATA, seqnum, reply, reply_len);
}

dc_status_t
suunto_nautic_device_fetch (dc_device_t *abstract, const char *path, dc_buffer_t *response)
{
	if (!suunto_nautic_is_device (abstract) || path == NULL || response == NULL)
		return DC_STATUS_INVALIDARGS;

	dc_buffer_t *packet = dc_buffer_new (0);
	if (packet == NULL)
		return DC_STATUS_NOMEMORY;

	unsigned int result = 0;
	dc_status_t status = suunto_nautic_fetch_packet ((suunto_nautic_device_t *) abstract, path, packet, &result);
	if (status == DC_STATUS_SUCCESS && result != STATUS_OK && result != STATUS_CONTINUE) {
		ERROR (abstract->context, "Failed to fetch %s (status %u).", path, result);
		status = DC_STATUS_PROTOCOL;
	}

	// Everything after the start byte, opcode and length. A status 100 reply
	// is the first page only.
	if (status == DC_STATUS_SUCCESS) {
		dc_buffer_clear (response);
		if (!dc_buffer_append (response, dc_buffer_get_data (packet) + 4, dc_buffer_get_size (packet) - 4))
			status = DC_STATUS_NOMEMORY;
	}

	dc_buffer_free (packet);
	return status;
}

dc_status_t
suunto_nautic_device_fetch_raw (dc_device_t *abstract, const char *path, dc_buffer_t *response)
{
	if (!suunto_nautic_is_device (abstract) || path == NULL || response == NULL)
		return DC_STATUS_INVALIDARGS;

	unsigned int result = 0;
	return suunto_nautic_fetch_packet ((suunto_nautic_device_t *) abstract, path, response, &result);
}

dc_status_t
suunto_nautic_device_list (dc_device_t *abstract, dc_buffer_t *ids)
{
	if (!suunto_nautic_is_device (abstract) || ids == NULL)
		return DC_STATUS_INVALIDARGS;

	suunto_nautic_entries_t entries;
	dc_status_t status = suunto_nautic_list ((suunto_nautic_device_t *) abstract, &entries);
	if (status != DC_STATUS_SUCCESS)
		return status;

	dc_buffer_clear (ids);
	for (unsigned int i = 0; i < entries.count; i++) {
		unsigned char id[4];
		array_uint32_le_set (id, entries.ids[i]);
		if (!dc_buffer_append (ids, id, sizeof (id))) {
			status = DC_STATUS_NOMEMORY;
			break;
		}
	}

	suunto_nautic_entries_free (&entries);
	return status;
}

// Scans a raw /Logbook/Entries response for 4-aligned (start, end) timestamp
// pairs. The driver parses the records instead; kept for existing callers.
unsigned int
suunto_nautic_extract_entry_ids (const unsigned char data[], size_t size, unsigned int *ids, unsigned int max_ids)
{
	unsigned int count = 0;
	for (size_t i = 0; i + 8 <= size && count < max_ids; i += 4) {
		unsigned int start = array_uint32_le (data + i);
		if (start < 1500000000u || start > 2100000000u)
			continue;
		unsigned int end = array_uint32_le (data + i + 4);
		if (end >= 1500000000u && end <= 2100000000u && end > start && end - start <= 86400u) {
			ids[count++] = start;
			i += 4;
		}
	}

	for (unsigned int a = 1; a < count; a++) {
		unsigned int key = ids[a];
		int b = (int) a - 1;
		while (b >= 0 && ids[b] < key) {
			ids[b + 1] = ids[b];
			b--;
		}
		ids[b + 1] = key;
	}

	return count;
}

dc_status_t
suunto_nautic_device_fetch_paged (dc_device_t *abstract, const char *path, dc_buffer_t *response)
{
	if (!suunto_nautic_is_device (abstract) || path == NULL || response == NULL)
		return DC_STATUS_INVALIDARGS;

	return suunto_nautic_fetch_pages ((suunto_nautic_device_t *) abstract, path, response);
}

dc_status_t
suunto_nautic_device_download_summary (dc_device_t *abstract, const char *logbook_id, dc_buffer_t *summary)
{
	if (!suunto_nautic_is_device (abstract) || logbook_id == NULL || summary == NULL)
		return DC_STATUS_INVALIDARGS;

	char path[128];
	int n = snprintf (path, sizeof (path), "/Logbook/byId/%s/Summary", logbook_id);
	if (n < 0 || (size_t) n >= sizeof (path))
		return DC_STATUS_INVALIDARGS;

	return suunto_nautic_fetch_pages ((suunto_nautic_device_t *) abstract, path, summary);
}

dc_status_t
suunto_nautic_device_download (dc_device_t *abstract, const char *logbook_id, dc_buffer_t *raw)
{
	if (!suunto_nautic_is_device (abstract) || logbook_id == NULL || raw == NULL)
		return DC_STATUS_INVALIDARGS;

	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;

	char *end = NULL;
	unsigned long id = strtoul (logbook_id, &end, 10);
	if (end == logbook_id || *end != 0 || id == 0 || id > 0xFFFFFFFFul)
		return DC_STATUS_INVALIDARGS;

	// The listed size to check the download against; a dive that isn't
	// listed is downloaded without the check.
	unsigned int listed = 0;
	suunto_nautic_entries_t entries;
	if (suunto_nautic_list (device, &entries) == DC_STATUS_SUCCESS) {
		for (unsigned int i = 0; i < entries.count; i++) {
			if (entries.ids[i] == id)
				listed = entries.sizes[i];
		}
		suunto_nautic_entries_free (&entries);
	}

	int incomplete = 0, unreadable = 0;
	dc_status_t status = suunto_nautic_download (device, (unsigned int) id, listed, raw, &incomplete, &unreadable);
	if (status == DC_STATUS_SUCCESS && incomplete)
		return DC_STATUS_DATAFORMAT;

	return status;
}

dc_status_t
suunto_nautic_device_subscribe (dc_device_t *abstract, const char *path, unsigned char handle[3], dc_buffer_t *value)
{
	if (!suunto_nautic_is_device (abstract) || path == NULL || handle == NULL)
		return DC_STATUS_INVALIDARGS;

	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;

	unsigned int h = 0, result = 0;
	dc_status_t status = suunto_nautic_get (device, path, &h, &result);
	if (status != DC_STATUS_SUCCESS)
		return status;

	if (HANDLE_SLOT (h) == SLOT_UNKNOWN) {
		WARNING (abstract->context, "The watch has no %s resource.", path);
		return DC_STATUS_UNSUPPORTED;
	}
	if (result != STATUS_OK) {
		ERROR (abstract->context, "Failed to resolve %s (status %u).", path, result);
		return DC_STATUS_PROTOCOL;
	}
	array_uint24_le_set (handle, h);

	// A still bound 00 slot was left by a link that dropped.
	if (HANDLE_SLOT (h) == SLOT_ALT) {
		WARNING (abstract->context, "Releasing the stale slot of %s.", path);
		suunto_nautic_release (device, (h & ~0xFFu) | SLOT_DEFAULT);
	}

	// The reply carries the current value: TYPE(2) VALUE.
	unsigned char reply[MAX_PAYLOAD] = {0};
	size_t reply_len = 0;
	status = suunto_nautic_transfer (device, RPC_OP_SUBSCRIBE, RPC_OP_SUBSCRIBE_REPLY,
		h, suunto_nautic_noparams, sizeof (suunto_nautic_noparams), reply, sizeof (reply), &reply_len);
	if (status != DC_STATUS_SUCCESS)
		return status;

	result = array_uint16_le (reply + REPLY_STATUS);
	if (result != STATUS_OK) {
		ERROR (abstract->context, "The watch refused the subscription to %s (status %u).", path, result);
		return DC_STATUS_PROTOCOL;
	}

	if (value) {
		dc_buffer_clear (value);
		if (!dc_buffer_append (value, reply + REPLY_CONTENT, reply_len - REPLY_CONTENT))
			return DC_STATUS_NOMEMORY;
	}

	return status;
}

dc_status_t
suunto_nautic_device_unsubscribe (dc_device_t *abstract, const unsigned char handle[3])
{
	if (!suunto_nautic_is_device (abstract) || handle == NULL)
		return DC_STATUS_INVALIDARGS;

	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;
	unsigned int h = array_uint24_le (handle);

	unsigned char reply[MAX_PAYLOAD] = {0};
	size_t reply_len = 0;
	dc_status_t status = suunto_nautic_transfer (device, RPC_OP_UNSUBSCRIBE, RPC_OP_UNSUBSCRIBE_REPLY,
		h, suunto_nautic_noparams, sizeof (suunto_nautic_noparams), reply, sizeof (reply), &reply_len);
	if (status != DC_STATUS_SUCCESS)
		return status;

	suunto_nautic_release (device, h);
	return status;
}

dc_status_t
suunto_nautic_device_wait_notification (dc_device_t *abstract, unsigned int timeout, unsigned char handle[3], dc_buffer_t *value)
{
	if (!suunto_nautic_is_device (abstract) || handle == NULL || value == NULL)
		return DC_STATUS_INVALIDARGS;

	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;

	if (device_is_cancelled (abstract))
		return DC_STATUS_CANCELLED;

	dc_status_t status = dc_iostream_set_timeout (device->iostream, (int) timeout);
	if (status != DC_STATUS_SUCCESS)
		return status;

	// A value notification is HANDLE(3) FLAGS(3) TYPE(2) VALUE.
	unsigned char data[MAX_PAYLOAD] = {0};
	size_t size = 0;
	status = suunto_nautic_recv (device, RPC_OP_NOTIFICATION, 0, data, sizeof (data), &size);
	if (status == DC_STATUS_SUCCESS && size < 6) {
		ERROR (abstract->context, "Unexpected notification size (" DC_PRINTF_SIZE ").", size);
		status = DC_STATUS_PROTOCOL;
	}
	if (status == DC_STATUS_SUCCESS) {
		memcpy (handle, data, 3);
		dc_buffer_clear (value);
		if (!dc_buffer_append (value, data + 6, size - 6))
			status = DC_STATUS_NOMEMORY;
	}

	dc_status_t rc = dc_iostream_set_timeout (device->iostream, TIMEOUT_DEFAULT);
	if (status == DC_STATUS_SUCCESS)
		status = rc;

	return status;
}

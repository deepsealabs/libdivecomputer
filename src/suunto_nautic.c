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
#include "timer.h"
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
#define MAX_PAYLOAD  512
#define MAX_PATH     240
#define MAX_PARAMS   7

// HTTP-like status codes carried in the replies.
#define ERR_OK       200
#define ERR_CONTINUE 100 // more pages follow
// Fork only.
#define ERR_NOT_FOUND 404
#define ERR_LOCKED    423

// A GET of a per-id path (/Logbook/byId/<id>/...) binds the id to one of the
// resource's handle slots, [00|10] 24 <resource>, until a RELEASE frees it. A
// second GET while the 00 slot is still bound, e.g. by another app on the
// link, gets the 10 slot; the handle the GET returns is always the one used.
// Static paths answer with an F0 handle, e.g. F0 24 00 for /Logbook/Entries,
// which isn't released, and an unknown path with FF FF FF. A few static
// paths, /Info among them, answer with F1 instead; those are released like a
// slot, and the watch answers that with 200. The slot is the first byte on
// the wire, the resource the other two.
#define HANDLE_ISSTATIC(handle)  (((handle) & 0xFF) == 0xF0)
#define HANDLE_ISINVALID(handle) ((handle) == 0xFFFFFF)
#define HANDLE_RESOURCE(handle)  ((handle) >> 8)
#define HANDLE_SLOT(handle)      ((handle) & 0xFF)

// Request parameters are COUNT(1), then TYPE(2) VALUE for each parameter. The
// /Summary page offset is an int32, the /Logbook/Entries StartAfterId (the id
// of the last entry received) a uint32.
#define PARAM_INT32  0x06
#define PARAM_UINT32 0x07

// Stream notification payload:
// HANDLE(3) CLIENT(3) UNKNOWN(4) OFFSET(4) LENGTH(2) UNKNOWN(6) DATA(LENGTH) 00
// HANDLE is the static handle of the resource (F0 24 0E for /Data), not the
// slot the GET returned. OFFSET is the position of the chunk in the stream.
// The last chunk has a zero length, at an offset equal to the total size, and
// is sent twice. The 00 after the data ends every notification the watch
// sends, not only those of the stream.
#define CHUNK_OFFSET 10
#define CHUNK_LENGTH 14
#define CHUNK_DATA   22

// A page of a paged resource (/Summary, or /Data read with a FETCH) is
// HEADER(11) DATA, with the data length at offset 3 of the header. The paging
// offset counts data bytes only, so for /Data it is the stream offset.
#define PAGE_HEADER 11
#define PAGE_LENGTH 3

// A /Logbook/Entries page is a Whiteboard struct, TYPE(2) SIZE(2) PADDING(2)
// STRUCT, and the struct is an array, COUNT(2) PADDING(2) OFFSET(4), with the
// records at OFFSET from the start of the struct: 12 on a page with records,
// 8 on a page without. A record is ID(4) MODIFIED(4) 01 PADDING(7) SIZE(8),
// the LogEntry of the Movesense logbook API, in which the size is optional
// and the 01 marks it as present. The id is the dive's start time, and the
// size is the compressed /Data plus the /Summary data bytes, which fits in
// its low 4 bytes.
#define ENTRIES_STRUCT  6
#define ENTRIES_COUNT   0
#define ENTRIES_RECORDS 4
#define ENTRY_SIZE     24
#define ENTRY_START    0
#define ENTRY_HASSIZE  8
#define ENTRY_LENGTH   16

// /Info is a Whiteboard struct, TYPE(2) SIZE(2) PADDING(2) STRUCT, and the
// struct starts with the offsets of eight NUL-terminated strings, as uint32
// counted from the start of the struct: the manufacturer, the product, the
// codename, a hardware id, the serial, a PCBA id, the firmware and the
// hardware version, e.g. Suunto, Nautic, Vaasa, T, 2604C3003306, ..., 2.55.46.
// The type is 02 2F on the Nautic, the Nautic S and the Ocean. The serial is
// 12 hex digits, and is reported as the value of its last 8 (0xC3003306 for
// 2604C3003306).
#define INFO_TYPE     0x2F02
#define INFO_STRUCT   6
#define INFO_PRODUCT  1
#define INFO_SERIAL   4
#define INFO_FIRMWARE 6

// The models of the descriptor table, which /Info's product names.
#define NAUTIC 0
#define OCEAN  1

#define NSTEPS 1000
#define STEP(i,n) ((unsigned int) ((unsigned long long) NSTEPS * (i) / (n)))

#define TIMEOUT_DEFAULT 5000
#define TIMEOUT_STREAM  4000 // the gap between two chunks reaches about 2s
#define TIMEOUT_SKIP    (3 * TIMEOUT_DEFAULT) // a reply takes up to about 1s, see suunto_nautic_skip
// Fork only: how long the rest of a stopped stream of ours keeps a request's
// reply waiting at most; a Nautic S /Data streams for 150 to 200 s.
#define TIMEOUT_TAIL    200000

// Fork only: another app (the Suunto app) may already have a session on the
// link. Before a hello of our own, a GET without one: the watch answers it
// only when there is a session, and then we use that session. A hello would
// take it over, and a Suunto app that doesn't answer it with a hello of its
// own keeps sending requests but stops getting their replies. A fresh link
// stays silent.
#define PROBE_PATH    "/Logbook/Entries"
#define TIMEOUT_PROBE 1500
// The watch doesn't answer the probe while another app's stream is running.
// Then wait once until the link has been quiet for QUIET_MS, longer than the
// Suunto app's ~10.6 s hello retry, and ask again. The wait gives up after
// QUIET_MAX_S, so that the open fails with DC_STATUS_TIMEOUT before a host
// gives up on a connection that takes too long. A link that is still busy
// fails the open, and the retry is left to the application.
#define QUIET_POLL_MS 1000
#define QUIET_MS      15000
#define QUIET_MAX_S   20
// On a shared session the watch's replies to the other app reach us too, and
// those that arrive while we're idle wait in the receive buffer. A download
// first reads and drops them, a packet at a time with a short timeout, so
// that only a reply that arrives while we're working counts as the other app
// using the watch. Waiting packets come back at once and the drain ends at
// the first read that times out, so an app that is busy right now doesn't
// keep it going: the first request then sees its traffic. DRAIN_MAX only
// bounds the backlog. The other app's /Data stream reaches us too, a packet
// per chunk: a 1 MB dive leaves over 4,000, and a long app sync thousands of
// replies.
#define DRAIN_MS  10
#define DRAIN_MAX 65536

// Fork only: why the device stepped aside for another app (taken_over).
#define TAKEN_ACTIVE 1 // the other app is using the watch; our stream is still ours
#define TAKEN_STREAM 2 // its hello ended our stream, or its request took it

// Heatshrink (LZSS) parameters used by the Nautic/Ocean's MDS stream.
#define HEATSHRINK_WINDOW_SZ2    7
#define HEATSHRINK_LOOKAHEAD_SZ2 5
#define HEATSHRINK_INPUT_BUFFER_SIZE 256

// Fork only: the extension API hands over a reply payload whole, HANDLE(3)
// CLIENT(3) ERRCODE(2) DATA, with its error code unchecked.
#define REPLY_STATUS  6
#define REPLY_CONTENT 8

// Fork only: the downloads carried over to a later connection. The resume
// buffer holds a record per dive, ID(4) LISTED(4) SIZE(4) DATA(SIZE): the
// dive, its listed size and the compressed /Data received before its
// download failed. The records are oldest first, at most RESUME_MAX.
#define RESUME_ID     0
#define RESUME_LISTED 4
#define RESUME_SIZE   8
#define RESUME_HEADER 12
#define RESUME_MAX    4

// Fork only: the sequence number to continue from on the next connection.
// The Suunto app's carry on across connections too, so a reconnect never
// repeats one the watch still holds from the dropped session.
static unsigned int g_suunto_nautic_seqnum = 0;

// Fork only: how many of the sequence numbers up to the current one count as
// ours, so that a late reply to one of them isn't taken for another app's.
#define SEQNUM_RECENT 8

typedef struct suunto_nautic_device_t {
	dc_device_t base;
	dc_iostream_t *iostream; // HDLC-framed
	dc_timer_t *timer;
	unsigned int seqnum;
	unsigned int stream; // the handle of the stream being received, 0 for none
	// Fork only: whether the watch answered the hello (extension API).
	int acknowledged;
	// The dive id (a UNIX timestamp) of the most recently downloaded dive,
	// little-endian. All-zero means no fingerprint.
	unsigned char fingerprint[4];
	// Fork only: the caller's buffer that carries a failed download over to
	// a later connection (extension API), or NULL.
	dc_buffer_t *resume;
	// Fork only: the entries the last foreach left out as not dives.
	unsigned int nondives;
	// Fork only: set while the extension API waits for a notification, where
	// a timeout without a byte received is the usual outcome, not an error.
	int polling;
	// Fork only: whether another app took the link over (TAKEN_*), after
	// which every request fails until the device is reopened, and whether the
	// device has waited for the other app since.
	int taken_over;
	int stepped_aside;
	// Fork only: how many of the sequence numbers up to the current one were
	// ours, up to SEQNUM_RECENT.
	unsigned int nrecent;
	// Fork only: whether the device uses another app's session instead of a
	// hello of its own, and whether the link has been quiet since it opened.
	int shared;
	int quiet;
} suunto_nautic_device_t;

static dc_status_t suunto_nautic_device_set_fingerprint (dc_device_t *abstract, const unsigned char data[], unsigned int size);
static dc_status_t suunto_nautic_step_aside (suunto_nautic_device_t *device);
static dc_status_t suunto_nautic_await_quiet (suunto_nautic_device_t *device);
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

// The download of one dive, for the progress: the bytes received so far, out
// of the listed size, and the progress before the dive.
typedef struct suunto_nautic_progress_t {
	dc_event_progress_t *event; // Fork only: NULL for the extension API, which reports none
	unsigned int initial;
	unsigned int listed;
	unsigned int received;
	// Fork only: 0 for a read without a listed size to check against, a
	// /Summary or a paged resource of the extension API, or a by-id download
	// of a dive the list leaves out.
	unsigned int checked;
} suunto_nautic_progress_t;

static unsigned int
suunto_nautic_seqnum (suunto_nautic_device_t *device)
{
	// Zero is Whiteboard's invalid request id (ID_INVALID_REQUEST). The watch
	// uses it for the packets that don't answer a request: the hello, its
	// reply and the stream notifications.
	device->seqnum = (device->seqnum + 1) & 0xFFFF;
	if (device->seqnum == 0)
		device->seqnum = 1;

	// Fork only.
	if (device->nrecent < SEQNUM_RECENT)
		device->nrecent++;

	return device->seqnum;
}

// Fork only: whether a reply's sequence number is one of the last few we
// used: a reply that arrives after its request gave up on it, such as the
// probe's when it takes longer than TIMEOUT_PROBE, or a request a host tries
// again after a timeout. It is skipped, not taken for another app's.
static int
suunto_nautic_ours (suunto_nautic_device_t *device, unsigned int seqnum)
{
	return seqnum != 0 && ((device->seqnum - seqnum) & 0xFFFF) < device->nrecent;
}

static dc_status_t
suunto_nautic_send (suunto_nautic_device_t *device, unsigned char opcode, unsigned int seqnum, const unsigned char data[], size_t size)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	dc_device_t *abstract = (dc_device_t *) device;
	unsigned char packet[6 + MAX_PAYLOAD + 4] = {0};

	// Fork only: after a takeover the other app is using the watch: our
	// requests would get in its way, or, while its stream runs, go unanswered
	// until it ends.
	if (device->taken_over) {
		ERROR (abstract->context, "Another app has the link; not sending.");
		return DC_STATUS_IO;
	}

	// The UNSUBSCRIBE and RELEASE still go out after a cancel, so the watch
	// doesn't keep streaming or keep the handle bound.
	if (opcode != RPC_OP_UNSUBSCRIBE && opcode != RPC_OP_RELEASE &&
		device_is_cancelled (abstract))
		return DC_STATUS_CANCELLED;

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

	status = dc_iostream_write (device->iostream, packet, 6 + size + 4, NULL);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (device->base.context, "Failed to send the packet.");
		return status;
	}

	return status;
}

// Another app's packets can keep coming while ours never does, so skipping
// them ends after TIMEOUT_SKIP without one of ours. A cancel ends only a wait
// for a notification, so it never loses a request's handle or subscription.
static dc_status_t
suunto_nautic_skip (suunto_nautic_device_t *device, unsigned char opcode, dc_usecs_t begin)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	dc_device_t *abstract = (dc_device_t *) device;

	if (opcode == RPC_OP_NOTIFICATION && device_is_cancelled (abstract))
		return DC_STATUS_CANCELLED;

	dc_usecs_t now = 0;
	status = dc_timer_now (device->timer, &now);
	if (status != DC_STATUS_SUCCESS)
		return status;

	if (now - begin >= (dc_usecs_t) TIMEOUT_SKIP * 1000) {
		ERROR (abstract->context, "Only other packets for %d ms while waiting for %02x.", TIMEOUT_SKIP, opcode);
		return DC_STATUS_TIMEOUT;
	}

	return status;
}

// Fork only: another app's hello cuts off the chunk it arrives in. While a
// stream of ours is on, a damaged packet is a lost chunk: the next packet
// tells whether the stream goes on with a gap, was taken over or stopped.
static dc_status_t
suunto_nautic_skip_damaged (suunto_nautic_device_t *device, unsigned char opcode, dc_usecs_t begin, size_t length)
{
	WARNING (device->base.context, "Skipping a damaged packet (" DC_PRINTF_SIZE " bytes).", length);
	return suunto_nautic_skip (device, opcode, begin);
}

// Fork only: a notification of the stream we stopped restarts the deadline on
// the reply we wait for, up to TIMEOUT_TAIL after `start`, unless the host
// cancelled; then it counts toward the deadline like any other packet.
static dc_status_t
suunto_nautic_skip_tail (suunto_nautic_device_t *device, unsigned char opcode, dc_usecs_t start, dc_usecs_t *begin)
{
	dc_usecs_t now = 0;
	dc_status_t status = dc_timer_now (device->timer, &now);
	if (status != DC_STATUS_SUCCESS)
		return status;

	if (device_is_cancelled ((dc_device_t *) device) || now - start >= (dc_usecs_t) TIMEOUT_TAIL * 1000)
		return suunto_nautic_skip (device, opcode, *begin);

	*begin = now;
	return DC_STATUS_SUCCESS;
}

// Receive the packet with the given opcode and sequence number. The watch
// serves every app connected to it over the same link, so other packets can
// arrive in between. The notifications that are still on their way after a
// stream was stopped before its end are skipped; a reply to another app's
// request, which is recognized by its sequence number, fails with
// DC_STATUS_IO (fork only, see below).
static dc_status_t
suunto_nautic_recv (suunto_nautic_device_t *device, unsigned char opcode, unsigned int seqnum, unsigned char data[], size_t size, size_t *actual)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	unsigned char packet[6 + MAX_PAYLOAD + 4] = {0};
	size_t length = 0;

	if (size > MAX_PAYLOAD)
		return DC_STATUS_INVALIDARGS;

	dc_usecs_t begin = 0;
	status = dc_timer_now (device->timer, &begin);
	if (status != DC_STATUS_SUCCESS)
		return status;
	const dc_usecs_t start = begin;

	while (1) {
		status = dc_iostream_read (device->iostream, packet, sizeof(packet), &length);
		// Fork only: a frame torn so that its framing breaks, as by another
		// app's hello, is a damaged packet like one with a bad checksum.
		if (status == DC_STATUS_IO && device->stream && dc_hdlc_damaged (device->iostream)) {
			status = suunto_nautic_skip_damaged (device, opcode, begin, length);
			if (status != DC_STATUS_SUCCESS)
				return status;
			continue;
		}
		if (status != DC_STATUS_SUCCESS) {
			if (!(device->polling && status == DC_STATUS_TIMEOUT && length == 0))
				ERROR (device->base.context, "Failed to receive the packet.");
			return status;
		}

		if (length < 10) {
			if (device->stream) {
				status = suunto_nautic_skip_damaged (device, opcode, begin, length);
				if (status != DC_STATUS_SUCCESS)
					return status;
				continue;
			}
			ERROR (device->base.context, "Unexpected packet size (" DC_PRINTF_SIZE ").", length);
			return DC_STATUS_PROTOCOL;
		}

		unsigned int crc = array_uint32_le (packet + length - 4);
		unsigned int ccrc = checksum_crc32r (packet, length - 4);
		if (crc != ccrc) {
			if (device->stream) {
				status = suunto_nautic_skip_damaged (device, opcode, begin, length);
				if (status != DC_STATUS_SUCCESS)
					return status;
				continue;
			}
			ERROR (device->base.context, "Unexpected packet checksum (%08x %08x).", crc, ccrc);
			return DC_STATUS_PROTOCOL;
		}

		if (packet[0] != RPC_START) {
			ERROR (device->base.context, "Unexpected packet start byte (%02x).", packet[0]);
			return DC_STATUS_PROTOCOL;
		}

		unsigned int rsp_length = array_uint16_le (packet + 2);
		if (rsp_length != length - 10) {
			ERROR (device->base.context, "Unexpected packet payload length (%u " DC_PRINTF_SIZE ").", rsp_length, length - 10);
			return DC_STATUS_PROTOCOL;
		}

		unsigned int rsp_opcode = packet[1];
		unsigned int rsp_seqnum = array_uint16_le (packet + 4);

		// Fork only: a reply to another app's request, or its hello, means
		// that app is using the watch. The watch drops the GETs that arrive
		// while a /Data stream runs, so carrying on would starve the other
		// app, which then says hello again and ends our stream, and its hello
		// ends the handles we hold. Step aside: what arrived before is still
		// ours, and a new device waits for the link to go quiet on open.
		if (rsp_opcode != RPC_OP_NOTIFICATION && (rsp_opcode != opcode || rsp_seqnum != seqnum) &&
			!suunto_nautic_ours (device, rsp_seqnum)) {
			// While waiting for a notification the device isn't using the
			// watch, so another app's replies get in nobody's way. Only its
			// hello, which ends our session and its subscriptions with it,
			// ends the wait, and without waiting for the other app.
			if (device->polling && rsp_opcode != RPC_OP_HELLO_REPLY) {
				WARNING (device->base.context, "Skipping another app's reply (%02x %u).", rsp_opcode, rsp_seqnum);
				status = suunto_nautic_skip (device, opcode, begin);
				if (status != DC_STATUS_SUCCESS)
					return status;
				continue;
			}

			WARNING (device->base.context, "Another app is using the watch (%02x %u).", rsp_opcode, rsp_seqnum);
			// The watch has one /Data stream, shared by every client: a reply
			// on its resource (whatever the slot) means the other app's
			// request took it or ended it.
			if (rsp_opcode == RPC_OP_HELLO_REPLY || (device->stream && rsp_length >= 3 &&
				HANDLE_RESOURCE (array_uint24_le (packet + 6)) == HANDLE_RESOURCE (device->stream)))
				device->taken_over = TAKEN_STREAM;
			else if (!device->taken_over)
				device->taken_over = TAKEN_ACTIVE;
			// A stream of ours is stopped first (suunto_nautic_stream).
			if (!device->stream && !device->polling)
				return suunto_nautic_step_aside (device);
			return DC_STATUS_IO;
		}

		if (rsp_opcode != opcode) {
			WARNING (device->base.context, "Skipping a packet with an unexpected opcode (%02x %02x).", rsp_opcode, opcode);
			// The rest of a stopped stream of ours shows the watch is still busy with us.
			// Fork only: up to TIMEOUT_TAIL, and not after a cancel: another
			// app's stream has the same resource.
			if (rsp_opcode == RPC_OP_NOTIFICATION && device->stream && rsp_length >= 3 &&
				HANDLE_RESOURCE (array_uint24_le (packet + 6)) == HANDLE_RESOURCE (device->stream))
				status = suunto_nautic_skip_tail (device, opcode, start, &begin);
			else
				status = suunto_nautic_skip (device, opcode, begin);
			if (status != DC_STATUS_SUCCESS)
				return status;
			continue;
		}

		if (rsp_seqnum != seqnum) {
			WARNING (device->base.context, "Skipping a packet with an unexpected sequence number (%u %u).", rsp_seqnum, seqnum);
			status = suunto_nautic_skip (device, opcode, begin);
			if (status != DC_STATUS_SUCCESS)
				return status;
			continue;
		}

		if (rsp_length > size) {
			ERROR (device->base.context, "Unexpected packet payload length (%u " DC_PRINTF_SIZE ").", rsp_length, size);
			return DC_STATUS_NOMEMORY;
		}

		memcpy (data, packet + 6, rsp_length);
		if (actual)
			*actual = rsp_length;

		return status;
	}
}

// Send a request on a handle and receive its reply:
//
//   W: HANDLE(3) 01 80 00 PARAMS
//   R: HANDLE(3) 01 80 00 ERRCODE(2) DATA
//
// The reply must echo the handle and the 01 80 00 client id, and carry
// ERR_OK or ERR_CONTINUE; any other error code fails the request. Only the
// DATA is returned, and the error code for the callers that need to tell
// the last page (ERR_OK) from the others (ERR_CONTINUE). The DATA must fill
// the buffer exactly when the caller doesn't ask for its size, and fit in it
// otherwise.
static dc_status_t
suunto_nautic_transfer (suunto_nautic_device_t *device, unsigned char opcode, unsigned char rsp_opcode,
	unsigned int handle, const unsigned char params[], size_t nparams,
	unsigned char data[], size_t size, size_t *actual, unsigned int *errorcode)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	unsigned char request[6 + MAX_PARAMS] = {0};
	unsigned char reply[MAX_PAYLOAD] = {0};
	size_t length = 0;
	unsigned int errcode = 0;

	if (nparams > MAX_PARAMS) {
		status = DC_STATUS_INVALIDARGS;
		goto error_exit;
	}

	array_uint24_le_set (request, handle);
	request[3] = 0x01;
	request[4] = 0x80;
	request[5] = 0x00;
	if (nparams)
		memcpy (request + 6, params, nparams);

	unsigned int seqnum = suunto_nautic_seqnum (device);
	status = suunto_nautic_send (device, opcode, seqnum, request, 6 + nparams);
	if (status != DC_STATUS_SUCCESS)
		goto error_exit;

	size_t reply_len = 0;
	status = suunto_nautic_recv (device, rsp_opcode, seqnum, reply, sizeof (reply), &reply_len);
	if (status != DC_STATUS_SUCCESS)
		goto error_exit;

	if (reply_len < 8) {
		ERROR (device->base.context, "Unexpected reply size (" DC_PRINTF_SIZE ").", reply_len);
		status = DC_STATUS_PROTOCOL;
		goto error_exit;
	}

	unsigned int rsp_handle = array_uint24_le (reply);
	if (rsp_handle != handle) {
		ERROR (device->base.context, "Unexpected reply handle (%06x %06x).", rsp_handle, handle);
		status = DC_STATUS_PROTOCOL;
		goto error_exit;
	}

	if (memcmp (reply + 3, request + 3, 3) != 0) {
		ERROR (device->base.context, "Unexpected reply client id (%02x %02x %02x).", reply[3], reply[4], reply[5]);
		status = DC_STATUS_PROTOCOL;
		goto error_exit;
	}

	errcode = array_uint16_le (reply + 6);
	if (errcode != ERR_OK && errcode != ERR_CONTINUE) {
		ERROR (device->base.context, "Unexpected reply error code (%u).", errcode);
		status = DC_STATUS_PROTOCOL;
		goto error_exit;
	}

	if (actual == NULL && reply_len - 8 != size) {
		ERROR (device->base.context, "Unexpected reply length (" DC_PRINTF_SIZE " " DC_PRINTF_SIZE ").", reply_len - 8, size);
		status = DC_STATUS_PROTOCOL;
		goto error_exit;
	}

	if (reply_len - 8 > size) {
		ERROR (device->base.context, "Unexpected reply length (" DC_PRINTF_SIZE " " DC_PRINTF_SIZE ").", reply_len - 8, size);
		status = DC_STATUS_NOMEMORY;
		goto error_exit;
	}

	if (reply_len - 8)
		memcpy (data, reply + 8, reply_len - 8);
	length = reply_len - 8;

error_exit:
	if (actual)
		*actual = length;
	if (errorcode)
		*errorcode = errcode;
	return status;
}

// Fork only: send a request on a handle and return its whole reply payload,
// HANDLE(3) CLIENT(3) ERRCODE(2) DATA, checked to hold the header only. The
// extension API hands the reply and its error code to the caller as they are.
static dc_status_t
suunto_nautic_transfer_raw (suunto_nautic_device_t *device, unsigned char opcode, unsigned char rsp_opcode,
	unsigned int handle, const unsigned char params[], size_t nparams, unsigned char data[], size_t size, size_t *actual)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	unsigned char request[6 + MAX_PARAMS] = {0};

	if (nparams > MAX_PARAMS)
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

	size_t length = 0;
	status = suunto_nautic_recv (device, rsp_opcode, seqnum, data, size, &length);
	if (status != DC_STATUS_SUCCESS)
		return status;

	if (length < REPLY_CONTENT) {
		ERROR (device->base.context, "Unexpected reply size (" DC_PRINTF_SIZE ").", length);
		return DC_STATUS_PROTOCOL;
	}

	if (actual)
		*actual = length;

	return status;
}

// Release a handle bound by a GET, so the next GET of the same resource binds
// its own id to the slot.
static dc_status_t
suunto_nautic_release (suunto_nautic_device_t *device, unsigned int handle)
{
	dc_status_t status = DC_STATUS_SUCCESS;

	if (HANDLE_ISSTATIC (handle) || HANDLE_ISINVALID (handle))
		return status;

	status = suunto_nautic_transfer (device, RPC_OP_RELEASE, RPC_OP_RELEASE_REPLY,
		handle, NULL, 0, NULL, 0, NULL, NULL);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (device->base.context, "Failed to release handle %06x.", handle);
		return status;
	}

	return status;
}

// Resolve a path to a handle:
//
//   W: 01 80 00 LENGTH PATH(LENGTH)
//   R: HANDLE(3) 01 80 00 ERRCODE(2)
static dc_status_t
suunto_nautic_get_handle (suunto_nautic_device_t *device, const char *path, unsigned int *handle)
{
	dc_status_t status = DC_STATUS_SUCCESS;

	if (path == NULL)
		return DC_STATUS_INVALIDARGS;

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

	unsigned char reply[8] = {0};
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

	if (memcmp (reply + 3, request, 3) != 0) {
		ERROR (device->base.context, "Unexpected reply client id (%02x %02x %02x).", reply[3], reply[4], reply[5]);
		return DC_STATUS_PROTOCOL;
	}

	unsigned int value = array_uint24_le (reply);
	unsigned int errcode = array_uint16_le (reply + 6);
	if (errcode != ERR_OK) {
		ERROR (device->base.context, "Failed to resolve %s (error code %u).", path, errcode);
		return DC_STATUS_PROTOCOL;
	}

	if (handle)
		*handle = value;

	return status;
}

// Decompress a Heatshrink (LZSS) stream, with the parameters above, and
// append the result to the output buffer. The input isn't const, because
// heatshrink_decoder_sink() doesn't take a const buffer.
static dc_status_t
suunto_nautic_heatshrink_decompress (dc_context_t *context, unsigned char *input, size_t input_size, dc_buffer_t *output)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	unsigned char outbuf[HEATSHRINK_INPUT_BUFFER_SIZE];

	heatshrink_decoder *hsd = heatshrink_decoder_alloc (HEATSHRINK_INPUT_BUFFER_SIZE, HEATSHRINK_WINDOW_SZ2, HEATSHRINK_LOOKAHEAD_SZ2);
	if (hsd == NULL) {
		ERROR (context, "Failed to allocate the heatshrink decoder.");
		return DC_STATUS_NOMEMORY;
	}

	size_t sunk_total = 0;
	while (sunk_total < input_size) {
		size_t sunk = 0;
		HSD_sink_res sres = heatshrink_decoder_sink (hsd, input + sunk_total, input_size - sunk_total, &sunk);
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

// Count the bytes received for a dive, and update the progress. A dive is
// never larger than its listed size, so more data is an error, which also
// ends a stream or a paged read that doesn't stop.
static dc_status_t
suunto_nautic_progress (suunto_nautic_device_t *device, suunto_nautic_progress_t *progress, unsigned int length)
{
	dc_device_t *abstract = (dc_device_t *) device;

	// Fork only: nothing to check against, and no progress to report.
	if (!progress->checked) {
		progress->received += length;
		return DC_STATUS_SUCCESS;
	}

	if (length > progress->listed - progress->received) {
		ERROR (abstract->context, "Unexpected data past the listed size (%u).", progress->listed);
		return DC_STATUS_PROTOCOL;
	}

	if (length == 0)
		return DC_STATUS_SUCCESS;

	progress->received += length;
	if (progress->event) {
		progress->event->current = progress->initial + STEP (progress->received, progress->listed);
		device_event_emit (abstract, DC_EVENT_PROGRESS, progress->event);
	}

	return DC_STATUS_SUCCESS;
}

// Read the pages of a resource on a handle bound by a GET, from the given
// offset, and append their data. Each page is requested by the offset of
// its data, and the last page has status 200.
static dc_status_t
suunto_nautic_read_pages (suunto_nautic_device_t *device, const char *path, unsigned int handle, unsigned int offset, suunto_nautic_progress_t *progress, dc_buffer_t *buffer)
{
	dc_device_t *abstract = (dc_device_t *) device;
	dc_status_t status = DC_STATUS_SUCCESS;

	while (1) {
		unsigned char params[7] = {0x01, PARAM_INT32, 0x00};
		array_uint32_le_set (params + 3, offset);

		unsigned char page[MAX_PAYLOAD] = {0};
		size_t page_len = 0;
		unsigned int errcode = 0;
		status = suunto_nautic_transfer (device, RPC_OP_FETCH, RPC_OP_DATA,
			handle, params, sizeof (params), page, sizeof (page), &page_len, &errcode);
		if (status != DC_STATUS_SUCCESS) {
			ERROR (abstract->context, "Failed to fetch %s (offset %u).", path, offset);
			break;
		}

		if (page_len < PAGE_HEADER) {
			ERROR (abstract->context, "Unexpected page size (" DC_PRINTF_SIZE ").", page_len);
			status = DC_STATUS_PROTOCOL;
			break;
		}

		// An empty page wouldn't advance the offset, so the next request
		// would be the same one again. Only the last page may be empty.
		unsigned int length = array_uint16_le (page + PAGE_LENGTH);
		if ((length == 0 && errcode != ERR_OK) || PAGE_HEADER + length != page_len) {
			ERROR (abstract->context, "Unexpected page length (%u " DC_PRINTF_SIZE ").", length, page_len);
			status = DC_STATUS_PROTOCOL;
			break;
		}

		status = suunto_nautic_progress (device, progress, length);
		if (status != DC_STATUS_SUCCESS)
			break;

		if (!dc_buffer_append (buffer, page + PAGE_HEADER, length)) {
			ERROR (abstract->context, "Failed to allocate memory.");
			status = DC_STATUS_NOMEMORY;
			break;
		}
		offset += length;

		if (errcode == ERR_OK)
			break;
	}

	return status;
}

// Download a streamed resource (the dive profile): GET, SUBSCRIBE, the
// notifications up to the end marker, UNSUBSCRIBE and RELEASE. Returns the
// still compressed stream, with a lost chunk read again in pages, or an
// error when the watch refuses the stream, a chunk arrives at an earlier
// offset or the stream stops before its end marker.
static dc_status_t
suunto_nautic_stream (suunto_nautic_device_t *device, const char *path, suunto_nautic_progress_t *progress, dc_buffer_t *buffer)
{
	dc_device_t *abstract = (dc_device_t *) device;
	dc_status_t status = DC_STATUS_SUCCESS;
	dc_status_t rc = DC_STATUS_SUCCESS;
	unsigned int received = 0;
	unsigned int missing = 0;
	unsigned int end = 0;
	dc_usecs_t last = 0; // the last notification for the stream
	int taken_over = 0;

	unsigned int handle = 0;
	status = suunto_nautic_get_handle (device, path, &handle);
	if (status != DC_STATUS_SUCCESS)
		return status;

	device->stream = handle;

	// The SUBSCRIBE and UNSUBSCRIBE replies carry two more bytes, 00 00.
	unsigned char reply[2] = {0};
	unsigned int errcode = 0;
	for (unsigned int attempt = 0; ; attempt++) {
		status = suunto_nautic_transfer (device, RPC_OP_SUBSCRIBE, RPC_OP_SUBSCRIBE_REPLY,
			handle, suunto_nautic_noparams, sizeof (suunto_nautic_noparams), reply, sizeof (reply), NULL, &errcode);

		// Fork only: a stream that was never unsubscribed, because the app
		// that asked for it was killed or lost the link, holds the watch's
		// one stream after it ends: every SUBSCRIBE gets 423 until a hello.
		// Once the link has been quiet, it isn't another app's stream running
		// (or between its end marker and its UNSUBSCRIBE); it was asked for in
		// the session we share, and ours can end it, but only with an
		// UNSUBSCRIBE from slot 0. So when its old binding put us in another
		// slot, free both and bind again.
		if (status != DC_STATUS_PROTOCOL || errcode != ERR_LOCKED || attempt >= 2)
			break;

		if (device->shared && !device->quiet) {
			status = suunto_nautic_await_quiet (device);
			if (status != DC_STATUS_SUCCESS)
				goto error_release;
		}

		if (HANDLE_SLOT (handle) != 0) {
			WARNING (abstract->context, "A stream left over from an earlier connection holds the watch (error code %u); freeing its slot.", errcode);
			status = suunto_nautic_release (device, handle & ~0xFFu);
			if (status == DC_STATUS_SUCCESS)
				status = suunto_nautic_release (device, handle);
			if (status == DC_STATUS_SUCCESS)
				status = suunto_nautic_get_handle (device, path, &handle);
			if (status != DC_STATUS_SUCCESS)
				goto error_exit;
			device->stream = handle;
			continue;
		}

		WARNING (abstract->context, "A stream left over from an earlier connection holds the watch (error code %u); ending it.", errcode);
		status = suunto_nautic_transfer (device, RPC_OP_UNSUBSCRIBE, RPC_OP_UNSUBSCRIBE_REPLY,
			handle, suunto_nautic_noparams, sizeof (suunto_nautic_noparams), reply, sizeof (reply), NULL, &errcode);
		if (status != DC_STATUS_SUCCESS && !(status == DC_STATUS_PROTOCOL && errcode)) {
			ERROR (abstract->context, "Failed to unsubscribe from %s.", path);
			goto error_release;
		}
		INFO (abstract->context, "Unsubscribed the left-over stream (error code %u).", errcode);
	}
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to subscribe to %s.", path);
		// Without its reply, the watch may have subscribed all the same; fork
		// only: also when another app's reply came first.
		if (status == DC_STATUS_TIMEOUT || (status == DC_STATUS_IO && device->taken_over == TAKEN_ACTIVE))
			goto error_unsubscribe;
		goto error_release;
	}

	if (errcode != ERR_OK) {
		ERROR (abstract->context, "Unexpected error code for the subscription to %s (%u).", path, errcode);
		status = DC_STATUS_PROTOCOL;
		goto error_release;
	}

	status = dc_iostream_set_timeout (device->iostream, TIMEOUT_STREAM);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to set the timeout.");
		goto error_unsubscribe;
	}

	status = dc_timer_now (device->timer, &last);
	if (status != DC_STATUS_SUCCESS)
		goto error_unsubscribe;

	// The watch streams the whole resource without acknowledgements, up to
	// the end marker. Nothing is sent meanwhile, so check for a cancel here.
	while (1) {
		if (device_is_cancelled (abstract)) {
			status = DC_STATUS_CANCELLED;
			break;
		}

		unsigned char chunk[MAX_PAYLOAD] = {0};
		size_t chunk_len = 0;
		status = suunto_nautic_recv (device, RPC_OP_NOTIFICATION, 0, chunk, sizeof (chunk), &chunk_len);
		if (status != DC_STATUS_SUCCESS) {
			ERROR (abstract->context, "Failed to receive the stream for %s.", path);
			break;
		}

		// The values of another app's subscriptions (the Suunto app holds
		// several) arrive as notifications too, for another resource.
		if (chunk_len >= 3 && HANDLE_RESOURCE (array_uint24_le (chunk)) != HANDLE_RESOURCE (handle)) {
			WARNING (abstract->context, "Skipping a notification for another resource (%06x).", array_uint24_le (chunk));
			status = suunto_nautic_skip (device, RPC_OP_NOTIFICATION, last);
			if (status != DC_STATUS_SUCCESS)
				break;
			continue;
		}

		status = dc_timer_now (device->timer, &last);
		if (status != DC_STATUS_SUCCESS)
			break;

		if (chunk_len < CHUNK_DATA) {
			ERROR (abstract->context, "Unexpected chunk size (" DC_PRINTF_SIZE ").", chunk_len);
			status = DC_STATUS_PROTOCOL;
			break;
		}

		unsigned int offset = array_uint32_le (chunk + CHUNK_OFFSET);
		unsigned int length = array_uint16_le (chunk + CHUNK_LENGTH);
		if (chunk_len != CHUNK_DATA + length + 1 || chunk[CHUNK_DATA + length] != 0) {
			ERROR (abstract->context, "Unexpected chunk length (%u " DC_PRINTF_SIZE ").", length, chunk_len);
			status = DC_STATUS_PROTOCOL;
			break;
		}

		// A read error on the watch is reported as a chunk at offset
		// 0xFFFFFFFF, with an int16 error code as its data.
		if (offset == 0xFFFFFFFF) {
			if (length != 2) {
				ERROR (abstract->context, "Unexpected read error length (%u).", length);
				status = DC_STATUS_PROTOCOL;
				break;
			}
			ERROR (abstract->context, "Failed to read %s on the watch (%d).", path, (signed short) array_uint16_le (chunk + CHUNK_DATA));
			status = DC_STATUS_PROTOCOL;
			break;
		}

		// The end marker, a chunk without data at the total size, is sent
		// twice, and nothing follows it.
		if (end) {
			if (offset != received || length != 0) {
				ERROR (abstract->context, "Unexpected chunk after the end marker (%u %u).", offset, length);
				status = DC_STATUS_PROTOCOL;
			}
			break;
		}

		// A lost chunk isn't sent again: the next one just arrives at a later
		// offset. The rest is read in pages, after the UNSUBSCRIBE.
		if (offset > received) {
			WARNING (abstract->context, "Missing stream data (%u %u), reading the rest in pages.", offset, received);
			missing = 1;
			break;
		}

		if (offset != received) {
			ERROR (abstract->context, "Unexpected chunk offset (%u %u).", offset, received);
			status = DC_STATUS_PROTOCOL;
			break;
		}

		if (length == 0) {
			end = 1;
			continue;
		}

		status = suunto_nautic_progress (device, progress, length);
		if (status != DC_STATUS_SUCCESS)
			break;

		if (!dc_buffer_append (buffer, chunk + CHUNK_DATA, length)) {
			ERROR (abstract->context, "Failed to allocate memory.");
			status = DC_STATUS_NOMEMORY;
			break;
		}
		received += length;
	}

error_unsubscribe:
	// Without the UNSUBSCRIBE the watch keeps streaming, and the next GET of a
	// stream is refused with status 423. Fork only: a stream left running also
	// starves the other app we step aside for. Once the stream is the other
	// app's, ours would end it; the handle is left bound, as after a lost link.
	taken_over = device->taken_over;
	if (taken_over != TAKEN_STREAM) {
		device->taken_over = 0;
		rc = suunto_nautic_transfer (device, RPC_OP_UNSUBSCRIBE, RPC_OP_UNSUBSCRIBE_REPLY,
			handle, suunto_nautic_noparams, sizeof (suunto_nautic_noparams), reply, sizeof (reply), NULL, &errcode);
		if (rc == DC_STATUS_PROTOCOL && errcode == ERR_NOT_FOUND) {
			// Another app's hello ended our session, and the stream with it.
			// The hello usually cuts off the chunk it arrives in, and its
			// reply then never arrives whole.
			WARNING (abstract->context, "Another app ended the stream (error code %u).", errcode);
			device->taken_over = TAKEN_STREAM;
		} else if (rc != DC_STATUS_SUCCESS) {
			ERROR (abstract->context, "Failed to unsubscribe from %s.", path);
			dc_status_set_error (&status, rc);
		}
		if (device->taken_over < taken_over)
			device->taken_over = taken_over;
	}

	rc = dc_iostream_set_timeout (device->iostream, TIMEOUT_DEFAULT);
	if (rc != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to restore the timeout.");
		dc_status_set_error (&status, rc);
	}

	// The handle serves the same resource in pages too, from any offset, which
	// is how the Suunto app reads the rest of a stream with a gap.
	if (missing && status == DC_STATUS_SUCCESS)
		status = suunto_nautic_read_pages (device, path, handle, received, progress, buffer);

error_release:
	// Fork only: after a takeover the device sends nothing more.
	if (!device->taken_over) {
		rc = suunto_nautic_release (device, handle);
		if (rc != DC_STATUS_SUCCESS)
			dc_status_set_error (&status, rc);
	}
error_exit:
	device->stream = 0;
	// Fork only: with the stream of ours stopped, step aside. A step-aside
	// fails the download with DC_STATUS_IO (or DC_STATUS_CANCELLED), whatever
	// ended the stream: after a hello that cut off a chunk, the read times
	// out first.
	if (device->taken_over)
		status = suunto_nautic_step_aside (device);
	return status;
}

// Read a paged resource (/Summary).
static dc_status_t
suunto_nautic_fetch_pages (suunto_nautic_device_t *device, const char *path, suunto_nautic_progress_t *progress, dc_buffer_t *buffer)
{
	dc_status_t status = DC_STATUS_SUCCESS;

	unsigned int handle = 0;
	status = suunto_nautic_get_handle (device, path, &handle);
	if (status != DC_STATUS_SUCCESS)
		return status;

	status = suunto_nautic_read_pages (device, path, handle, 0, progress, buffer);

	dc_status_t rc = suunto_nautic_release (device, handle);
	if (rc != DC_STATUS_SUCCESS)
		dc_status_set_error (&status, rc);
	return status;
}

// Fork only: read the rest of a /Data stream that an earlier connection
// didn't finish, in pages from the first missing byte, on the handle of a new
// GET. After a lost link the watch binds the same handle again and serves the
// pages from any offset, as it does after a lost chunk.
static dc_status_t
suunto_nautic_resume_pages (suunto_nautic_device_t *device, const char *path, suunto_nautic_progress_t *progress, dc_buffer_t *buffer)
{
	unsigned int handle = 0;
	dc_status_t status = suunto_nautic_get_handle (device, path, &handle);
	if (status != DC_STATUS_SUCCESS)
		return status;

	status = suunto_nautic_read_pages (device, path, handle, dc_buffer_get_size (buffer), progress, buffer);

	dc_status_t rc = suunto_nautic_release (device, handle);
	if (rc != DC_STATUS_SUCCESS)
		dc_status_set_error (&status, rc);
	return status;
}

// Fork only: the failures after which the /Data received so far is still
// right, so a later connection can carry on from it: the link went, or the
// download was cancelled.
static int
suunto_nautic_resumable (dc_status_t status)
{
	return status == DC_STATUS_TIMEOUT || status == DC_STATUS_IO ||
		status == DC_STATUS_NODEVICE || status == DC_STATUS_CANCELLED;
}

// Fork only: find the record of a dive in the resume buffer, and count the
// records. A buffer that doesn't parse as records is emptied.
static int
suunto_nautic_resume_find (dc_buffer_t *resume, unsigned int id, size_t *offset, unsigned int *count)
{
	const unsigned char *data = dc_buffer_get_data (resume);
	size_t size = dc_buffer_get_size (resume);
	size_t position = 0;
	unsigned int n = 0;
	int found = 0;

	while (size - position >= RESUME_HEADER) {
		size_t length = array_uint32_le (data + position + RESUME_SIZE);
		if (length > size - position - RESUME_HEADER)
			break;
		if (!found && array_uint32_le (data + position + RESUME_ID) == id) {
			*offset = position;
			found = 1;
		}
		position += RESUME_HEADER + length;
		n++;
	}

	if (position != size) {
		dc_buffer_clear (resume);
		found = 0;
		n = 0;
	}

	if (count)
		*count = n;
	return found;
}

// Fork only: remove the record at the offset from the resume buffer.
static void
suunto_nautic_resume_remove (dc_buffer_t *resume, size_t offset)
{
	unsigned char *data = dc_buffer_get_data (resume);
	size_t size = dc_buffer_get_size (resume);
	size_t length = RESUME_HEADER + array_uint32_le (data + offset + RESUME_SIZE);

	memmove (data + offset, data + offset + length, size - offset - length);
	dc_buffer_resize (resume, size - length);
}

// Fork only: forget what was kept for a dive.
static void
suunto_nautic_resume_forget (suunto_nautic_device_t *device, unsigned int id)
{
	size_t offset = 0;

	if (device->resume && suunto_nautic_resume_find (device->resume, id, &offset, NULL))
		suunto_nautic_resume_remove (device->resume, offset);
}

// Fork only: put the /Data an earlier connection kept for this dive in the
// buffer. Returns its size, 0 when nothing was kept.
static size_t
suunto_nautic_resume_load (suunto_nautic_device_t *device, unsigned int id, unsigned int listed, dc_buffer_t *buffer)
{
	dc_buffer_t *resume = device->resume;
	size_t offset = 0;

	if (resume == NULL || listed == 0 || !suunto_nautic_resume_find (resume, id, &offset, NULL))
		return 0;

	const unsigned char *record = dc_buffer_get_data (resume) + offset;
	size_t size = array_uint32_le (record + RESUME_SIZE);
	if (array_uint32_le (record + RESUME_LISTED) != listed || size == 0 || size >= listed)
		return 0;

	dc_buffer_clear (buffer);
	if (!dc_buffer_append (buffer, record + RESUME_HEADER, size)) {
		dc_buffer_clear (buffer);
		return 0;
	}

	return size;
}

// Fork only: keep the /Data received so far for a dive, in place of what was
// kept for it before. The oldest record goes when there are too many.
static void
suunto_nautic_resume_keep (suunto_nautic_device_t *device, unsigned int id, unsigned int listed, dc_buffer_t *compressed)
{
	dc_device_t *abstract = (dc_device_t *) device;
	dc_buffer_t *resume = device->resume;
	size_t size = dc_buffer_get_size (compressed);
	size_t offset = 0;
	unsigned int count = 0;

	if (suunto_nautic_resume_find (resume, id, &offset, &count)) {
		suunto_nautic_resume_remove (resume, offset);
		count--;
	}
	for (; count >= RESUME_MAX; count--)
		suunto_nautic_resume_remove (resume, 0);

	unsigned char header[RESUME_HEADER] = {0};
	array_uint32_le_set (header + RESUME_ID, id);
	array_uint32_le_set (header + RESUME_LISTED, listed);
	array_uint32_le_set (header + RESUME_SIZE, size);

	size_t end = dc_buffer_get_size (resume);
	if (!dc_buffer_append (resume, header, sizeof (header)) ||
		!dc_buffer_append (resume, dc_buffer_get_data (compressed), size)) {
		dc_buffer_resize (resume, end);
		return;
	}

	WARNING (abstract->context, "Keeping the " DC_PRINTF_SIZE " bytes of dive %u received so far for the next connection.", size, id);
}

// Fork only: after a dive's download, keep the /Data received so far when the
// link failed, for the next connection, or forget what was kept for the dive
// when it downloaded or its bytes can't be trusted. A resumed /Data that
// timed out without getting any further starts over next time, instead of
// trying the same way again. `resumed` is the number of bytes the /Data
// started from, 0 when it wasn't read.
static void
suunto_nautic_resume_update (suunto_nautic_device_t *device, unsigned int id, unsigned int listed,
	dc_buffer_t *compressed, size_t resumed, dc_status_t status)
{
	dc_buffer_t *resume = device->resume;

	if (resume == NULL)
		return;

	size_t size = compressed ? dc_buffer_get_size (compressed) : 0;
	int stalled = status == DC_STATUS_TIMEOUT && resumed && size <= resumed;
	if (suunto_nautic_resumable (status) && !stalled) {
		if (listed && size && size < listed)
			suunto_nautic_resume_keep (device, id, listed, compressed);
		return;
	}

	suunto_nautic_resume_forget (device, id);
}

// Fork only: finish the /Data of a download from what an earlier connection
// received. The /Summary came first, and the listed size less the /Summary
// is the size of the whole /Data, so the rest is read in pages only when some
// is missing, and never from past its end. If the watch won't serve the rest
// in pages, the /Data is streamed from the start, as without the kept bytes.
static dc_status_t
suunto_nautic_resume (suunto_nautic_device_t *device, const char *path, unsigned int id, size_t summary_size,
	suunto_nautic_progress_t *progress, dc_buffer_t *compressed)
{
	dc_device_t *abstract = (dc_device_t *) device;
	dc_status_t status = DC_STATUS_SUCCESS;
	unsigned int listed = progress->listed;
	unsigned int received = progress->received;

	size_t kept = dc_buffer_get_size (compressed);
	if (summary_size >= listed || kept > listed - summary_size) {
		WARNING (abstract->context, "The " DC_PRINTF_SIZE " bytes kept for dive %u don't fit its listed size, downloading it again.", kept, id);
		suunto_nautic_resume_forget (device, id);
		dc_buffer_clear (compressed);
		return suunto_nautic_stream (device, path, progress, compressed);
	}

	status = suunto_nautic_progress (device, progress, kept);
	if (status != DC_STATUS_SUCCESS)
		return status;

	if (kept == listed - summary_size) {
		WARNING (abstract->context, "Resuming dive %u with its whole profile (" DC_PRINTF_SIZE " bytes) from an earlier connection.", id, kept);
		return status;
	}

	WARNING (abstract->context, "Resuming dive %u at offset " DC_PRINTF_SIZE " of " DC_PRINTF_SIZE " from an earlier connection, reading the rest in pages.",
		id, kept, listed - summary_size);
	status = suunto_nautic_resume_pages (device, path, progress, compressed);
	if (status == DC_STATUS_PROTOCOL) {
		WARNING (abstract->context, "The watch didn't serve the rest of dive %u in pages, downloading it again.", id);
		dc_buffer_clear (compressed);
		progress->received = received;
		status = suunto_nautic_stream (device, path, progress, compressed);
	}

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

	dc_status_t rc = DC_STATUS_SUCCESS;
	unsigned char reply[MAX_PAYLOAD] = {0};
	size_t reply_len = 0;
	unsigned int errcode = 0;
	status = suunto_nautic_transfer (device, RPC_OP_FETCH, RPC_OP_DATA,
		handle, suunto_nautic_noparams, sizeof (suunto_nautic_noparams), reply, sizeof (reply), &reply_len, &errcode);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to fetch %s.", path);
		goto error_release;
	}

	if (errcode != ERR_OK) {
		ERROR (abstract->context, "Unexpected error code for %s (%u).", path, errcode);
		status = DC_STATUS_PROTOCOL;
		goto error_release;
	}

	if (!dc_buffer_append (buffer, reply, reply_len)) {
		ERROR (abstract->context, "Failed to allocate memory.");
		status = DC_STATUS_NOMEMORY;
	}

error_release:
	rc = suunto_nautic_release (device, handle);
	if (rc != DC_STATUS_SUCCESS)
		dc_status_set_error (&status, rc);
	return status;
}

// List the dives: the records of all pages, oldest first. The list is served
// in pages: a page with status 100 is followed by a fetch for the dives after
// the last id received, until a page with status 200.
static dc_status_t
suunto_nautic_list (suunto_nautic_device_t *device, dc_buffer_t *entries)
{
	dc_device_t *abstract = (dc_device_t *) device;
	dc_status_t status = DC_STATUS_SUCCESS;
	const char *path = "/Logbook/Entries";

	unsigned int handle = 0;
	status = suunto_nautic_get_handle (device, path, &handle);
	if (status != DC_STATUS_SUCCESS)
		return status;

	// The first page is requested without the StartAfterId, which is
	// optional, as the Suunto app does. Per the Movesense logbook API, a
	// StartAfterId that isn't the id of an entry, such as 0, gets a 404.
	unsigned char params[7] = {0x00, PARAM_UINT32, 0x00};
	size_t nparams = 1;
	unsigned int nentries = 0, last = 0;
	while (1) {
		unsigned char data[MAX_PAYLOAD] = {0};
		size_t size = 0;
		unsigned int errcode = 0;
		status = suunto_nautic_transfer (device, RPC_OP_FETCH, RPC_OP_DATA,
			handle, params, nparams, data, sizeof (data), &size, &errcode);
		if (status != DC_STATUS_SUCCESS) {
			ERROR (abstract->context, "Failed to fetch %s.", path);
			break;
		}

		if (size < ENTRIES_STRUCT + 8) {
			ERROR (abstract->context, "Unexpected entries size (" DC_PRINTF_SIZE ").", size);
			status = DC_STATUS_PROTOCOL;
			break;
		}

		// The page holds exactly the records, after the array header.
		unsigned int count = array_uint16_le (data + ENTRIES_STRUCT + ENTRIES_COUNT);
		unsigned int start = array_uint32_le (data + ENTRIES_STRUCT + ENTRIES_RECORDS);
		if (start < 8 || start > size - ENTRIES_STRUCT ||
			size - ENTRIES_STRUCT - start != count * ENTRY_SIZE) {
			ERROR (abstract->context, "Unexpected number of entries (%u %u " DC_PRINTF_SIZE ").", count, start, size);
			status = DC_STATUS_PROTOCOL;
			break;
		}

		// The ids rise, which the fingerprint relies on, and which also
		// ends a list whose pages don't move on.
		const unsigned char *records = data + ENTRIES_STRUCT + start;
		for (unsigned int i = 0; i < count; i++) {
			unsigned int id = array_uint32_le (records + i * ENTRY_SIZE + ENTRY_START);
			if (nentries && id <= last) {
				ERROR (abstract->context, "Unexpected entry order (%u %u).", id, last);
				status = DC_STATUS_PROTOCOL;
				break;
			}
			last = id;
			nentries++;
		}

		if (status != DC_STATUS_SUCCESS)
			break;

		if (!dc_buffer_append (entries, records, count * ENTRY_SIZE)) {
			ERROR (abstract->context, "Failed to allocate memory.");
			status = DC_STATUS_NOMEMORY;
			break;
		}

		if (errcode == ERR_OK)
			break;

		if (count == 0) {
			ERROR (abstract->context, "No entries with more pages pending.");
			status = DC_STATUS_PROTOCOL;
			break;
		}

		// The next page starts after the last id received.
		params[0] = 0x01;
		memcpy (params + 3, records + (count - 1) * ENTRY_SIZE + ENTRY_START, 4);
		nparams = sizeof (params);
	}

	dc_status_t rc = suunto_nautic_release (device, handle);
	if (rc != DC_STATUS_SUCCESS)
		dc_status_set_error (&status, rc);

	return status;
}

// Download one dive as SUMMARY_SIZE(4) SUMMARY PROFILE: the /Summary, with
// the fields that are not in the profile (gradient factors, gas mixes), like
// a dive header, and then the decompressed /Data stream. Both are SBEM0103
// containers, which don't store their own size, hence the size in front.
// The listed size is the compressed /Data plus the /Summary data bytes,
// exactly, and a mismatch fails the download. Checking the content is left
// to the parser, which also tells, from the /Summary, an entry that isn't a
// dive: it stops there, with isdive 0. Fork only: a NULL isdive, from the
// by-id download, downloads any entry.
static dc_status_t
suunto_nautic_download (suunto_nautic_device_t *device, dc_event_progress_t *event, unsigned int id, unsigned int listed, unsigned int checked, dc_buffer_t *buffer, int *isdive)
{
	dc_device_t *abstract = (dc_device_t *) device;
	dc_status_t status = DC_STATUS_SUCCESS;
	size_t kept = 0, resumed = 0;

	suunto_nautic_progress_t progress;
	progress.event = event;
	progress.initial = event ? event->current : 0;
	progress.listed = listed;
	progress.received = 0;
	progress.checked = checked;

	char data_path[64], summary_path[64];
	snprintf (data_path, sizeof (data_path), "/Logbook/byId/%u/Data", id);
	snprintf (summary_path, sizeof (summary_path), "/Logbook/byId/%u/Summary", id);

	dc_buffer_t *compressed = dc_buffer_new (listed);
	if (compressed == NULL) {
		ERROR (abstract->context, "Failed to allocate memory.");
		return DC_STATUS_NOMEMORY;
	}

	// Fork only: carry on from the /Data an earlier connection received for
	// this dive, when the caller kept it.
	if (checked)
		kept = suunto_nautic_resume_load (device, id, listed, compressed);

	// The size is filled in once the /Summary is complete.
	unsigned char header[4] = {0};
	if (!dc_buffer_append (buffer, header, sizeof (header))) {
		ERROR (abstract->context, "Failed to allocate memory.");
		status = DC_STATUS_NOMEMORY;
		goto error_free;
	}

	// The /Summary goes first: it is much smaller than the /Data, so an
	// error there doesn't come after the long download of the profile.
	status = suunto_nautic_fetch_pages (device, summary_path, &progress, buffer);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to fetch the summary of dive %u.", id);
		goto error_free;
	}

	size_t summary_size = dc_buffer_get_size (buffer) - sizeof (header);
	array_uint32_le_set (dc_buffer_get_data (buffer), summary_size);

	if (isdive) {
		unsigned int activity = 0;
		*isdive = suunto_nautic_parser_isdive (dc_buffer_get_data (buffer) + sizeof (header), (unsigned int) summary_size, id, &activity);
		if (!*isdive) {
			WARNING (abstract->context, "Skipping entry %u, not a dive (activity %u).", id, activity);
			goto error_free;
		}
	}

	// Fork only: the resumed download, which only the /Data can stall.
	resumed = kept;
	if (resumed)
		status = suunto_nautic_resume (device, data_path, id, summary_size, &progress, compressed);
	else
		status = suunto_nautic_stream (device, data_path, &progress, compressed);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to download the profile of dive %u.", id);
		goto error_free;
	}

	size_t data_size = dc_buffer_get_size (compressed);
	// Fork only: a by-id download of a dive the list leaves out has no size to check.
	if (checked && data_size + summary_size != listed) {
		ERROR (abstract->context, "Unexpected size of dive %u (" DC_PRINTF_SIZE " + " DC_PRINTF_SIZE " bytes, listed %u).",
			id, data_size, summary_size, listed);
		status = DC_STATUS_PROTOCOL;
		goto error_free;
	}

	status = suunto_nautic_heatshrink_decompress (abstract->context,
		dc_buffer_get_data (compressed), dc_buffer_get_size (compressed), buffer);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to decompress dive %u.", id);
		goto error_free;
	}

error_free:
	// Fork only.
	suunto_nautic_resume_update (device, id, listed, compressed, resumed, status);
	dc_buffer_free (compressed);
	return status;
}

// Return the string at the given index of the /Info strings, or NULL when its
// offset is outside the data or it isn't NUL-terminated there.
static const char *
suunto_nautic_info_string (const unsigned char data[], size_t size, unsigned int index)
{
	if (INFO_STRUCT + (index + 1) * 4 > size)
		return NULL;

	unsigned int offset = array_uint32_le (data + INFO_STRUCT + index * 4);
	if (offset >= size - INFO_STRUCT)
		return NULL;

	const unsigned char *string = data + INFO_STRUCT + offset;
	if (memchr (string, 0, size - INFO_STRUCT - offset) == NULL)
		return NULL;

	return (const char *) string;
}

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
		goto error_free;
	}

	const unsigned char *data = dc_buffer_get_data (info);
	size_t size = dc_buffer_get_size (info);

	if (size < INFO_STRUCT || array_uint16_le (data) != INFO_TYPE) {
		ERROR (abstract->context, "Unexpected device info type.");
		status = DC_STATUS_DATAFORMAT;
		goto error_free;
	}

	const char *serial = suunto_nautic_info_string (data, size, INFO_SERIAL);
	unsigned char number[4] = {0};
	if (serial == NULL || strlen (serial) != 12 ||
		array_convert_hex2bin ((const unsigned char *) serial + 4, 8, number, sizeof (number)) != 0) {
		ERROR (abstract->context, "Unexpected serial in the device info.");
		status = DC_STATUS_DATAFORMAT;
		goto error_free;
	}

	const char *firmware = suunto_nautic_info_string (data, size, INFO_FIRMWARE);
	unsigned int major = 0, minor = 0, patch = 0;
	if (firmware == NULL || sscanf (firmware, "%u.%u.%u", &major, &minor, &patch) != 3) {
		ERROR (abstract->context, "Unexpected firmware in the device info.");
		status = DC_STATUS_DATAFORMAT;
		goto error_free;
	}

	// The product is "Nautic" on the Nautic and "Ocean" on the Ocean. The table
	// has no row for the Nautic S, so any "Nautic" product is the Nautic, and
	// so is an unknown one, as every watch was before the product was read.
	const char *product = suunto_nautic_info_string (data, size, INFO_PRODUCT);
	unsigned int model = NAUTIC;
	if (product != NULL && strcmp (product, "Ocean") == 0) {
		model = OCEAN;
	} else if (product == NULL || strncmp (product, "Nautic", 6) != 0) {
		WARNING (abstract->context, "Unknown product '%s' in the device info.", product ? product : "");
	}

	dc_event_devinfo_t devinfo;
	memset (&devinfo, 0, sizeof (devinfo));
	devinfo.model = model;
	devinfo.firmware = (major << 16) | (minor << 8) | patch;
	devinfo.serial = array_uint32_be (number);

	device_event_emit (abstract, DC_EVENT_DEVINFO, &devinfo);

error_free:
	dc_buffer_free (info);
	return status;
}

// Fork only: whether another app already has a session on the link: the watch
// answers a GET from a client that didn't say hello only then. The first
// packet decides: the reply means a session, silence means none, and anything
// else means another app is busy with the watch, and is all `busy` reports,
// since the other app's stream could go on for minutes.
static dc_status_t
suunto_nautic_probe (suunto_nautic_device_t *device, int *shared, int *busy)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	size_t pathlen = strlen (PROBE_PATH);

	unsigned char request[4 + MAX_PATH] = {0};
	request[0] = 0x01;
	request[1] = 0x80;
	request[2] = 0x00;
	request[3] = pathlen;
	memcpy (request + 4, PROBE_PATH, pathlen);

	*shared = 0;
	*busy = 0;

	unsigned int seqnum = suunto_nautic_seqnum (device);
	status = suunto_nautic_send (device, RPC_OP_GET, seqnum, request, 4 + pathlen);
	if (status != DC_STATUS_SUCCESS)
		return status;

	unsigned char packet[6 + MAX_PAYLOAD + 4] = {0};
	size_t length = 0;
	status = dc_iostream_read (device->iostream, packet, sizeof (packet), &length);
	if (status == DC_STATUS_TIMEOUT)
		return DC_STATUS_SUCCESS;
	// A damaged frame is another app's traffic too.
	if (status == DC_STATUS_IO && dc_hdlc_damaged (device->iostream)) {
		*busy = 1;
		return DC_STATUS_SUCCESS;
	}
	if (status != DC_STATUS_SUCCESS)
		return status;

	if (length >= 10 && packet[0] == RPC_START && packet[1] == RPC_OP_GET_REPLY &&
		array_uint16_le (packet + 4) == seqnum &&
		array_uint32_le (packet + length - 4) == checksum_crc32r (packet, length - 4))
		*shared = 1;
	else
		*busy = 1;

	return status;
}

// Fork only: read and discard packets until the link has been quiet for
// QUIET_MS: the traffic of another app using the watch. `packets`, when not
// NULL, gets how many arrived meanwhile. DC_STATUS_TIMEOUT means the link is
// still busy after QUIET_MAX_S.
static dc_status_t
suunto_nautic_wait_quiet (suunto_nautic_device_t *device, unsigned int *packets_out)
{
	dc_device_t *abstract = (dc_device_t *) device;
	dc_status_t status = DC_STATUS_SUCCESS;

	status = dc_iostream_set_timeout (device->iostream, QUIET_POLL_MS);
	if (status != DC_STATUS_SUCCESS)
		return status;

	dc_usecs_t start = 0;
	status = dc_timer_now (device->timer, &start);
	if (status != DC_STATUS_SUCCESS)
		return status;

	unsigned int quiet = 0, packets = 0;
	while (quiet < QUIET_MS) {
		if (device_is_cancelled (abstract))
			return DC_STATUS_CANCELLED;

		dc_usecs_t now = 0;
		status = dc_timer_now (device->timer, &now);
		if (status != DC_STATUS_SUCCESS)
			return status;

		if (now - start >= (dc_usecs_t) QUIET_MAX_S * 1000000) {
			ERROR (abstract->context, "The link is still busy after %u s.", QUIET_MAX_S);
			return DC_STATUS_TIMEOUT;
		}

		unsigned char packet[6 + MAX_PAYLOAD + 4] = {0};
		size_t length = 0;
		status = dc_iostream_read (device->iostream, packet, sizeof (packet), &length);
		if (status == DC_STATUS_TIMEOUT) {
			quiet += QUIET_POLL_MS;
			continue;
		}
		// A damaged frame is traffic like any other.
		if (status == DC_STATUS_IO && dc_hdlc_damaged (device->iostream)) {
			packets++;
			quiet = 0;
			continue;
		}
		if (status != DC_STATUS_SUCCESS)
			return status;

		if (length) {
			packets++;
			quiet = 0;
		}
	}

	INFO (abstract->context, "The link is quiet (%u packets from the other app).", packets);
	device->quiet = 1;
	if (packets_out)
		*packets_out = packets;
	return DC_STATUS_SUCCESS;
}

// Fork only: after a takeover, keep off the link until the other app is done
// with it, before failing: a host that reconnects at once would otherwise
// meet the other app between its hello and its first requests, find the link
// quiet and get in its way again. The wait is bounded and cancellable.
// Returns the status the call that stepped aside fails with: DC_STATUS_IO, or
// DC_STATUS_CANCELLED when the host cancelled the wait.
static dc_status_t
suunto_nautic_step_aside (suunto_nautic_device_t *device)
{
	if (device->stepped_aside)
		return DC_STATUS_IO;
	device->stepped_aside = 1;

	WARNING (device->base.context, "Waiting for the other app to finish.");
	dc_status_t status = suunto_nautic_wait_quiet (device, NULL);
	dc_iostream_set_timeout (device->iostream, TIMEOUT_DEFAULT);

	return status == DC_STATUS_CANCELLED ? status : DC_STATUS_IO;
}

// Fork only: on another app's session that the open didn't wait for, the
// link must have been quiet before the device touches what may be that app's
// stream. Traffic meanwhile means the app is using the watch: step aside.
static dc_status_t
suunto_nautic_await_quiet (suunto_nautic_device_t *device)
{
	unsigned int packets = 0;

	INFO (device->base.context, "Waiting for a quiet link before ending the stream.");
	dc_status_t status = suunto_nautic_wait_quiet (device, &packets);
	dc_status_t rc = dc_iostream_set_timeout (device->iostream, TIMEOUT_DEFAULT);
	if (status == DC_STATUS_CANCELLED)
		return status;

	if (status == DC_STATUS_TIMEOUT || (status == DC_STATUS_SUCCESS && packets)) {
		WARNING (device->base.context, "Another app is using the watch (%u packets).", packets);
		device->taken_over = TAKEN_ACTIVE;
		device->stepped_aside = 1;
		return DC_STATUS_IO;
	}

	if (status == DC_STATUS_SUCCESS)
		status = rc;
	return status;
}

// Fork only: drop the packets left in the receive buffer since the last
// request: on a shared session, the watch's replies to the other app. Not
// dc_iostream_purge, which not every transport implements.
static dc_status_t
suunto_nautic_drain (suunto_nautic_device_t *device)
{
	dc_status_t status = dc_iostream_set_timeout (device->iostream, DRAIN_MS);
	if (status != DC_STATUS_SUCCESS)
		return status;

	unsigned int packets = 0;
	while (packets < DRAIN_MAX) {
		if (device_is_cancelled ((dc_device_t *) device))
			return DC_STATUS_CANCELLED;

		unsigned char packet[6 + MAX_PAYLOAD + 4] = {0};
		size_t length = 0;
		status = dc_iostream_read (device->iostream, packet, sizeof (packet), &length);
		if (status == DC_STATUS_TIMEOUT)
			break;
		// A damaged frame is left from before like any other.
		if (status == DC_STATUS_IO && dc_hdlc_damaged (device->iostream)) {
			packets++;
			continue;
		}
		if (status != DC_STATUS_SUCCESS)
			return status;
		if (length)
			packets++;
	}

	if (packets)
		INFO (device->base.context, "Dropped %u packets left from before.", packets);

	return dc_iostream_set_timeout (device->iostream, TIMEOUT_DEFAULT);
}

// Fork only: the start of every download, listing or fetch of dive data, by
// foreach or by id: a device that stepped aside sends nothing more, and the
// packets left from before are dropped.
static dc_status_t
suunto_nautic_begin (suunto_nautic_device_t *device)
{
	if (device->taken_over) {
		ERROR (device->base.context, "Another app has the link; not sending.");
		return DC_STATUS_IO;
	}

	dc_status_t status = suunto_nautic_drain (device);
	if (status != DC_STATUS_SUCCESS)
		ERROR (device->base.context, "Failed to drop the packets left from before.");
	return status;
}

dc_status_t
suunto_nautic_device_open (dc_device_t **out, dc_context_t *context, dc_iostream_t *iostream)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	suunto_nautic_device_t *device = NULL;
	// Fork only: the open found another app using the watch.
	int other_app = 0;

	if (out == NULL)
		return DC_STATUS_INVALIDARGS;

	device = (suunto_nautic_device_t *) dc_device_allocate (context, &suunto_nautic_device_vtable);
	if (device == NULL) {
		ERROR (context, "Failed to allocate memory.");
		return DC_STATUS_NOMEMORY;
	}

	// Start at a different sequence number on every connection, so our
	// requests are unlikely to share a number with those of another app on
	// the same link, whose replies we also receive.
	device->seqnum = ((unsigned int) dc_datetime_now () * 2654435761u) & 0xFFFF;
	// Fork only: carry on from the previous connection, whose last sequence
	// numbers count as ours: a device opened again on the same link can still
	// get the late replies to them.
	device->nrecent = 0;
	if (g_suunto_nautic_seqnum) {
		device->seqnum = g_suunto_nautic_seqnum;
		device->nrecent = SEQNUM_RECENT;
	}
	device->stream = 0;
	memset (device->fingerprint, 0, sizeof (device->fingerprint));
	device->acknowledged = 0;
	device->resume = NULL;
	device->nondives = 0;
	device->polling = 0;
	device->taken_over = 0;
	device->stepped_aside = 0;
	device->shared = 0;
	device->quiet = 0;

	status = dc_timer_new (&device->timer);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to create a high resolution timer.");
		goto error_free;
	}

	status = dc_hdlc_open (&device->iostream, context, iostream, 244, 244);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to open the HDLC layer.");
		goto error_timer_free;
	}

	// Fork only: another app's hello cuts off the chunk it arrives in, before
	// the chunk's closing flag, and the hello's opening flag ends the chunk.
	// Read the hello all the same. The watch sends nothing between frames.
	status = dc_hdlc_set_shared_flag (device->iostream, 1);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to share the HDLC flags.");
		goto error_close;
	}

	status = dc_iostream_set_timeout (device->iostream, TIMEOUT_PROBE);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to set the timeout.");
		goto error_close;
	}

	dc_iostream_purge (device->iostream, DC_DIRECTION_ALL);

	// Fork only.
	int shared = 0, busy = 0;
	status = suunto_nautic_probe (device, &shared, &busy);
	if (status == DC_STATUS_SUCCESS && busy) {
		INFO (context, "Another app is using the watch; waiting until it is done.");
		status = suunto_nautic_wait_quiet (device, NULL);
		if (status == DC_STATUS_TIMEOUT)
			other_app = 1;
		if (status == DC_STATUS_SUCCESS)
			status = dc_iostream_set_timeout (device->iostream, TIMEOUT_PROBE);
		if (status == DC_STATUS_SUCCESS)
			status = suunto_nautic_probe (device, &shared, &busy);
	}
	if (status == DC_STATUS_SUCCESS && busy) {
		ERROR (context, "Another app is still using the watch.");
		status = DC_STATUS_TIMEOUT;
		other_app = 1;
	}
	if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to check for another app's session.");
		goto error_close;
	}

	status = dc_iostream_set_timeout (device->iostream, TIMEOUT_DEFAULT);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to set the timeout.");
		goto error_close;
	}

	if (shared) {
		INFO (context, "Another app has a session on the link; using it instead of a hello of our own.");
		device->acknowledged = 1;
		device->shared = 1;
		*out = (dc_device_t *) device;
		return DC_STATUS_SUCCESS;
	}

	INFO (context, "No other session on the link (the request above went unanswered, as expected); saying hello.");
	// Fork only: the open waits for the link once, for the probe. Another
	// app's traffic in reply to the hello fails it without a second wait, and
	// the host's next attempt does the waiting.
	device->stepped_aside = 1;
	status = suunto_nautic_send (device, RPC_OP_HELLO, 0, suunto_nautic_hello, sizeof (suunto_nautic_hello));
	if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to send the hello.");
		goto error_close;
	}

	unsigned char hello[sizeof (suunto_nautic_hello)] = {0};
	size_t hello_len = 0;
	status = suunto_nautic_recv (device, RPC_OP_HELLO_REPLY, 0, hello, sizeof (hello), &hello_len);
	if (status == DC_STATUS_TIMEOUT) {
		// Fork only: a sleeping watch doesn't answer. Carry on, so the host
		// can tell the diver to wake it when the first request times out.
		WARNING (context, "No reply to the hello; continuing.");
		status = DC_STATUS_SUCCESS;
	} else if (status != DC_STATUS_SUCCESS) {
		ERROR (context, "Failed to receive the hello.");
		// Fork only: another app's traffic in reply to the hello: as busy as
		// above, without waiting again.
		if (device->taken_over) {
			status = DC_STATUS_TIMEOUT;
			other_app = 1;
		}
		goto error_close;
	} else if (hello_len != sizeof (hello) || hello[0] != 0x09 || hello[1] != 0x09) {
		// The reply has the layout of the hello, and the same protocol versions.
		ERROR (context, "Unexpected hello reply.");
		status = DC_STATUS_PROTOCOL;
		goto error_close;
	} else {
		device->acknowledged = 1;
	}

	// Fork only.
	device->stepped_aside = 0;

	*out = (dc_device_t *) device;

	return DC_STATUS_SUCCESS;

error_close:
	// Fork only: DC_STATUS_TIMEOUT means another app is using the watch. Any
	// other timeout, such as a write the transport wasn't ready to take, is a
	// failed attempt like a broken link, which the host can retry at once.
	if (status == DC_STATUS_TIMEOUT && !other_app)
		status = DC_STATUS_IO;
	dc_iostream_close (device->iostream);
error_timer_free:
	dc_timer_free (device->timer);
error_free:
	dc_device_deallocate ((dc_device_t *) device);
	return status;
}

static dc_status_t
suunto_nautic_device_close (dc_device_t *abstract)
{
	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;

	// Fork only.
	g_suunto_nautic_seqnum = device->seqnum ? device->seqnum : 1;

	dc_status_t status = dc_iostream_close (device->iostream);

	dc_timer_free (device->timer);

	return status;
}

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

static dc_status_t
suunto_nautic_device_foreach (dc_device_t *abstract, dc_dive_callback_t callback, void *userdata)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;

	dc_event_progress_t progress = EVENT_PROGRESS_INITIALIZER;
	device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

	// Fork only.
	device->nondives = 0;
	status = suunto_nautic_begin (device);
	if (status != DC_STATUS_SUCCESS)
		return status;

	status = suunto_nautic_devinfo (device);
	if (status != DC_STATUS_SUCCESS)
		return status;

	dc_buffer_t *entries = dc_buffer_new (0);
	dc_buffer_t *buffer = dc_buffer_new (0);
	if (entries == NULL || buffer == NULL) {
		ERROR (abstract->context, "Failed to allocate memory.");
		status = DC_STATUS_NOMEMORY;
		goto error_free;
	}

	status = suunto_nautic_list (device, entries);
	if (status != DC_STATUS_SUCCESS) {
		ERROR (abstract->context, "Failed to list the dives.");
		goto error_free;
	}

	const unsigned char *records = dc_buffer_get_data (entries);
	unsigned int count = dc_buffer_get_size (entries) / ENTRY_SIZE;

	// The entries are oldest first, and the dives are downloaded newest
	// first, up to the one that matches the fingerprint. Count those.
	unsigned int ndives = 0;
	for (unsigned int i = count; i > 0; i--) {
		const unsigned char *record = records + (i - 1) * ENTRY_SIZE;
		if (memcmp (record + ENTRY_START, device->fingerprint, sizeof (device->fingerprint)) == 0)
			break;
		ndives++;
	}

	progress.current = 1 * NSTEPS;
	progress.maximum = (ndives + 1) * NSTEPS;
	device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

	for (unsigned int i = 0; i < ndives; i++) {
		const unsigned char *record = records + (count - 1 - i) * ENTRY_SIZE;
		unsigned int id = array_uint32_le (record + ENTRY_START);
		unsigned int listed = array_uint32_le (record + ENTRY_LENGTH);
		int isdive = 0;

		// The size is optional in the API, but no watch has been seen to list
		// an entry without one, or with one that needs more than 32 bits.
		if (record[ENTRY_HASSIZE] != 1 || array_uint32_le (record + ENTRY_LENGTH + 4) != 0) {
			ERROR (abstract->context, "Unexpected size of dive %u.", id);
			status = DC_STATUS_DATAFORMAT;
			break;
		}

		dc_buffer_clear (buffer);
		if (!dc_buffer_reserve (buffer, listed)) {
			ERROR (abstract->context, "Failed to allocate memory.");
			status = DC_STATUS_NOMEMORY;
			break;
		}

		status = suunto_nautic_download (device, &progress, id, listed, 1, buffer, &isdive);
		if (status != DC_STATUS_SUCCESS) {
			// Stop here: the fingerprint of a newer dive would mark this one
			// as downloaded.
			ERROR (abstract->context, "Failed to download dive %u.", id);
			break;
		}

		progress.current = (i + 2) * NSTEPS;
		device_event_emit (abstract, DC_EVENT_PROGRESS, &progress);

		// Not a dive: left out, but the walk goes on, and the fingerprint
		// stays the newest dive's.
		if (!isdive) {
			device->nondives++; // Fork only.
			continue;
		}

		// The fingerprint is the id, as it is stored in the record.
		if (callback && !callback (dc_buffer_get_data (buffer), dc_buffer_get_size (buffer), record + ENTRY_START, sizeof (device->fingerprint), userdata))
			break;
	}

error_free:
	dc_buffer_free (buffer);
	dc_buffer_free (entries);
	return status;
}

/*
 * Fork only: the extension API (include/libdivecomputer/suunto_nautic.h),
 * direct access for tools that list, download or explore the watch outside
 * dc_device_foreach().
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
	unsigned char packet[6 + MAX_PAYLOAD + 4] = {0};

	if (size > MAX_PAYLOAD)
		return DC_STATUS_INVALIDARGS;

	packet[0] = RPC_START;
	packet[1] = opcode;
	array_uint16_le_set (packet + 2, size);
	array_uint16_le_set (packet + 4, seqnum);
	memcpy (packet + 6, data, size);
	array_uint32_le_set (packet + 6 + size, checksum_crc32r (packet, 6 + size));

	dc_buffer_clear (buffer);
	if (!dc_buffer_append (buffer, packet, 6 + size + 4))
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

int
suunto_nautic_device_taken_over (dc_device_t *abstract)
{
	if (!suunto_nautic_is_device (abstract))
		return 0;

	return ((suunto_nautic_device_t *) abstract)->taken_over != 0;
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
	status = suunto_nautic_transfer_raw (device, RPC_OP_FETCH, RPC_OP_DATA,
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
	if (status == DC_STATUS_SUCCESS && result != ERR_OK && result != ERR_CONTINUE) {
		ERROR (abstract->context, "Failed to fetch %s (error code %u).", path, result);
		status = DC_STATUS_PROTOCOL;
	}

	// Everything after the start byte, opcode and length. An ERR_CONTINUE
	// reply is the first page only.
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

	dc_status_t status = suunto_nautic_begin ((suunto_nautic_device_t *) abstract);
	if (status != DC_STATUS_SUCCESS)
		return status;

	dc_buffer_t *entries = dc_buffer_new (0);
	if (entries == NULL)
		return DC_STATUS_NOMEMORY;

	status = suunto_nautic_list ((suunto_nautic_device_t *) abstract, entries);
	if (status != DC_STATUS_SUCCESS) {
		dc_buffer_free (entries);
		return status;
	}

	// The ids, newest first.
	const unsigned char *records = dc_buffer_get_data (entries);
	unsigned int count = dc_buffer_get_size (entries) / ENTRY_SIZE;
	dc_buffer_clear (ids);
	for (unsigned int i = count; i > 0; i--) {
		if (!dc_buffer_append (ids, records + (i - 1) * ENTRY_SIZE + ENTRY_START, 4)) {
			status = DC_STATUS_NOMEMORY;
			break;
		}
	}

	dc_buffer_free (entries);
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

// Every page of a resource, without a listed size to check against.
static dc_status_t
suunto_nautic_fetch_all (suunto_nautic_device_t *device, const char *path, dc_buffer_t *response)
{
	suunto_nautic_progress_t progress = {NULL, 0, 0, 0, 0};

	dc_buffer_clear (response);
	dc_status_t status = suunto_nautic_fetch_pages (device, path, &progress, response);
	if (status != DC_STATUS_SUCCESS)
		dc_buffer_clear (response);

	return status;
}

dc_status_t
suunto_nautic_device_fetch_paged (dc_device_t *abstract, const char *path, dc_buffer_t *response)
{
	if (!suunto_nautic_is_device (abstract) || path == NULL || response == NULL)
		return DC_STATUS_INVALIDARGS;

	dc_status_t status = suunto_nautic_begin ((suunto_nautic_device_t *) abstract);
	if (status != DC_STATUS_SUCCESS)
		return status;

	return suunto_nautic_fetch_all ((suunto_nautic_device_t *) abstract, path, response);
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

	dc_status_t status = suunto_nautic_begin ((suunto_nautic_device_t *) abstract);
	if (status != DC_STATUS_SUCCESS)
		return status;

	return suunto_nautic_fetch_all ((suunto_nautic_device_t *) abstract, path, summary);
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

	dc_buffer_clear (raw);

	dc_status_t status = suunto_nautic_begin (device);
	if (status != DC_STATUS_SUCCESS)
		return status;

	// The listed size to check the download against; a dive that isn't
	// listed is downloaded without the check.
	const unsigned char *record = NULL;
	dc_buffer_t *entries = dc_buffer_new (0);
	if (entries == NULL)
		return DC_STATUS_NOMEMORY;
	status = suunto_nautic_list (device, entries);
	if (status == DC_STATUS_SUCCESS) {
		const unsigned char *records = dc_buffer_get_data (entries);
		unsigned int count = dc_buffer_get_size (entries) / ENTRY_SIZE;
		for (unsigned int i = 0; i < count; i++) {
			if (array_uint32_le (records + i * ENTRY_SIZE + ENTRY_START) == id)
				record = records + i * ENTRY_SIZE;
		}
	}

	// A watch that doesn't answer the listing won't answer the download either.
	if (status == DC_STATUS_TIMEOUT || status == DC_STATUS_IO ||
		status == DC_STATUS_NODEVICE || status == DC_STATUS_CANCELLED) {
		dc_buffer_free (entries);
		return status;
	}

	unsigned int listed = 0;
	if (record) {
		// As in foreach.
		if (record[ENTRY_HASSIZE] != 1 || array_uint32_le (record + ENTRY_LENGTH + 4) != 0) {
			ERROR (abstract->context, "Unexpected size of dive %lu.", id);
			dc_buffer_free (entries);
			return DC_STATUS_DATAFORMAT;
		}
		listed = array_uint32_le (record + ENTRY_LENGTH);
	}
	dc_buffer_free (entries);

	status = suunto_nautic_download (device, NULL, (unsigned int) id, listed, record != NULL, raw, NULL);
	if (status != DC_STATUS_SUCCESS)
		dc_buffer_clear (raw);

	return status;
}

dc_status_t
suunto_nautic_device_set_resume (dc_device_t *abstract, dc_buffer_t *resume)
{
	if (!suunto_nautic_is_device (abstract))
		return DC_STATUS_INVALIDARGS;

	((suunto_nautic_device_t *) abstract)->resume = resume;

	return DC_STATUS_SUCCESS;
}

dc_status_t
suunto_nautic_device_get_nondives (dc_device_t *abstract, unsigned int *count)
{
	if (!suunto_nautic_is_device (abstract) || count == NULL)
		return DC_STATUS_INVALIDARGS;

	*count = ((suunto_nautic_device_t *) abstract)->nondives;

	return DC_STATUS_SUCCESS;
}

dc_status_t
suunto_nautic_device_get_resume (dc_device_t *abstract, unsigned int id, unsigned int *size)
{
	if (!suunto_nautic_is_device (abstract) || size == NULL)
		return DC_STATUS_INVALIDARGS;

	dc_buffer_t *resume = ((suunto_nautic_device_t *) abstract)->resume;
	size_t offset = 0;

	*size = 0;
	if (resume && suunto_nautic_resume_find (resume, id, &offset, NULL))
		*size = array_uint32_le (dc_buffer_get_data (resume) + offset + RESUME_SIZE);

	return DC_STATUS_SUCCESS;
}

// GET a path, returning the handle and the reply error code even when it
// isn't ERR_OK, so an unknown path (FF FF FF, 404) can be told apart.
static dc_status_t
suunto_nautic_resolve (suunto_nautic_device_t *device, const char *path, unsigned int *handle, unsigned int *result)
{
	size_t pathlen = strlen (path);
	if (pathlen == 0 || pathlen > MAX_PATH)
		return DC_STATUS_INVALIDARGS;

	unsigned char request[4 + MAX_PATH] = {0x01, 0x80, 0x00};
	request[3] = pathlen;
	memcpy (request + 4, path, pathlen);

	unsigned int seqnum = suunto_nautic_seqnum (device);
	dc_status_t status = suunto_nautic_send (device, RPC_OP_GET, seqnum, request, 4 + pathlen);
	if (status != DC_STATUS_SUCCESS)
		return status;

	unsigned char reply[REPLY_CONTENT] = {0};
	size_t reply_len = 0;
	status = suunto_nautic_recv (device, RPC_OP_GET_REPLY, seqnum, reply, sizeof (reply), &reply_len);
	if (status != DC_STATUS_SUCCESS)
		return status;

	if (reply_len != sizeof (reply)) {
		ERROR (device->base.context, "Unexpected reply size (" DC_PRINTF_SIZE ").", reply_len);
		return DC_STATUS_PROTOCOL;
	}

	*handle = array_uint24_le (reply);
	*result = array_uint16_le (reply + REPLY_STATUS);

	return status;
}

dc_status_t
suunto_nautic_device_subscribe (dc_device_t *abstract, const char *path, unsigned char handle[3], dc_buffer_t *value)
{
	if (!suunto_nautic_is_device (abstract) || path == NULL || handle == NULL)
		return DC_STATUS_INVALIDARGS;

	suunto_nautic_device_t *device = (suunto_nautic_device_t *) abstract;

	unsigned int h = 0, result = 0;
	dc_status_t status = suunto_nautic_resolve (device, path, &h, &result);
	if (status != DC_STATUS_SUCCESS)
		return status;

	if (HANDLE_ISINVALID (h)) {
		WARNING (abstract->context, "The watch has no %s resource.", path);
		return DC_STATUS_UNSUPPORTED;
	}
	if (result != ERR_OK) {
		ERROR (abstract->context, "Failed to resolve %s (error code %u).", path, result);
		return DC_STATUS_PROTOCOL;
	}
	array_uint24_le_set (handle, h);

	// The reply carries the current value: TYPE(2) VALUE.
	unsigned char reply[MAX_PAYLOAD] = {0};
	size_t reply_len = 0;
	status = suunto_nautic_transfer_raw (device, RPC_OP_SUBSCRIBE, RPC_OP_SUBSCRIBE_REPLY,
		h, suunto_nautic_noparams, sizeof (suunto_nautic_noparams), reply, sizeof (reply), &reply_len);
	if (status != DC_STATUS_SUCCESS)
		return status;

	result = array_uint16_le (reply + REPLY_STATUS);
	if (result != ERR_OK) {
		ERROR (abstract->context, "The watch refused the subscription to %s (error code %u).", path, result);
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
	dc_status_t status = suunto_nautic_transfer_raw (device, RPC_OP_UNSUBSCRIBE, RPC_OP_UNSUBSCRIBE_REPLY,
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
	device->polling = 1;
	status = suunto_nautic_recv (device, RPC_OP_NOTIFICATION, 0, data, sizeof (data), &size);
	device->polling = 0;
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

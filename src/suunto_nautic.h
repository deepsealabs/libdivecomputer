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

/*
 * Suunto Nautic / Ocean ("Vaasa" generation) BLE dive computers.
 *
 * Transport and framing:
 *   - BLE, with HDLC framing (flag 0x7E, escape 0x7D / XOR 0x20; no
 *     separate checksum at this layer).
 *   - Every packet is 0xA5, opcode, length(u16 LE), seqnum(u16 LE),
 *     payload(length), crc32(u32 LE), where crc32 is the reflected CRC-32
 *     (checksum_crc32r) of every preceding byte. A reply echoes the
 *     request's sequence number. The watch serves every app connected to
 *     it over the same link: a reply to another app's request is
 *     recognized by its sequence number (see below), and leftover
 *     notifications of a stream that has ended are skipped.
 *   - A client starts a session with a hello (0x12), which takes over any
 *     other session on the link. The watch answers a request from a client
 *     that didn't say hello only when another app has a session, so a GET
 *     before the hello tells whether one does; if so, the driver uses it
 *     instead of saying hello (fork only). A Suunto app whose session is
 *     taken over, and that doesn't answer with a hello of its own, stops
 *     getting replies.
 *   - The watch has one /Data stream, shared by every client. While it
 *     runs, the watch drops other clients' GETs (a PUT can still be
 *     answered), so a client that streams starves the others: the Suunto
 *     app, its requests unanswered, says hello again, which ends the stream.
 *     So the driver steps aside as soon as another app shows it is using the
 *     watch (fork only): a reply to another app's request, a hello reply, or
 *     a 404 to the UNSUBSCRIBE that closes our stream (a hello that cut off
 *     the chunk it arrived in ends our session that way). It ends a stream
 *     that is still its own (not one the other app's request or hello took),
 *     waits until the link has been quiet for a while (bounded), and fails
 *     the download with DC_STATUS_IO, keeping what arrived before for a
 *     resume. The device then sends nothing more; a new device waits for the
 *     link to go quiet on open.
 *   - A stream nobody unsubscribed (its app was killed, or the link went
 *     mid-stream) runs to its end and then holds the stream: every SUBSCRIBE
 *     gets 423 until a hello. An UNSUBSCRIBE only clears it from slot 0, so
 *     with the link quiet, the driver frees the slots, binds again in slot 0,
 *     ends it with an UNSUBSCRIBE there and subscribes again (fork only).
 *   - A GET (0x0A) resolves a path to a handle; the other requests (FETCH
 *     0x0D, SUBSCRIBE 0x10, UNSUBSCRIBE 0x11, RELEASE 0x0B) address that
 *     handle. A per-dive handle stays bound until it is released.
 *
 * Dive download:
 *   - GET /Logbook/byId/<id>/Data, SUBSCRIBE: the watch streams the
 *     compressed dive in unacknowledged notifications (0x01), each with
 *     its offset in the stream, and ends with a zero length chunk at the
 *     total size, sent twice. Then UNSUBSCRIBE and RELEASE.
 *   - A lost chunk isn't sent again. After the UNSUBSCRIBE, the same handle
 *     serves the rest in pages, like /Summary, from the offset of the
 *     first byte missing.
 *   - The stream is Heatshrink-compressed (LZSS variant, see
 *     src/heatshrink/; window_sz2 = 7, lookahead_sz2 = 5). The decoded
 *     stream is an SBEM0103 container.
 *   - GET /Logbook/byId/<id>/Summary, FETCH page by page: an uncompressed
 *     SBEM0103 container with the fields that are not in the profile
 *     (gradient factors, gas mixes). It is downloaded first, and stored in
 *     front of the profile, with its size: SUMMARY_SIZE(4) SUMMARY PROFILE.
 *
 * SBEM0103 container:
 *   - An 8-byte header (SBEM0103), then chunks ID LENGTH DATA(LENGTH). The
 *     id is one byte, or 0xFF and a uint16 LE id; the length is one byte,
 *     or 0xFF and a uint32 LE length. Unknown chunk IDs are skipped.
 *   - Decoded chunks (suunto_nautic_parser.c): 0x01 (timeline base),
 *     0x12 (1Hz absolute pressure / temperature), 0x16 (depth, cylinder
 *     pressures, NDL, time-to-surface), 0x0B (GPS), 0x17 (surface
 *     pressure -> DC_FIELD_ATMOSPHERIC), plus dive events and high-rate
 *     IMU. The ids from 0x20 up aren't fixed, see the parser.
 *   - Series libdivecomputer has no sample type for (battery, GPS
 *     accuracy, 9-axis IMU, dive-route features, gradient factors) are
 *     emitted through DC_SAMPLE_VENDOR tagged SAMPLE_VENDOR_SUUNTO_NAUTIC,
 *     each record led by a VENDOR_KIND_* byte.
 *
 * Enumeration:
 *   - /Logbook/Entries lists the dives, oldest first and in pages. Each
 *     record holds the dive id (its start time, a UNIX timestamp) and its
 *     size, which is checked against the download. Dives are downloaded
 *     newest first, stopping at the first id matching the fingerprint.
 *   - The list holds every activity the watch records, not only the dives
 *     (the Ocean is also a sports watch). An entry whose /Summary names
 *     another sport, without a dive header, is skipped before its /Data.
 *
 * Datetime:
 *   - The profile starts with the timeline base (chunk 0x01): the local
 *     time of the dive start in milliseconds, in its low 7 bytes, and the
 *     UTC offset of the watch in quarter hours, as an int8, in its top
 *     byte. dc_parser_get_datetime() returns that local time, with the
 *     offset as the time zone. The local time minus the offset is about
 *     a second after the dive id, at most.
 */

#ifndef SUUNTO_NAUTIC_H
#define SUUNTO_NAUTIC_H

#include <libdivecomputer/context.h>
#include <libdivecomputer/iostream.h>
#include <libdivecomputer/device.h>
#include <libdivecomputer/parser.h>
#include <libdivecomputer/buffer.h>

/* Family-specific public API (download by logbook id, protocol helpers). */
#include <libdivecomputer/suunto_nautic.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

dc_status_t
suunto_nautic_device_open (dc_device_t **device, dc_context_t *context, dc_iostream_t *iostream);

dc_status_t
suunto_nautic_parser_create (dc_parser_t **parser, dc_context_t *context, const unsigned char data[], size_t size);

/*
 * Whether the /Summary of a logbook entry is a dive's, for the driver to
 * leave out another activity before its /Data. An entry isn't a dive only
 * when its Header gives another sport than scuba, freediving or mermaiding,
 * and its /Summary doesn't start with a dive header. Anything else, a
 * /Summary that can't be read included, is a dive. The sport is the
 * Header's, set when the Header is found.
 */
int
suunto_nautic_parser_isdive (const unsigned char data[], unsigned int size, unsigned int id, unsigned int *sport);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SUUNTO_NAUTIC_H */

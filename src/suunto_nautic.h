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
 * EXPERIMENTAL Suunto Nautic / Ocean ("Vaasa" generation) support.
 *
 * Reverse-engineering reference: libdivecomputer issue #70. As of this
 * writing that investigation is still open and unresolved upstream.
 * Sources used to write this driver: the hex frame samples posted in
 * the issue body/comments, a ~9.8KB single-dive raw capture attached
 * there (dive_1787752091.zip, fully intact — not a text export), and a
 * full ~15,000-line Apple PacketLogger session export also attached
 * there (iphone.txt) covering one real sync that downloaded one dive in
 * ~2425 chunks. Note: PacketLogger's *text* export truncates any BLE
 * packet's displayed hex to its first ~16 bytes, so iphone.txt is only
 * reliable for structural facts near the start of each frame (opcode,
 * sequence number, ASCII path prefixes, request/response ordering) —
 * not for full-payload/CRC verification, which instead relies on the
 * issue's directly-quoted hex samples and the intact .bin file.
 *
 * What is understood and implemented here:
 *   - The BLE service/characteristic UUIDs.
 *   - The HDLC framing (identical to dc_hdlc_open: flag 0x7E, escape
 *     0x7D, XOR 0x20 — no separate checksum at this layer).
 *   - The RPC frame envelope for simple path-addressed GET requests:
 *       0xA5, opcode, sublen(u16 LE), seq(u16 LE), 0x01, 0x80, 0x00,
 *       pathlen(u8), path bytes..., crc32(u32 LE)
 *     where crc32 is the reflected CRC-32 (checksum_crc32r) of every
 *     preceding byte. Verified against 39 full frames spanning 8
 *     distinct opcodes (0x01, 0x02, 0x03, 0x08, 0x0A, 0x0B, 0x10, 0x12)
 *     from the issue's quoted samples and the intact .bin file, and
 *     lets us build valid requests for arbitrary paths rather than only
 *     replaying fixed captured bytes.
 *   - The high-level request sequence for downloading one dive, as
 *     confirmed by the full session capture: GET .../Data (opcode
 *     0x0A) -> ack (0x02) -> two stream-fetch triggers (0x0B, 0x10) ->
 *     ack (0x03), ack (0x08) -> chunk stream (opcode 0x01, repeated) ->
 *     one 0x09 frame, after which the client moves on to its next
 *     request. Two more opcodes (0x0D before the GET, 0x11 near the end
 *     of the chunk stream) appear in every real session but are not
 *     understood; they are not sent by this driver.
 *
 * What is NOT understood/implemented:
 *   - The "EVA" authentication handshake is replayed verbatim from a
 *     single captured session; whether it is universal or session/
 *     device-specific is unknown.
 *   - The "Stream Fetch" trigger frames that make the watch start
 *     sending file data are only partly explained: the sequence number
 *     generalizes cleanly (see suunto_nautic.c), but the rest of the
 *     frame appears to echo device/session state we cannot yet derive,
 *     so they are also replayed verbatim as a best-effort probe.
 *   - The response format of /Logbook/Entries and
 *     /Logbook/UnsynchronisedLogs (needed to enumerate real dive IDs)
 *     has no known sample and is not parsed.
 *   - The "PMT" chunk header/payload split. A small (31-chunk) isolated
 *     capture made the 4 bytes at header offset 16 look like a linearly
 *     incrementing byte offset (0, 278, 556, ...), which is what an
 *     earlier version of this file assumed. The full ~2425-chunk real
 *     capture refutes that: those same 4 bytes are statistically
 *     indistinguishable from random across the full stream (~50% of
 *     consecutive deltas are negative), meaning they are almost
 *     certainly just the start of the compressed payload, not
 *     reassembly metadata, and the earlier reading was a coincidence of
 *     a very small sample. The real header/payload boundary and any
 *     real reassembly mechanism remain unknown. Chunks are therefore
 *     captured and concatenated RAW (framing intact) rather than
 *     reassembled into one buffer.
 *   - The dive-data compression itself ("headerless LZ4 block" per the
 *     issue). Standard raw LZ4 block decompression was tested against a
 *     real captured chunk payload and does not decode it, so it is a
 *     distinct/unknown algorithm. suunto_nautic_parser_create() does
 *     not attempt decompression; it exposes only raw/vendor data.
 *
 * A third issue attachment (a ~1MB Suunto app JSON export,
 * 6a8f0979bfa3f0177c29721f.json) is NOT a byte-exact plaintext pair for
 * either raw capture above (it has no "1787752091" logbook ID anywhere,
 * and is dated a day before the iphone.txt session), so it can't be used
 * for a known-plaintext attack on the compression. It IS useful as the
 * confirmed TARGET decoded schema once compression is solved: a
 * DeviceLog.Header (dive/session summary: DiveTime, Depth.Max, Ascent/
 * Descent rate, Temperature, HrZones, Device.Info.{HW,SW} = "GT_RevX"/
 * firmware version, ...) plus DeviceLog.Samples, a flat time-ordered
 * array where each entry carries whichever fields changed at that
 * instant (sparse encoding) — Depth/Cylinders(tank pressure, 8
 * slots)/DeviceInternalTemperature/RtGradientFactors/NoDecTime/
 * TimeToSurface at ~8s intervals during the dive, and Altitude/Cadence/
 * Power/Speed/Temperature/AbsPressure at ~1Hz for the whole activity.
 *
 * Practical implication: this driver can connect, authenticate
 * (best-effort), and download the raw bytes of a *known* logbook entry
 * ID via suunto_nautic_device_download(). It cannot yet enumerate which
 * IDs exist on a given watch, and it cannot decode a downloaded entry
 * into an actual dive profile.
 */

#ifndef SUUNTO_NAUTIC_H
#define SUUNTO_NAUTIC_H

#include <libdivecomputer/context.h>
#include <libdivecomputer/iostream.h>
#include <libdivecomputer/device.h>
#include <libdivecomputer/parser.h>
#include <libdivecomputer/buffer.h>

// suunto_nautic_device_request() / suunto_nautic_device_download() are
// declared in the public include/libdivecomputer/suunto_nautic.h
// instead of here — see that header's comment for why this family (and
// only this one) has a public API beyond the generic dc_device_open() /
// dc_device_foreach() / dc_parser_new2() dispatch used everywhere else.
#include <libdivecomputer/suunto_nautic.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

dc_status_t
suunto_nautic_device_open (dc_device_t **device, dc_context_t *context, dc_iostream_t *iostream);

dc_status_t
suunto_nautic_parser_create (dc_parser_t **parser, dc_context_t *context, const unsigned char data[], size_t size);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SUUNTO_NAUTIC_H */

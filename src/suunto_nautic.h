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
 * Reverse-engineering reference: libdivecomputer issue #70. Sources used
 * to write this driver: the hex frame samples and two written reports
 * posted in the issue (an initial report, and a follow-up "Extended
 * Status, Cylinders and GPS" / "Full Chunk Dictionary" update that
 * solved the compression), a ~9.8KB single-dive raw capture attached
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
 *   - The MDS chunk header wrapping each compressed block (opcode 0x01
 *     frames): 28 bytes, with the true payload size as a little-endian
 *     u16 at offset 20-21 and the payload itself starting at offset 28.
 *     An earlier version of this file used a 20-byte header based on a
 *     small (31-chunk) isolated capture where the 4 bytes at offset 16
 *     happened to look like a linearly incrementing byte offset (0,
 *     278, 556, ...); that was refuted by a full ~2425-chunk real
 *     capture, where the same bytes are statistically indistinguishable
 *     from random. They are simply the start of the compressed payload
 *     under the wrong header size, not reassembly metadata — reading
 *     from offset 20 instead of 28 injects 8 bytes of garbage into the
 *     decompressor's LZSS window and corrupts everything after the
 *     first block.
 *   - The compression: Heatshrink (an LZSS variant; see
 *     src/heatshrink/), window_sz2=7, lookahead_sz2=5. NOT LZ4 as an
 *     earlier version of this file assumed based on the issue's initial
 *     "headerless LZ4 block" description — that description turned out
 *     to be a naming/guess error on the issue author's part, corrected
 *     in their own follow-up. Verified byte-for-byte against a
 *     reference Python implementation (heatshrink2) using the real
 *     dive_1787752091.zip capture; the decompressed output starts with
 *     the expected "SBEM0103" magic.
 *   - The decompressed container format: SBEM0103, a numeric
 *     Type-Length-Value stream — [id: 1 byte][length: 1 byte][value:
 *     length bytes], where length==255 means an extended 4-byte
 *     little-endian length follows before the value. Implemented in
 *     suunto_nautic_parser.c, which currently decodes chunk 0x12 (1Hz
 *     AbsPressure/Temperature) and chunk 0x16 (Depth, cylinder/tank
 *     pressures, NDL, time-to-surface) into real dc_field/dc_sample
 *     output — verified end-to-end against dive_1787752091.zip via the
 *     public dc_parser_new2()/dc_parser_get_field()/
 *     dc_parser_samples_foreach() API (max depth 2.6m, temperature
 *     22.9-24.3C, tank pressure 222.8-225.6 bar — all physically
 *     plausible and internally consistent).
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
 *   - Most SBEM chunk IDs beyond 0x12/0x16. The issue's chunk
 *     dictionary also names 0x08 (activity), 0x0B (GPS), 0x0E
 *     (satellites), 0x14 (battery), 0x17 (surface pressure) with exact
 *     byte offsets, and 0x1A/0x1B/0x1C/0x1E (dive events: laps, alarms,
 *     gas switches, notifications) and 0x23/0x24 (high-frequency IMU)
 *     more qualitatively, without exact offsets. None of these are
 *     wired into the parser yet; unknown chunk IDs are silently
 *     skipped (not treated as errors), so adding them is additive.
 *   - No chunk in the decoded stream carries a wall-clock timestamp.
 *     Per the issue, that likely lives in the separate /Summary
 *     endpoint (not yet explored/requested by this driver). Sample
 *     time is therefore a synthetic per-chunk-0x12 counter (see
 *     suunto_nautic_parser.c), and dc_parser_get_datetime() is
 *     unsupported.
 *
 * A third issue attachment (a ~1MB Suunto app JSON export,
 * 6a8f0979bfa3f0177c29721f.json) is a different dive than either raw
 * capture above (no shared logbook ID, different date), so it wasn't a
 * usable known-plaintext pair — but its DeviceLog.Header/.Samples
 * schema (Depth, Cylinders tank pressure, DeviceInternalTemperature,
 * NoDecTime, TimeToSurface, ...) matches the now-decoded SBEM chunk
 * 0x16 fields closely enough to have served as a second, independent
 * confirmation that the decode is producing the right kind of data.
 *
 * Practical implication: this driver can connect, authenticate
 * (best-effort), download, and decode a *known* logbook entry ID via
 * suunto_nautic_device_download() + suunto_nautic_parser_create() into
 * a real depth/temperature/tank-pressure profile. It cannot yet
 * enumerate which IDs exist on a given watch, cannot get the true dive
 * date/time, and does not yet decode dive events, GPS, or the other
 * chunk IDs named above.
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

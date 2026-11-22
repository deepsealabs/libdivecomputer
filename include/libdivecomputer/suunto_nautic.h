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
 * Public extension API for Suunto Nautic / Ocean ("Vaasa") support.
 *
 * The standard dc_device_foreach() / dc_parser_new2() interface is
 * supported and is the normal way to download dives. These additional
 * entry points let a client download or list by logbook id directly, and
 * expose the underlying RPC transport for protocol exploration.
 *
 * dc_device_foreach(), suunto_nautic_device_list(),
 * suunto_nautic_device_download(), suunto_nautic_device_download_summary()
 * and suunto_nautic_device_fetch_paged() first drop the packets left on the
 * link since the last call, such as the watch's replies to another app that
 * has since finished, so that only another app's traffic during the call
 * makes the device step aside (see suunto_nautic_device_taken_over()).
 */

#ifndef DC_SUUNTO_NAUTIC_H
#define DC_SUUNTO_NAUTIC_H

#include <libdivecomputer/context.h>
#include <libdivecomputer/device.h>
#include <libdivecomputer/buffer.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Issue a raw GET request to an arbitrary RPC endpoint path (e.g.
 * "/System/Mode", "/Logbook/Entries") and return the raw, undecoded
 * response payload (the ACK only).
 */
/*
 * 1 when the watch answered the EVA handshake on open. The open still succeeds
 * when only other frames arrived before the link went quiet (a sleeping watch
 * or the tail of an earlier stream), so 0 means the first request may time out.
 *
 * The open fails with DC_STATUS_TIMEOUT only when another app is using the
 * watch: it waits for the link to go quiet (about 20 s at most) and gives up
 * if it doesn't. The host can try again later. A watch that is asleep opens
 * with this returning 0.
 */
int
suunto_nautic_device_handshake_acknowledged (dc_device_t *device);

/*
 * 1 once the device has stepped aside for another app using the watch (a
 * reply to its request, its hello, or a stream it ended), 0 otherwise. The
 * call that saw it fails with DC_STATUS_IO, the status a lost link also gives,
 * after waiting (about 20 s at most) for the other app to finish, or with
 * DC_STATUS_CANCELLED when the host cancels that wait; a wait for a
 * notification fails without that wait. From then on the device sends nothing
 * more: every call fails with DC_STATUS_IO, so the host closes it and opens a
 * new one, once the other app is done, to carry on.
 * What was downloaded before is kept for a resume, see
 * suunto_nautic_device_set_resume().
 */
int
suunto_nautic_device_taken_over (dc_device_t *device);

dc_status_t
suunto_nautic_device_request (dc_device_t *device, const char *path, dc_buffer_t *response);

/*
 * Fetch a small whole resource whose response doesn't fit in a single ACK
 * (e.g. "/Logbook/Entries", "/Logbook/UnsynchronisedLogs"). Unlike
 * suunto_nautic_device_request(), which returns only the ACK, this runs the
 * GET -> ACK -> short fetch -> data sequence and returns the raw response.
 * Not for compressed/paginated dive data -- use suunto_nautic_device_download().
 */
dc_status_t
suunto_nautic_device_fetch (dc_device_t *device, const char *path, dc_buffer_t *response);

/*
 * Diagnostic variant of suunto_nautic_device_fetch(): runs the same
 * GET -> ACK -> short fetch sequence but returns the RAW response frame
 * (the whole 0xA5.. packet) with no opcode/status validation, for
 * exporting the actual bytes when a normal fetch fails.
 */
dc_status_t
suunto_nautic_device_fetch_raw (dc_device_t *device, const char *path, dc_buffer_t *response);

/*
 * List dive ids (each is a UNIX-timestamp LogId), newest-first, without
 * downloading the dives. Follows every /Logbook/Entries page. `ids` receives the ids packed as little-endian
 * uint32 (4 bytes each); read them back as a plain array. This is the cheap
 * way to enumerate the logbook; the entry-parsing lives here in the driver so
 * callers don't reimplement it.
 */
dc_status_t
suunto_nautic_device_list (dc_device_t *device, dc_buffer_t *ids);

/*
 * The pure entry-parser behind suunto_nautic_device_list(): extract dive-start
 * ids (newest-first) from a raw /Logbook/Entries response into `ids` (capacity
 * `max_ids`), returning the count. Exposed so it can be unit-tested directly
 * against captured entry buffers, with no device.
 */
unsigned int
suunto_nautic_extract_entry_ids (const unsigned char data[], size_t size, unsigned int *ids, unsigned int max_ids);

/*
 * Paged 0x0D fetch of any resource (GET -> every page -> release), up to
 * MAX_PAGES. For multi-page /Logbook/byId/<id>/... resources such as
 * Descriptors; `response` receives the data bytes with page headers stripped.
 */
dc_status_t
suunto_nautic_device_fetch_paged (dc_device_t *device, const char *path, dc_buffer_t *response);

/*
 * Download a dive's /Summary (metadata: gradient factors, gas mix, ...).
 * Uses the paginated 0x0D fetch; `summary` receives the raw, uncompressed
 * SBEM0103 payload (page headers and CRCs stripped). The caller locates the "SBEM0103" signature and reads
 * fields at documented offsets from it (unlike the profile from
 * suunto_nautic_device_download(), this is not Heatshrink-compressed).
 */
dc_status_t
suunto_nautic_device_download_summary (dc_device_t *device, const char *logbook_id, dc_buffer_t *summary);

/*
 * Download and decompress a specific logbook entry, given its numeric
 * id as it appears in a "/Logbook/byId/<id>/..." path (e.g.
 * "1787752091"). On success, `raw` holds the dive as dc_device_foreach()
 * delivers it, for suunto_nautic_parser_create(): SUMMARY_SIZE(4) SUMMARY
 * PROFILE, the /Summary SBEM with its size in front (uint32 LE), then the
 * decompressed /Data stream.
 *
 * The download is checked against the size /Logbook/Entries lists for the
 * id. A download that doesn't match it, like any other failure, returns an
 * error with `raw` empty.
 */
dc_status_t
suunto_nautic_device_download (dc_device_t *device, const char *logbook_id, dc_buffer_t *raw);

/*
 * Carry a dive's download over a dropped link. `resume` is a buffer the
 * caller keeps for one watch across connections and hands to each device it
 * opens for that watch; NULL detaches it. The device doesn't own it, so it
 * must outlive the device or be detached first.
 *
 * When a listed dive fails to download because the link went, another app
 * was using the watch (DC_STATUS_IO, after waiting for it to finish; try
 * again once it is done), or the download was cancelled (DC_STATUS_TIMEOUT,
 * _IO, _NODEVICE, _CANCELLED),
 * the device keeps the compressed /Data received so far in `resume`. The
 * next download of the same dive, by dc_device_foreach() or
 * suunto_nautic_device_download(), on this device or a later one, fetches
 * the /Summary first, which gives the size of the whole /Data, then GETs the
 * /Data again and reads only what is missing, in pages from the first
 * missing byte, instead of streaming it from the start. A success, or any
 * failure other than the link's, forgets the dive, and so does a resumed
 * download that times out without getting any further. It holds up to 4
 * dives, the oldest going first, and its content is only valid for the watch
 * it came from.
 *
 * get_resume reports the number of /Data bytes held for a dive, 0 when
 * none. Neither call may run while a download does.
 */
dc_status_t
suunto_nautic_device_set_resume (dc_device_t *device, dc_buffer_t *resume);

dc_status_t
suunto_nautic_device_get_resume (dc_device_t *device, unsigned int id, unsigned int *size);

/*
 * The number of entries the last dc_device_foreach() left out because they
 * aren't dives: the watch lists every activity it records, and foreach skips
 * one whose /Summary names another sport, before its /Data. The by-id
 * download fetches any entry.
 */
dc_status_t
suunto_nautic_device_get_nondives (dc_device_t *device, unsigned int *count);

/*
 * Value subscriptions (e.g. "/Logbook/UnsynchronisedLogs", "/Sync/BusyState").
 * subscribe writes the resource handle and the current value; the value is
 * Whiteboard-encoded as [type:u16 LE][value...]. wait_notification returns the
 * next pushed value on any subscribed handle, or DC_STATUS_TIMEOUT after
 * `timeout` milliseconds without a byte received, which isn't logged as an
 * error. Another app's replies on the link are skipped meanwhile; its hello,
 * which ends the session and its subscriptions, fails the wait at once with
 * DC_STATUS_IO, and suunto_nautic_device_taken_over() then returns 1. Not
 * valid while a dive download is in progress.
 * unsubscribe also releases the handle when it is a per-id slot.
 */
dc_status_t
suunto_nautic_device_subscribe (dc_device_t *device, const char *path, unsigned char handle[3], dc_buffer_t *value);

dc_status_t
suunto_nautic_device_unsubscribe (dc_device_t *device, const unsigned char handle[3]);

dc_status_t
suunto_nautic_device_wait_notification (dc_device_t *device, unsigned int timeout, unsigned char handle[3], dc_buffer_t *value);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* DC_SUUNTO_NAUTIC_H */

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
 * EXPERIMENTAL public extension API for Suunto Nautic/Ocean ("Vaasa")
 * support. See src/suunto_nautic.h (not installed/public — internal
 * driver header) for the full status of what is/isn't understood about
 * this device family (libdivecomputer issue #70).
 *
 * Every other supported family is driven entirely through the generic
 * dc_device_open() / dc_device_foreach() / dc_parser_new2() interface,
 * with no family-specific public API. This family is a deliberate
 * exception: dc_device_foreach() cannot yet enumerate real dives (the
 * /Logbook/Entries response format is still unknown), so these two
 * functions exist to let client applications still get useful work
 * done — exploring the RPC protocol, and downloading + decompressing a
 * dive by a known logbook ID into its decoded SBEM0103 form, ready for
 * suunto_nautic_parser_create() — while that enumeration piece is still
 * being reverse-engineered.
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
 * "/System/Mode", "/Logbook/Entries", "/Logbook/UnsynchronisedLogs")
 * and return the raw, undecoded response payload. Intended for
 * interactive protocol exploration: every response captured this way
 * is a candidate input for further reverse-engineering.
 */
dc_status_t
suunto_nautic_device_request (dc_device_t *device, const char *path, dc_buffer_t *response);

/*
 * Download and decompress a specific logbook entry, given its numeric
 * id as it appears in a "/Logbook/byId/<id>/..." path (e.g.
 * "1787752091"). On success, `raw` holds the decoded SBEM0103 TLV
 * stream (magic-verified), suitable for suunto_nautic_parser_create().
 */
dc_status_t
suunto_nautic_device_download (dc_device_t *device, const char *logbook_id, dc_buffer_t *raw);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* DC_SUUNTO_NAUTIC_H */

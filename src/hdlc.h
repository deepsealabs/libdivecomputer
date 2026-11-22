/*
 * libdivecomputer
 *
 * Copyright (C) 2023 Jef Driesen
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

#ifndef DC_HDLC_H
#define DC_HDLC_H

#include <libdivecomputer/common.h>
#include <libdivecomputer/context.h>
#include <libdivecomputer/iostream.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Create a HDLC I/O stream layered on top of another base I/O stream.
 *
 * @param[out]  iostream    A location to store the HDLC I/O stream.
 * @param[in]   context     A valid context.
 * @param[in]   base        A valid I/O stream.
 * @param[in]   isize       The input packet size in bytes.
 * @param[in]   osize       The output packet size in bytes.
 * @returns #DC_STATUS_SUCCESS on success, or another #dc_status_t code
 * on failure.
 */
dc_status_t
dc_hdlc_open (dc_iostream_t **iostream, dc_context_t *context, dc_iostream_t *base, size_t isize, size_t osize);

/**
 * Let the flag that closes a frame also open the next one. A frame that is
 * cut off before its closing flag then ends at the opening flag of the frame
 * after it, and that frame is still read, instead of being skipped up to its
 * closing flag. Only for a device that sends nothing between its frames: any
 * bytes after a closing flag are read as the next frame. Off by default.
 *
 * @param[in]   iostream    A valid HDLC I/O stream.
 * @param[in]   value       Non-zero to share the flags, zero not to.
 * @returns #DC_STATUS_SUCCESS on success, or another #dc_status_t code
 * on failure.
 */
dc_status_t
dc_hdlc_set_shared_flag (dc_iostream_t *iostream, unsigned int value);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* DC_HDLC_H */

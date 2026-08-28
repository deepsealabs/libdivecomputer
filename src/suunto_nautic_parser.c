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
 * EXPERIMENTAL: the data this parser receives is either a raw, still
 * SML/LZ4-compressed dive capture, or a raw diagnostic response captured
 * by suunto_nautic_device_foreach() (see suunto_nautic.c). Neither the
 * compression algorithm nor the SML container format is understood yet
 * (libdivecomputer issue #70), so this parser makes NO attempt to decode
 * depth/time/temperature samples. It only exposes the raw bytes back to
 * the caller as a single DC_SAMPLE_VENDOR sample, so client applications
 * can inspect/export them (e.g. to feed further reverse-engineering)
 * instead of receiving fabricated or silently-wrong dive data.
 */

#include <stdlib.h>

#include "suunto_nautic.h"
#include "context-private.h"
#include "parser-private.h"

typedef struct suunto_nautic_parser_t {
	dc_parser_t base;
} suunto_nautic_parser_t;

static dc_status_t suunto_nautic_parser_get_field (dc_parser_t *abstract, dc_field_type_t type, unsigned int flags, void *value);
static dc_status_t suunto_nautic_parser_samples_foreach (dc_parser_t *abstract, dc_sample_callback_t callback, void *userdata);

static const dc_parser_vtable_t suunto_nautic_parser_vtable = {
	sizeof(suunto_nautic_parser_t),
	DC_FAMILY_SUUNTO_NAUTIC,
	NULL, /* set_clock */
	NULL, /* set_atmospheric */
	NULL, /* set_density */
	NULL, /* datetime -- date/time encoding is unknown */
	suunto_nautic_parser_get_field,
	suunto_nautic_parser_samples_foreach,
	NULL, /* destroy */
};

dc_status_t
suunto_nautic_parser_create (dc_parser_t **out, dc_context_t *context, const unsigned char data[], size_t size)
{
	suunto_nautic_parser_t *parser = NULL;

	if (out == NULL)
		return DC_STATUS_INVALIDARGS;

	parser = (suunto_nautic_parser_t *) dc_parser_allocate (context, &suunto_nautic_parser_vtable, data, size);
	if (parser == NULL) {
		ERROR (context, "Failed to allocate memory.");
		return DC_STATUS_NOMEMORY;
	}

	*out = (dc_parser_t *) parser;

	return DC_STATUS_SUCCESS;
}

static dc_status_t
suunto_nautic_parser_get_field (dc_parser_t *abstract, dc_field_type_t type, unsigned int flags, void *value)
{
	// Every structured field (dive time, max depth, gas mixes, ...)
	// requires decoding the SML container, which is not implemented.
	return DC_STATUS_UNSUPPORTED;
}

static dc_status_t
suunto_nautic_parser_samples_foreach (dc_parser_t *abstract, dc_sample_callback_t callback, void *userdata)
{
	if (callback == NULL || abstract->size == 0)
		return DC_STATUS_SUCCESS;

	dc_sample_value_t sample = {0};
	sample.vendor.type = 0; // no known vendor-data subtype yet
	sample.vendor.size = abstract->size;
	sample.vendor.data = abstract->data;

	callback (DC_SAMPLE_VENDOR, &sample, userdata);

	return DC_STATUS_SUCCESS;
}

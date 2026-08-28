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
 * Parses the SBEM0103 TLV stream produced by
 * suunto_nautic_device_download() after MDS-chunk extraction and
 * Heatshrink decompression (see suunto_nautic.c/.h). Format and chunk
 * IDs per libdivecomputer issue #70's second report:
 *
 *   [chunk id: 1 byte][length: 1 byte][value: length bytes]
 *   length == 255 means an extended 4-byte little-endian length follows
 *   immediately, before the value.
 *
 * Only the chunks confirmed against real captured data are decoded
 * here (0x12 and 0x16). Several other chunk IDs are documented in the
 * issue (0x08 activity, 0x0B GPS, 0x0E satellites, 0x14 battery, 0x17
 * surface pressure, 0x1A/0x1B/0x1C/0x1E dive events, 0x23/0x24
 * high-frequency IMU) but are not yet wired into dc_field/dc_sample
 * output — unknown chunk IDs are simply skipped, not treated as
 * errors, so extending this later is additive.
 *
 * No chunk in this stream carries a wall-clock timestamp; per the
 * issue, that likely lives in the separate /Summary endpoint (not yet
 * explored). dc_parser_get_datetime() is therefore unsupported. Sample
 * time is a synthetic counter incremented once per chunk 0x12 record,
 * since that chunk is described as a 1Hz profile — the 2-byte field at
 * its offset 0 looks like a sub-second phase (values cluster on
 * multiples of 10, wrapping 0-90) rather than a usable elapsed-time
 * counter, so it is intentionally not used for timing.
 */

#include <string.h>
#include <stdlib.h>

#include "suunto_nautic.h"
#include "context-private.h"
#include "parser-private.h"
#include "array.h"

#define SBEM_MAGIC_SIZE 8

#define CHUNK_PROFILE_1HZ    0x12
#define CHUNK_EXTENDED_STATUS 0x16

#define MAX_TANKS 8

typedef struct suunto_nautic_tank_t {
	unsigned int used;
	double beginpressure; // bar
	double endpressure;   // bar
} suunto_nautic_tank_t;

typedef struct suunto_nautic_parser_t {
	dc_parser_t base;
	unsigned int cached;
	unsigned int divetime; // seconds
	double maxdepth;       // meters
	double avgdepth;       // meters
	unsigned int have_temperature;
	double temperature_minimum;
	double temperature_maximum;
	unsigned int ntanks;
	suunto_nautic_tank_t tank[MAX_TANKS];
} suunto_nautic_parser_t;

typedef struct sbem_chunk_t {
	unsigned int id;
	const unsigned char *data;
	unsigned int size;
} sbem_chunk_t;

static dc_status_t suunto_nautic_parser_get_field (dc_parser_t *abstract, dc_field_type_t type, unsigned int flags, void *value);
static dc_status_t suunto_nautic_parser_samples_foreach (dc_parser_t *abstract, dc_sample_callback_t callback, void *userdata);

static const dc_parser_vtable_t suunto_nautic_parser_vtable = {
	sizeof(suunto_nautic_parser_t),
	DC_FAMILY_SUUNTO_NAUTIC,
	NULL, /* set_clock */
	NULL, /* set_atmospheric */
	NULL, /* set_density */
	NULL, /* datetime -- no timestamp chunk identified yet, see file header */
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

	parser->cached = 0;

	*out = (dc_parser_t *) parser;

	return DC_STATUS_SUCCESS;
}

// Advance to the next TLV chunk starting at *offset. Returns 0 (and
// leaves *offset unchanged) once the buffer is exhausted or malformed.
static int
suunto_nautic_sbem_next (const unsigned char data[], unsigned int size, unsigned int *offset, sbem_chunk_t *chunk)
{
	unsigned int pos = *offset;
	unsigned int header = 2;
	unsigned int length = 0;

	if (pos + 2 > size)
		return 0;

	unsigned int id = data[pos];
	length = data[pos + 1];

	if (length == 255) {
		if (pos + 6 > size)
			return 0;
		length = array_uint32_le (data + pos + 2);
		header = 6;
	}

	if (pos + header + length > size)
		return 0;

	chunk->id = id;
	chunk->data = data + pos + header;
	chunk->size = length;

	*offset = pos + header + length;

	return 1;
}

static dc_status_t
suunto_nautic_parser_parse (dc_parser_t *abstract, dc_sample_callback_t callback, void *userdata)
{
	suunto_nautic_parser_t *parser = (suunto_nautic_parser_t *) abstract;

	if (abstract->size < SBEM_MAGIC_SIZE || memcmp (abstract->data, "SBEM0103", SBEM_MAGIC_SIZE) != 0) {
		ERROR (abstract->context, "Unexpected magic in the SBEM stream.");
		return DC_STATUS_DATAFORMAT;
	}

	unsigned int offset = SBEM_MAGIC_SIZE;
	unsigned int time = 0; // synthetic, see file header comment

	double maxdepth = 0.0;
	double depth_sum = 0.0;
	unsigned int depth_count = 0;

	unsigned int have_temperature = 0;
	double temperature_minimum = 0.0;
	double temperature_maximum = 0.0;

	unsigned int ntanks = 0;
	suunto_nautic_tank_t tank[MAX_TANKS];
	memset (tank, 0, sizeof (tank));

	sbem_chunk_t chunk;
	while (suunto_nautic_sbem_next (abstract->data, (unsigned int) abstract->size, &offset, &chunk)) {
		if (chunk.id == CHUNK_PROFILE_1HZ && chunk.size >= 18) {
			double temperature = array_uint16_le (chunk.data + 16) / 100.0 - 273.15;

			if (!have_temperature) {
				temperature_minimum = temperature_maximum = temperature;
				have_temperature = 1;
			} else {
				if (temperature < temperature_minimum)
					temperature_minimum = temperature;
				if (temperature > temperature_maximum)
					temperature_maximum = temperature;
			}

			if (callback) {
				dc_sample_value_t sample = {0};
				sample.time = time * 1000;
				callback (DC_SAMPLE_TIME, &sample, userdata);
				sample.temperature = temperature;
				callback (DC_SAMPLE_TEMPERATURE, &sample, userdata);
			}

			time++;
		} else if (chunk.id == CHUNK_EXTENDED_STATUS) {
			if (chunk.size >= 6) {
				double depth = array_float_le (chunk.data + 2);

				if (depth > maxdepth)
					maxdepth = depth;
				depth_sum += depth;
				depth_count++;

				if (callback) {
					dc_sample_value_t sample = {0};
					sample.time = time * 1000;
					callback (DC_SAMPLE_TIME, &sample, userdata);
					sample.depth = depth;
					callback (DC_SAMPLE_DEPTH, &sample, userdata);
				}
			}

			// Cylinders array: 8 elements of 18 bytes, starting at
			// offset 42 (idx:1, ?:1, pressure:4 LE Pa, pressure2:4 LE Pa, ...).
			if (chunk.size >= 42 + MAX_TANKS * 18) {
				for (unsigned int i = 0; i < MAX_TANKS; i++) {
					unsigned int base = 42 + i * 18;
					unsigned int pressure_pa = array_uint32_le (chunk.data + base + 2);
					if (pressure_pa == 0)
						continue; // not installed, per the issue's mapping

					double bar = pressure_pa / 100000.0;
					if (!tank[i].used) {
						tank[i].used = 1;
						tank[i].beginpressure = bar;
						ntanks++;
					}
					tank[i].endpressure = bar;

					if (callback) {
						dc_sample_value_t sample = {0};
						sample.time = time * 1000;
						callback (DC_SAMPLE_TIME, &sample, userdata);
						sample.pressure.tank = i;
						sample.pressure.value = bar;
						callback (DC_SAMPLE_PRESSURE, &sample, userdata);
					}
				}
			}
		}
	}

	parser->divetime = time;
	parser->maxdepth = maxdepth;
	parser->avgdepth = depth_count ? depth_sum / depth_count : 0.0;
	parser->have_temperature = have_temperature;
	parser->temperature_minimum = temperature_minimum;
	parser->temperature_maximum = temperature_maximum;
	parser->ntanks = ntanks;
	memcpy (parser->tank, tank, sizeof (tank));
	parser->cached = 1;

	return DC_STATUS_SUCCESS;
}

static dc_status_t
suunto_nautic_parser_get_field (dc_parser_t *abstract, dc_field_type_t type, unsigned int flags, void *value)
{
	dc_status_t status = DC_STATUS_SUCCESS;
	suunto_nautic_parser_t *parser = (suunto_nautic_parser_t *) abstract;

	if (!parser->cached) {
		status = suunto_nautic_parser_parse (abstract, NULL, NULL);
		if (status != DC_STATUS_SUCCESS)
			return status;
	}

	if (value == NULL)
		return DC_STATUS_SUCCESS;

	dc_tank_t *tank = (dc_tank_t *) value;

	switch (type) {
	case DC_FIELD_DIVETIME:
		*((unsigned int *) value) = parser->divetime;
		break;
	case DC_FIELD_MAXDEPTH:
		*((double *) value) = parser->maxdepth;
		break;
	case DC_FIELD_AVGDEPTH:
		*((double *) value) = parser->avgdepth;
		break;
	case DC_FIELD_TEMPERATURE_MINIMUM:
		if (!parser->have_temperature)
			return DC_STATUS_UNSUPPORTED;
		*((double *) value) = parser->temperature_minimum;
		break;
	case DC_FIELD_TEMPERATURE_MAXIMUM:
		if (!parser->have_temperature)
			return DC_STATUS_UNSUPPORTED;
		*((double *) value) = parser->temperature_maximum;
		break;
	case DC_FIELD_TANK_COUNT:
		*((unsigned int *) value) = parser->ntanks;
		break;
	case DC_FIELD_TANK:
		if (flags >= MAX_TANKS || !parser->tank[flags].used)
			return DC_STATUS_INVALIDARGS;
		tank->type = DC_TANKVOLUME_NONE;
		tank->volume = 0.0;
		tank->workpressure = 0.0;
		tank->beginpressure = parser->tank[flags].beginpressure;
		tank->endpressure = parser->tank[flags].endpressure;
		tank->gasmix = DC_GASMIX_UNKNOWN;
		tank->usage = DC_USAGE_NONE;
		break;
	default:
		return DC_STATUS_UNSUPPORTED;
	}

	return DC_STATUS_SUCCESS;
}

static dc_status_t
suunto_nautic_parser_samples_foreach (dc_parser_t *abstract, dc_sample_callback_t callback, void *userdata)
{
	return suunto_nautic_parser_parse (abstract, callback, userdata);
}

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
 * Chunks 0x12, 0x16, and 0x17 are decoded against real captured data;
 * 0x0B (GPS) is decoded to spec but the reference dive used for
 * verification doesn't contain one, so it's unconfirmed against real
 * bytes. Chunks 0x08 (activity), 0x0E (GPS satellite info), and 0x14
 * (battery) have confirmed fixed lengths (used for ghost-chunk
 * resync, see suunto_nautic_sbem_fixed_length) but aren't decoded --
 * libdivecomputer has no dc_field/dc_sample slot for "activity type,"
 * "satellite count," or "battery," so there's nothing to wire them to
 * yet. Chunks 0x23/0x24 are confirmed to be raw accelerometer/
 * gyroscope dumps used for client-side dead-reckoning to draw a 3D
 * dive path -- not real GPS/position data -- so they're permanently
 * out of scope here, not just "not yet done." 0x1A/0x1B/0x1C/0x1E
 * (dive events: laps, alarms, gas switches) are a harder case: the
 * chunk IDs for these are NOT fixed constants -- they're assigned
 * dynamically per dive/device via a schema (SDS::LogbookDecoder
 * ::setDescriptors in the official Android app) and identified by
 * path name (e.g. "Events.GasSwitch.GasNumber"), not a hardcoded
 * numeric ID the way 0x12/0x16/0x0B/0x17 are. Unknown chunk IDs are
 * simply skipped, not treated as errors, so extending any of this
 * later is additive.
 *
 * No chunk in this stream carries a wall-clock timestamp. Per a later
 * report on the issue, the dive start time is NOT inside the SBEM
 * payload at all -- it IS the dive ID returned by /Logbook/Entries
 * (an array of 4-byte little-endian UInt32, each one a standard UNIX
 * timestamp, used as the logbook_id argument to
 * suunto_nautic_device_download()). Since that value is already known
 * to the caller before download() is ever invoked, wiring it into
 * dc_parser_get_datetime() would require either threading it through
 * suunto_nautic_parser_create() as an extra argument or having the
 * caller set it separately -- an API decision, not made here.
 * dc_parser_get_datetime() is therefore still unsupported for now.
 *
 * Similarly, device metadata (serial number, hardware/software
 * version) is not in this payload either -- it's retrieved out-of-band
 * during the BLE connection handshake (serial from the advertisement
 * packet or /System/Info; HW/SW version via /System/Mode or
 * /Dev/Capabilities), before the logbook is ever queried. Not this
 * parser's concern, noted here only so it isn't hunted for again.
 *
 * Sample time is a synthetic counter incremented once per chunk 0x12
 * record, since that chunk is described as a 1Hz profile — the 2-byte
 * field at its offset 0 looks like a sub-second phase (values cluster
 * on multiples of 10, wrapping 0-90) rather than a usable elapsed-time
 * counter, so it is intentionally not used for timing.
 */

#include <string.h>
#include <stdlib.h>

#include "suunto_nautic.h"
#include "context-private.h"
#include "parser-private.h"
#include "array.h"

#define SBEM_MAGIC_SIZE 8

#define CHUNK_TIMELINE_BASE   0x01
#define CHUNK_ACTIVITY        0x08
#define CHUNK_GPS             0x0B
#define CHUNK_GPS_SATELLITES  0x0E
#define CHUNK_BATTERY         0x14
#define CHUNK_PROFILE_1HZ     0x12
#define CHUNK_EXTENDED_STATUS 0x16
#define CHUNK_SURFACE_PRESSURE 0x17
// Dive-event groups: the chunk id IS the event subgroup, each record is
// [timeDelta:2 LE][Type:1][Active:1] (Active 1=begin/onset, 0=end/cleared).
// Type indexes the subgroup's own enum (see the descriptor schema).
#define CHUNK_EVENT_ALARM     0x18
#define CHUNK_EVENT_WARNING   0x19
#define CHUNK_EVENT_NOTIFY    0x1A
#define CHUNK_EVENT_STATE     0x1B
#define CHUNK_DIVE_STATE      0x1C // [timeDelta:2][state:1]; 0=Idling,1=Diving,2=Recovering
#define CHUNK_DIVE_STATUS     0x1E // [timeDelta:2][active:1]; the DiveActive flag
#define CHUNK_GAS_SWITCH      0x1F // [timeDelta:2][gasnumber:int16 LE]

// DiveState values (CHUNK_DIVE_STATE payload).
#define DIVE_STATE_IDLING     0
#define DIVE_STATE_DIVING     1
#define DIVE_STATE_RECOVERING 2

#define MAX_TANKS 8
#define MAX_GASMIXES 4

// Field offsets within the /Summary SBEM0103 section (relative to its
// "SBEM0103" signature), confirmed against real hardware. The dive profile
// (/Data) carries samples but not these; the driver appends the /Summary
// SBEM after the profile so this parser can expose them the standard way.
#define SUMMARY_GF_LOW   0x33 // uint16 LE, %
#define SUMMARY_GF_HIGH  0x35 // uint16 LE, %
#define SUMMARY_GAS_BASE 0xC7 // first gas; 4 bytes each: id, O2%, He%, type

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
	unsigned int have_location;
	dc_location_t location;
	unsigned int have_atmospheric;
	double atmospheric; // bar
	unsigned int have_datetime;
	dc_ticks_t datetime; // dive start, UNIX seconds
	// From the /Summary SBEM section appended after the profile, if present.
	unsigned int ngasmixes;
	dc_gasmix_t gasmix[MAX_GASMIXES];
	unsigned int have_decomodel;
	dc_decomodel_t decomodel;
} suunto_nautic_parser_t;

typedef struct sbem_chunk_t {
	unsigned int id;
	const unsigned char *data;
	unsigned int size;
} sbem_chunk_t;

static dc_status_t suunto_nautic_parser_get_datetime (dc_parser_t *abstract, dc_datetime_t *datetime);
static dc_status_t suunto_nautic_parser_get_field (dc_parser_t *abstract, dc_field_type_t type, unsigned int flags, void *value);
static dc_status_t suunto_nautic_parser_samples_foreach (dc_parser_t *abstract, dc_sample_callback_t callback, void *userdata);

static const dc_parser_vtable_t suunto_nautic_parser_vtable = {
	sizeof(suunto_nautic_parser_t),
	DC_FAMILY_SUUNTO_NAUTIC,
	NULL, /* set_clock */
	NULL, /* set_atmospheric */
	NULL, /* set_density */
	suunto_nautic_parser_get_datetime, /* datetime */
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

// Chunk IDs whose payload length is fixed and has been confirmed
// against real captured data. Heatshrink decompression can leave
// localized artifacts in the stream (e.g. runs of a single repeated
// byte), which a strict linear TLV walk would otherwise misread as a
// chunk header -- permanently desyncing every chunk after it. Any
// candidate header naming one of these IDs is only accepted if its
// length byte matches; otherwise it is a "ghost chunk" and the parser
// resynchronizes by scanning forward one byte at a time.
static int
suunto_nautic_sbem_fixed_length (unsigned int id)
{
	switch (id) {
	case CHUNK_ACTIVITY:         return 6;
	case CHUNK_GPS:              return 20;
	case CHUNK_GPS_SATELLITES:   return 6;
	case CHUNK_BATTERY:          return 7;
	case CHUNK_EXTENDED_STATUS:  return 195;
	case CHUNK_SURFACE_PRESSURE: return 14;
	default:                     return -1; // unknown or variable length
	}
}

// Advance to the next TLV chunk starting at *offset. Returns 0 (and
// leaves *offset unchanged) once the buffer is exhausted.
static int
suunto_nautic_sbem_next (const unsigned char data[], unsigned int size, unsigned int *offset, sbem_chunk_t *chunk)
{
	unsigned int pos = *offset;

	while (pos + 2 <= size) {
		unsigned int id = data[pos];
		unsigned int length = data[pos + 1];
		unsigned int header = 2;

		if (length == 255) {
			if (pos + 6 > size) {
				pos++;
				continue;
			}
			length = array_uint32_le (data + pos + 2);
			header = 6;
		}

		int fixed = suunto_nautic_sbem_fixed_length (id);
		if (fixed >= 0 && (unsigned int) fixed != length) {
			// Ghost chunk: a real chunk with this id never has
			// this length. Resynchronize.
			pos++;
			continue;
		}

		if (pos + header + length > size) {
			pos++;
			continue;
		}

		chunk->id = id;
		chunk->data = data + pos + header;
		chunk->size = length;

		*offset = pos + header + length;

		return 1;
	}

	return 0;
}

// The driver appends the (uncompressed) /Summary SBEM after the profile,
// so the combined buffer holds two "SBEM0103" sections. Return the offset
// of the second one (the /Summary), or `size` when there's only the
// profile. Bounds the profile chunk walk and locates the /Summary fields.
static size_t
suunto_nautic_find_summary (const unsigned char *data, size_t size)
{
	if (size < SBEM_MAGIC_SIZE)
		return size;
	for (size_t i = SBEM_MAGIC_SIZE; i + SBEM_MAGIC_SIZE <= size; i++) {
		if (memcmp (data + i, "SBEM0103", SBEM_MAGIC_SIZE) == 0)
			return i;
	}
	return size;
}

// Parse gradient factors and gas mixes from the /Summary section, whose
// "SBEM0103" signature is at `sbem` (length `size`). Offsets are relative
// to that signature (confirmed on real hardware). Gases are validated by
// plausibility (O2 in 1..100, He in 0..100-O2) and counted until the first
// implausible slot, since unused slots hold unrelated bytes.
static void
suunto_nautic_parse_summary (suunto_nautic_parser_t *parser, const unsigned char *sbem, size_t size)
{
	if (size >= SUMMARY_GF_HIGH + 2) {
		unsigned int low = array_uint16_le (sbem + SUMMARY_GF_LOW);
		unsigned int high = array_uint16_le (sbem + SUMMARY_GF_HIGH);
		parser->decomodel.type = DC_DECOMODEL_BUHLMANN;
		parser->decomodel.conservatism = 0;
		parser->decomodel.params.gf.low = low;
		parser->decomodel.params.gf.high = high;
		parser->have_decomodel = 1;
	}

	for (unsigned int i = 0; i < MAX_GASMIXES; i++) {
		size_t base = SUMMARY_GAS_BASE + (size_t) i * 4;
		if (base + 3 > size)
			break;
		unsigned int o2 = sbem[base + 1];
		unsigned int he = sbem[base + 2];
		if (o2 < 1 || o2 > 100 || he > 100 || o2 + he > 100)
			break; // unused/implausible slot -- stop
		parser->gasmix[parser->ngasmixes].oxygen = o2 / 100.0;
		parser->gasmix[parser->ngasmixes].helium = he / 100.0;
		parser->gasmix[parser->ngasmixes].nitrogen = 1.0 - (o2 + he) / 100.0;
		parser->gasmix[parser->ngasmixes].usage = DC_USAGE_NONE;
		parser->ngasmixes++;
	}
}

// Map a Suunto dive-event (subgroup = chunk id, plus the subgroup's Type
// enum) to the closest libdivecomputer sample-event type. Suunto's set is
// richer than dc_sample_event_t, so unmapped subtypes fall back to a
// generic marker; the raw subgroup+type is still available via the
// descriptor for anyone needing the exact Suunto label.
static unsigned int
suunto_nautic_map_event (unsigned int chunk_id, unsigned int type)
{
	switch (chunk_id) {
	case CHUNK_EVENT_ALARM:
		switch (type) {
		case 1: case 2: return SAMPLE_EVENT_PO2;                 // PO2 Low/High
		case 3:         return SAMPLE_EVENT_AIRTIME;             // Tank Pressure
		case 5:         return SAMPLE_EVENT_ASCENT;              // Ascent Speed
		case 10:        return SAMPLE_EVENT_CEILING;             // Deco Stop Broken
		case 12:        return SAMPLE_EVENT_DEEPSTOP;            // Deep Stop Broken
		case 13:        return SAMPLE_EVENT_SAFETYSTOP_MANDATORY;// Safety Stop Broken
		default:        return SAMPLE_EVENT_VIOLATION;
		}
	case CHUNK_EVENT_WARNING:
		switch (type) {
		case 28:        return SAMPLE_EVENT_AIRTIME;             // User Tank Pressure
		default:        return SAMPLE_EVENT_VIOLATION;
		}
	case CHUNK_EVENT_STATE:
		switch (type) {
		case 19:          return SAMPLE_EVENT_CEILING;           // Ndl exceeded
		case 35: case 38: return SAMPLE_EVENT_DECOSTOP;          // At/Ahead Deco Stop
		case 36: case 39: return SAMPLE_EVENT_DEEPSTOP;          // At/Ahead Deep Stop
		case 37: case 40: return SAMPLE_EVENT_SAFETYSTOP;        // At/Ahead Safety Stop
		default:          return SAMPLE_EVENT_BOOKMARK;
		}
	case CHUNK_EVENT_NOTIFY:
		switch (type) {
		case 11:        return SAMPLE_EVENT_GASCHANGE;           // Gas Switch
		default:        return SAMPLE_EVENT_BOOKMARK;
		}
	default:
		return SAMPLE_EVENT_BOOKMARK;
	}
}

static dc_status_t
suunto_nautic_parser_parse (dc_parser_t *abstract, dc_sample_callback_t callback, void *userdata)
{
	suunto_nautic_parser_t *parser = (suunto_nautic_parser_t *) abstract;

	if (abstract->size < SBEM_MAGIC_SIZE || memcmp (abstract->data, "SBEM0103", SBEM_MAGIC_SIZE) != 0) {
		ERROR (abstract->context, "Unexpected magic in the SBEM stream.");
		return DC_STATUS_DATAFORMAT;
	}

	// The profile (/Data) is the first SBEM section; an optional /Summary
	// section (gradient factors, gas mix) is appended after it. Walk only
	// the profile here; parse /Summary separately below.
	size_t profile_size = suunto_nautic_find_summary (abstract->data, abstract->size);

	unsigned int offset = SBEM_MAGIC_SIZE;
	// Time is delta-encoded: every chunk (except the timeline base 0x01)
	// begins with a signed int16 LE millisecond delta at payload[0:2]. The
	// running sum is the absolute sample time -- there is no per-sample
	// absolute timestamp and no fixed sample rate.
	int time_ms = 0;

	// Dive phase, from CHUNK_DIVE_STATE. The stream carries brief spurious
	// Diving/Recovering blips at the very start, so dive time is the LONGEST
	// contiguous Diving span, not the first one. Average depth is taken over
	// Diving samples only; counting from the first raw sample instead includes
	// the pre-dive/surface phase and skews both low.
	unsigned int dive_state = DIVE_STATE_IDLING;
	int diving_start_ms = -1;
	int max_dive_ms = 0;

	double maxdepth = 0.0;
	double depth_sum = 0.0;
	unsigned int depth_count = 0;

	unsigned int have_temperature = 0;
	double temperature_minimum = 0.0;
	double temperature_maximum = 0.0;

	unsigned int ntanks = 0;
	suunto_nautic_tank_t tank[MAX_TANKS];
	memset (tank, 0, sizeof (tank));

	unsigned int have_location = 0;
	dc_location_t location = {0};

	unsigned int have_atmospheric = 0;
	double atmospheric = 0.0;

	unsigned int have_datetime = 0;

	sbem_chunk_t chunk;
	while (suunto_nautic_sbem_next (abstract->data, (unsigned int) profile_size, &offset, &chunk)) {
		// Advance the clock by this chunk's leading ms delta (all groups
		// except the timeline base carry one).
		if (chunk.id != CHUNK_TIMELINE_BASE && chunk.size >= 2)
			time_ms += (int16_t) array_uint16_le (chunk.data);

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
				sample.time = (unsigned int) time_ms;
				callback (DC_SAMPLE_TIME, &sample, userdata);
				sample.temperature = temperature;
				callback (DC_SAMPLE_TEMPERATURE, &sample, userdata);
			}
		} else if (chunk.id == CHUNK_EXTENDED_STATUS) {
			if (chunk.size >= 6) {
				double depth = array_float_le (chunk.data + 2);

				if (depth > maxdepth)
					maxdepth = depth;
				// Average only over the Diving phase (matches the app).
				if (dive_state == DIVE_STATE_DIVING) {
					depth_sum += depth;
					depth_count++;
				}

				if (callback) {
					dc_sample_value_t sample = {0};
					sample.time = (unsigned int) time_ms;
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
						sample.time = (unsigned int) time_ms;
						callback (DC_SAMPLE_TIME, &sample, userdata);
						sample.pressure.tank = i;
						sample.pressure.value = bar;
						callback (DC_SAMPLE_PRESSURE, &sample, userdata);
					}
				}
			}
		} else if (chunk.id == CHUNK_GPS && chunk.size >= 18) {
			// Payload: [timeDelta:2][UTC:8 ms LE][lat:4][lon:4]. UTC is an
			// absolute UNIX time in milliseconds; subtracting this sample's
			// relative time (time_ms) yields the stream-start epoch, i.e. the
			// dive start (== the logbook id, confirmed to the second). This is
			// the only absolute clock in the stream, so the first GPS fix sets
			// the dive datetime.
			unsigned long long utc_ms = array_uint64_le (chunk.data + 2);
			int lat_raw = (int) array_uint32_le (chunk.data + 10);
			int lon_raw = (int) array_uint32_le (chunk.data + 14);

			if (!have_datetime && utc_ms > (unsigned long long) time_ms) {
				have_datetime = 1;
				parser->datetime = (dc_ticks_t) ((utc_ms - (unsigned long long) time_ms) / 1000);
			}

			if (!have_location) {
				have_location = 1;
				location.latitude = lat_raw / 1.0e7;
				location.longitude = lon_raw / 1.0e7;
				location.altitude = 0.0;
			}

			if (callback) {
				dc_sample_value_t sample = {0};
				sample.time = (unsigned int) time_ms;
				callback (DC_SAMPLE_TIME, &sample, userdata);
				sample.location.latitude = lat_raw / 1.0e7;
				sample.location.longitude = lon_raw / 1.0e7;
				sample.location.altitude = 0.0;
				callback (DC_SAMPLE_LOCATION, &sample, userdata);
			}
		} else if (chunk.id == CHUNK_DIVE_STATE && chunk.size >= 3) {
			unsigned int new_state = chunk.data[2];
			if (new_state == DIVE_STATE_DIVING && dive_state != DIVE_STATE_DIVING) {
				diving_start_ms = time_ms;
			} else if (new_state != DIVE_STATE_DIVING && dive_state == DIVE_STATE_DIVING) {
				if (diving_start_ms >= 0 && time_ms - diving_start_ms > max_dive_ms)
					max_dive_ms = time_ms - diving_start_ms;
				diving_start_ms = -1;
			}
			dive_state = new_state;
		} else if ((chunk.id == CHUNK_EVENT_ALARM || chunk.id == CHUNK_EVENT_WARNING ||
				chunk.id == CHUNK_EVENT_NOTIFY || chunk.id == CHUNK_EVENT_STATE) && chunk.size >= 4) {
			// [timeDelta:2][Type:1][Active:1]; Active 1=begin, 0=end.
			if (callback) {
				dc_sample_value_t sample = {0};
				sample.time = (unsigned int) time_ms;
				callback (DC_SAMPLE_TIME, &sample, userdata);
				sample.event.type = suunto_nautic_map_event (chunk.id, chunk.data[2]);
				sample.event.flags = chunk.data[3] ? SAMPLE_FLAGS_BEGIN : SAMPLE_FLAGS_END;
				sample.event.value = 0;
				callback (DC_SAMPLE_EVENT, &sample, userdata);
			}
		} else if (chunk.id == CHUNK_GAS_SWITCH && chunk.size >= 4) {
			// [timeDelta:2][gasnumber:int16 LE].
			if (callback) {
				dc_sample_value_t sample = {0};
				sample.time = (unsigned int) time_ms;
				callback (DC_SAMPLE_TIME, &sample, userdata);
				sample.event.type = SAMPLE_EVENT_GASCHANGE;
				sample.event.flags = SAMPLE_FLAGS_BEGIN;
				sample.event.value = (unsigned int) (int16_t) array_uint16_le (chunk.data + 2);
				callback (DC_SAMPLE_EVENT, &sample, userdata);
			}
		} else if (chunk.id == CHUNK_SURFACE_PRESSURE && chunk.size >= 6) {
			// 3 Float32 values at offset 2/6/10 (SurfacePressure,
			// MaxSurfacePressure, MinSurfacePressure), Pa -- offset
			// 2, not 0: like chunk 0x16's Depth field, there are 2
			// leading bytes before the data starts. Confirmed against
			// a real captured chunk: offset 2 = 103662.24, offset 6 =
			// 103844.73, offset 10 = 101325.0 (standard atmospheric,
			// exactly), matching the issue's own worked example
			// (103662.2, 103844.7, 101325.0 Pa) almost to the decimal.
			// DC_FIELD_ATMOSPHERIC is a single ambient-pressure
			// reading in bar, so only SurfacePressure (offset 2) is
			// used -- last one logged wins, matching how e.g.
			// temperature/depth here track a running min/max rather
			// than every single reading being independently
			// meaningful for this field.
			have_atmospheric = 1;
			atmospheric = array_float_le (chunk.data + 2) / 100000.0;
		}
	}

	// A dive still in progress at the end of the stream closes the final span.
	if (dive_state == DIVE_STATE_DIVING && diving_start_ms >= 0 &&
			time_ms - diving_start_ms > max_dive_ms)
		max_dive_ms = time_ms - diving_start_ms;

	// Dive time = the longest Diving span (seconds). Fall back to the full
	// elapsed time if no DiveState markers were seen.
	if (max_dive_ms > 0)
		parser->divetime = (unsigned int) ((max_dive_ms + 500) / 1000);
	else
		parser->divetime = (unsigned int) ((time_ms + 500) / 1000);
	parser->maxdepth = maxdepth;
	parser->avgdepth = depth_count ? depth_sum / depth_count : 0.0;
	parser->have_temperature = have_temperature;
	parser->temperature_minimum = temperature_minimum;
	parser->temperature_maximum = temperature_maximum;
	parser->ntanks = ntanks;
	memcpy (parser->tank, tank, sizeof (tank));
	parser->have_location = have_location;
	parser->location = location;
	parser->have_atmospheric = have_atmospheric;
	parser->atmospheric = atmospheric;
	parser->have_datetime = have_datetime;

	// Gradient factors and gas mixes from the appended /Summary section.
	parser->ngasmixes = 0;
	parser->have_decomodel = 0;
	memset (parser->gasmix, 0, sizeof (parser->gasmix));
	memset (&parser->decomodel, 0, sizeof (parser->decomodel));
	if (profile_size < abstract->size) {
		suunto_nautic_parse_summary (parser, abstract->data + profile_size,
			abstract->size - profile_size);
	}

	parser->cached = 1;

	return DC_STATUS_SUCCESS;
}

static dc_status_t
suunto_nautic_parser_get_datetime (dc_parser_t *abstract, dc_datetime_t *datetime)
{
	suunto_nautic_parser_t *parser = (suunto_nautic_parser_t *) abstract;

	if (!parser->cached) {
		dc_status_t status = suunto_nautic_parser_parse (abstract, NULL, NULL);
		if (status != DC_STATUS_SUCCESS)
			return status;
	}

	// The dive start is derived from the first GPS fix's absolute UTC. A dive
	// without a surface GPS fix has no absolute clock in the stream; the caller
	// falls back to the logbook id (which is that same timestamp).
	if (!parser->have_datetime)
		return DC_STATUS_UNSUPPORTED;

	if (datetime && !dc_datetime_gmtime (datetime, parser->datetime))
		return DC_STATUS_DATAFORMAT;

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
	case DC_FIELD_LOCATION:
		if (!parser->have_location)
			return DC_STATUS_UNSUPPORTED;
		*((dc_location_t *) value) = parser->location;
		break;
	case DC_FIELD_ATMOSPHERIC:
		if (!parser->have_atmospheric)
			return DC_STATUS_UNSUPPORTED;
		*((double *) value) = parser->atmospheric;
		break;
	case DC_FIELD_GASMIX_COUNT:
		*((unsigned int *) value) = parser->ngasmixes;
		break;
	case DC_FIELD_GASMIX:
		if (flags >= parser->ngasmixes)
			return DC_STATUS_INVALIDARGS;
		*((dc_gasmix_t *) value) = parser->gasmix[flags];
		break;
	case DC_FIELD_DECOMODEL:
		if (!parser->have_decomodel)
			return DC_STATUS_UNSUPPORTED;
		*((dc_decomodel_t *) value) = parser->decomodel;
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

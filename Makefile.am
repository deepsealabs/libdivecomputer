# examples/ and doc/ don't exist in this fork -- excised from the
# vendored snapshot this fork was seeded from (see the "Snapshot
# vendored libdivecomputer" commit). Automake validates every SUBDIRS
# entry's directory exists at generation time regardless of any
# ENABLE_*/if-conditional guard, so these can't be here even
# conditionally disabled -- they have to be absent entirely.
SUBDIRS = include src

AM_MAKEFLAGS = -s
ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libdivecomputer.pc

# contrib/ doesn't exist in this fork either -- same excised-from-the-
# vendored-snapshot situation as examples/ and doc/ above. Unlike
# SUBDIRS, EXTRA_DIST doesn't fail at `automake` generation time for a
# missing file -- it only surfaces at `make dist`/`make distcheck`,
# which is where this was actually caught.
EXTRA_DIST = \
	libdivecomputer.pc.in

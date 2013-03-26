Release Notes
=============

This file contains a reverse-chronological list of releases and their associated
changes.

## Version 0.6.2 ##

Released 2013-03-26.

 * Various minor fixes and cleanups.
 * node-router: No longer depend on `btree` on embedded platforms.
 * transactions: No longer use `btree.c` on embedded builds.
 * Contiki support improvements and fixes.
 * Allow `.well-known/core` lookups to work on `smcp-simple` Contiki example
 * smcpctl: Remove some cruft from `get` command.
 * smcpctl: Add `--non` argument for sending non-confirmable get requests.
 * contiki: Fix outbound packet alignment for 32-bit platforms.
 * Add `smcp-complex` contiki example to travis.
 * Try to better detect when `libdl` is not available.

## Version 0.6.1 ##

Released 2013-02-13.

 * Version bump to 0.6.1
 * Add `--version` query to `smcpctl`
 * configure.ac: Replaced `AM_CONFIG_HEADER()` with `AC_CONFIG_HEADERS()`
 * Added contiki examples 'smcp-simple' and 'smcp-plugtest' to `.travis.yml`
 * Added contiki examples to `Makefile.am`, so that they are included in
   the tarball.
 * Various updates and cleanups.
 * Various Contiki fixes.
 * Make the "smcp-variable_node" no longer be a node. You can now use it
   without using the node-router.
 * Split off `smcp-inbound.c` from `smcp.c`.
 * Do better about avoiding the use of `printf()` (and variants).

## Version 0.6 ##

Initial public release.


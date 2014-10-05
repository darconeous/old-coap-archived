Release Notes
=============

This file contains a reverse-chronological list of releases and their associated
changes.

## Version 0.6.5 ##

Released 2014-10-05

 * We support RFC7252!
 * Support for running multiple SMCP instances on different threads in the same process.
 * smcp-inbound: Better abstracted duplicate packet detection.
 * Added some headers that were necessary to compile against `libsmcp`.
 * Fixes for various warnings and pedantic compiler errors.
 * Make `smcp_wait()` return SMCP_STATUS_TIMEOUT if the timeout expired.
 * unit-tests: Added "test-concurrency" to test general concurrency.
 * Cleanup of various untidy bits.
 * Added some additional documentation.

## Version 0.6.4 ##

Released 2014-06-13

 * SMCP is now an installable dynamically-linkable library, `libsmcp`.
 * Support for using multiple SMCP instances on different threads.
 * Support for more recent versions of Contiki.
 * Better networking layer abstraction.
 * Various API Improvements.
 * Various bugfixes.
 * Fixed various warnings.
 * configure.ac: Poach the version from `git describe`, if available.

## Version 0.6.3 ##

Released 2013-05-22

 * Various Contiki fixes.
 * Fix for building on Cygwin.
 * url-helpers: Improvements to `url_parse()` for lower stack usage.
 * Various other minor updates and fixes.

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


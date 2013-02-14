
## Version 0.6.1 ##

Released 2013-02-13.

 * Version bump to 0.6.1
 * Add --version query to smcpctl
 * configure.ac: Replaced AM_CONFIG_HEADER() with AC_CONFIG_HEADERS()
 * Added contiki examples 'smcp-simple' and 'smcp-plugtest' to .travis.yml
 * Added contiki examples to Makefile.am, so that they are included in
   the tarball.
 * Various updates and cleanups.
 * Various Contiki fixes.
 * Make the "smcp-variable_node" no longer be a node. You can now use it
   without using the node-router.
 * Split off `smcp-inbound.c` from `smcp.c`.
 * Do better about avoiding the use of printf (and variants).



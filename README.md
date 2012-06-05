SMTP — A C-Based CoAP Stack
===========================

SMTP is a C-based CoAP stack which is suitable for embedded
environments. Features include:

 * Low stack usage. (With continuing work to make it lower)
 * Fully asynchronous.
 * Supports both Contiki and BSD sockets.
 * Supports sending and receiving asynchronous responses.
 * Supports "pairing", which allows you to make POSTs to arbitrary
   URLs when a value chagnes.
 * Supports retransmission of confirmable packets.
 * CoAP-to-HTTP proxy, based on CuRL (incomplete, but kinda working)

Features which are in progress:

 * Observing. (Will be based on the current pairing implementaiton)

## Contiki Support ##

SMTP fully supports Contiki. To build the contiki examples, just make
sure that the CONTIKI variable is set point to your contiki root, like
so:

    cd contiki-src/examples/smcp-simple
	make CONTIKI=~/Projects/contiki TARGET=minimal-net

## SMCPCTL ##

`smcpctl` is a command-line interface for browsing, observing, and
interacting with CoAP devices. It is, for the most part, self-
documenting.


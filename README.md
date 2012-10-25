SMTP — A C-Based CoAP Stack
===========================

SMTP is a C-based CoAP stack which is suitable for embedded
environments. Features include:

 * Fully asynchronous.
 * Supports both Contiki and BSD sockets.
 * Supports sending and receiving asynchronous responses.
 * Supports "pairing", which allows you to make POSTs to arbitrary
   URLs when a value chagnes.
 * Supports retransmission of confirmable packets.
 * CoAP-to-HTTP proxy, based on CuRL (incomplete, but kinda working)
 * Supports more than 14 options in the header.
 * Low stack usage. (With continuing work to make it lower)

Features which are in progress:

 * Observing. (Will be based on the current pairing implementaiton)

Initial focus is on correctness of implementation. Stack usage and other
performance optimizations will become the focus later on.

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

## Test Servers ##

	* <coap://129.132.15.80/>
	* <coap://ns.tzi.org/>


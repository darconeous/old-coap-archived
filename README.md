SMCP — A C-Based CoAP Stack
===========================

SMCP is a C-based CoAP stack which is suitable for embedded
environments. Features include:

 * Supports draft-ietf-core-coap-12.
 * Fully asynchronous.
 * Supports both Contiki and BSD sockets.
 * Supports sending and receiving asynchronous responses.
 * Supports observing resources and offering observable resources.
 * Supports retransmission of confirmable packets.
 * Supports "pairing", which allows you to make POSTs to arbitrary
   URLs when a value chagnes.
 * CoAP-to-HTTP proxy, based on CuRL (incomplete, but kinda working)
 * Designed for low stack usage. (but some bloat has snuck in, will
   improve in the future)

Initial focus is on correctness of implementation. Stack usage and other
performance optimizations will become the focus later on.

## Why is it called SMCP? ##

Historical reasons. Don't think about it too much.

## Contiki Support ##

SMCP fully supports Contiki. To build the contiki examples, just make
sure that the CONTIKI variable is set point to your contiki root, like
so:

    cd contiki-src/examples/smcp-simple
	make CONTIKI=~/Projects/contiki TARGET=minimal-net

## Installing via Homebrew on OS X ##

To get the "latest-release":

	brew install https://raw.github.com/darconeous/smcp/formula/smcp.rb

To get the bleeding-edge release:

	brew install https://raw.github.com/darconeous/smcp/formula/smcp.rb --HEAD

## SMCPCTL ##

`smcpctl` is a command-line interface for browsing, observing, and
interacting with CoAP devices. It is, for the most part, self-
documenting.

## Test Servers ##

	* <coap://coap.me/>
	* <coap://vs0.inf.ethz.ch/> (But doesn't seem to support CoAP-12 yet...)


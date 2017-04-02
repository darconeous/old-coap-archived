SMCP — Simple Management and Control Protocol
=============================================

SMCP is an experimental [CoAP][1]-based machine-to-machine (M2M)
protocol that is in the early stages of development. It allows you to
create complicated interdependent relationships between resources on
different devices without relying on an outside service. A very rough
high-level scatter-shot description of the protocol is described
[here](https://gist.github.com/darconeous/fee998ee26260caad1443546e81fe06c).

This project contains a library (`libsmcp`) which is used to implement
the protocol. This project also includes `smcpd`, which is a plug-in
based posix CoAP daemon that can be used as a starting point for
adding SMCP support to Linux-based embedded devices and servers.

`libsmcp` uses [LibNyoci](http://libnyoci.org) for CoAP connectivity.
LibNyoci was [spun off](https://github.com/darconeous/smcp/issues/37)
from `libsmcp` in late March of 2017 to allow SMCP to focus on M2M
features.

---

`libsmcp`'s current features include:

*   In-band multicast group management (Working toward full
    [RFC7390][3] support)
*   Resource pairing (Pull-based, using CoAP observing)

All of the above features are configurable in-band using CoAP.

Planned features include:

*   Additional resource pairing types (Push and Sync)
*   Pairing predicates and transforms (Functional relationships
    between resources using a simple forth-like language)
*   Scenes
*   Timers (counts down to an event after being triggered)
*   Scheduled events (time-of-day, sunset/sunrise, etc)
*   Rich access controls

`libsmcp` is currently working toward a v1.0 API. Until v1.0 is
released, all APIs are subject to change.

[1]: http://tools.ietf.org/html/rfc7252
[2]: http://tools.ietf.org/html/rfc7390

## Getting Help ##

If you are having trouble with SMCP, you can join the official SMCP
mailing list and ask your questions there.

*   [SMCP Developers Group](https://groups.google.com/group/smcp-dev)
    <smcp-dev@googlegroups.com>

## Getting, building, and installing via Git ##

The first step is to get and install [LibNyoci](http://libnyoci.org).

Once you have your dependencies, go ahead and clone SMCP:

    $ git clone git://github.com/darconeous/smcp.git
    $ cd smcp

To build the latest tagged stable release:

    $ git checkout latest-release
    $ ./configure
    $ make
    $ sudo make install

For bleeding-edge:

    $ git checkout master
    $ git archive origin/autoconf/master | tar xv
    $ ./configure
    $ make
    $ sudo make install

## Getting, building, and installing from an archive ##

    $ curl https://github.com/darconeous/smcp/archive/full/latest-release.zip > latest-release.zip
    $ unzip latest-release.zip
    $ cd smcp-latest-release
    $ ./configure
    $ make
    $ sudo make install

## Installing via Homebrew on OS X ##

To get the "latest-release":

    $ brew tap darconeous/embedded
    $ brew install smcp

To get the bleeding-edge release:

    $ brew tap darconeous/embedded
    $ brew install smcp --HEAD

## Authors and Contributors ##

*   Robert Quattlebaum <darco@deepdarc.com>

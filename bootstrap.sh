#! /bin/sh
libtoolize --force --install
aclocal -I m4
autoheader
automake --force-missing --foreign --add-missing --copy
autoconf
#autoreconf

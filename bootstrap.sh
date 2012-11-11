#! /bin/sh
set -x
libtoolize --copy --force --install || exit -1
aclocal -I m4 || exit -1
autoheader || exit -1
automake --force-missing --foreign --add-missing --copy || exit -1
autoconf || exit -1
#autoreconf

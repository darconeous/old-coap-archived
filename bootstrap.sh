#!/bin/sh

die() {
	echo " *** $1 failed with error code $?"
	exit 1
}

cd "`dirname $0`"

set -x
mkdir -p m4

AUTOMAKE=automake\ --foreign autoreconf --verbose --force --install || die autoreconf

#which libtoolize || which glibtoolize && alias libtoolize=glibtoolize
#libtoolize --copy --force --install || die libtoolize
#aclocal -I m4 || die aclocal
#autoheader || die autoheader
#autoconf || die autoconf
#automake --force-missing --foreign --add-missing --copy || die automake

set +x

echo
echo Success.


#!/bin/sh

die() {
	echo " *** ERROR: " $*
	exit 1
}

set -x

if [ $BUILD_PLATFORM = contiki ]
then
	git clone git://github.com/contiki-os/contiki.git || die
	cd contiki || die
	git checkout 1d69099 || die
	cd .. || die
fi

exit 0

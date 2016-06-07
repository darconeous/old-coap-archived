#!/bin/sh

PREV_PATH="`pwd`"

die() {
	echo " *** ERROR: " $*
	exit 1
}

if [ $BUILD_PLATFORM = unix ]
then
	[ -e configure ] || ./bootstrap.sh || die

	mkdir -p "${BUILD_MAKEPATH}" || die

	cd "${BUILD_MAKEPATH}" || die

	../configure ${BUILD_CONFIGFLAGS} || die

	cd "${PREV_PATH}" || die
fi

make -C "${BUILD_MAKEPATH}" ${BUILD_MAKEARGS} || die

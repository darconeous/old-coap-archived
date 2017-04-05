#!/bin/sh

PREV_PATH="`pwd`"

die() {
	echo " *** ERROR: " $*
	exit 1
}

export PKG_CONFIG_PATH="`cd ~ && pwd`/lib/pkgconfig:${PKG_CONFIG_PATH}"

echo PKG_CONFIG_PATH=${PKG_CONFIG_PATH}

if [ $BUILD_PLATFORM = unix ]
then
	[ -e configure ] || ./bootstrap.sh || die

	mkdir -p "${BUILD_MAKEPATH}" || die

	cd "${BUILD_MAKEPATH}" || die

	../configure ${BUILD_CONFIGFLAGS} || die

	cd "${PREV_PATH}" || die
fi

make -C "${BUILD_MAKEPATH}" ${BUILD_MAKEARGS} || die

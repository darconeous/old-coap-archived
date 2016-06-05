#!/bin/sh

die() {
	echo " *** $1 failed with error code $?"
	exit 1
}

cd "`dirname $0`"

mkdir -p m4

AUTOMAKE=automake\ --foreign autoreconf --verbose --force --install || die autoreconf

echo
echo Success.


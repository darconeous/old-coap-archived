#!/bin/sh
die() {
	echo " *** ERROR: " $*
	exit 1
}

set -x

[ $TRAVIS_OS_NAME != linux ] || {
#	sudo apt-get -y update || die
#	sudo apt-get -y install bsdtar autoconf-archive automake autoconf || die

	cd .. || die
	git clone --depth=50 --branch=master https://github.com/darconeous/libnyoci.git || die
	cd libnyoci || die
	./bootstrap.sh || die
	./configure --prefix="`cd ~ && pwd`" || die
	make || die
	make install || die
}

[ $TRAVIS_OS_NAME != osx ] || {
	brew install autoconf-archive || die
	brew tap darconeous/embedded || die
	brew install libnyoci --HEAD || die
}

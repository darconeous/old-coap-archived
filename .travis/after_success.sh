#!/bin/sh

PREV_PATH="`pwd`"

die() {
	echo " *** ERROR: " $*
	exit 1
}

set -x

prep_ssh_key() {
	openssl aes-256-cbc -K "${encrypted_0f1462f1026b_key}" -iv "${encrypted_0f1462f1026b_iv}" -in .travis/deploy.prv.enc -out .travis/deploy.prv -d &&
	chmod 600 .travis/deploy.prv &&
	ssh-add .travis/deploy.prv &&
	git config --global user.name "Travis CI" &&
	git config --global user.email "noreply@travis-ci.com"
}

AUTOCONF_BRANCH="autoconf/$TRAVIS_BRANCH"

if [ $TRAVIS_REPO_SLUG = "darconeous/smcp" ]     \
&& [ $TRAVIS_BRANCH = "master" ]                 \
&& [ $TRAVIS_OS_NAME = "linux" ]                 \
&& [ $TRAVIS_PULL_REQUEST = "false" ]            \
&& [ $BUILD_MAKEPATH = "build" ]                 \
&& [ $BUILD_MAKEARGS = "distcheck" ]             \
&& prep_ssh_key                                  #
then
	git fetch --unshallow origin || die

	git fetch origin scripts:scripts ${AUTOCONF_BRANCH}:${AUTOCONF_BRANCH} ${TRAVIS_BRANCH}:${TRAVIS_BRANCH} || die

	PREVREV="`git rev-parse ${AUTOCONF_BRANCH}`"

	echo "Checking for update to '${AUTOCONF_BRANCH}'..."

	git checkout scripts || die

	NO_PUSH=1 ./update-autoconf-master ${TRAVIS_BRANCH} || die

	CHANGED_LINES=`git diff "${PREVREV}".."${AUTOCONF_BRANCH}" | grep '^[-+]' | grep -v '^[-+]SOURCE_VERSION=' | wc -l`

	if [ "$CHANGED_LINES" -gt "2" ]
	then
		echo "Branch '${AUTOCONF_BRANCH}' is OUT OF DATE."

		git checkout "${TRAVIS_BRANCH}" || die

		git push git@github.com:${TRAVIS_REPO_SLUG}.git ${AUTOCONF_BRANCH}:${AUTOCONF_BRANCH} || die
	else
		echo "Branch '${AUTOCONF_BRANCH}' is still up-to-date."
	fi
else
	echo "Skipping update of '${AUTOCONF_BRANCH}'."
fi

exit 0

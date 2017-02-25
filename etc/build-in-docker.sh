#!/bin/sh
#
# Copyright (c) 2016 Nest Labs, Inc.
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


DIR="`dirname $0`"

"${DIR}"/run-in-docker.sh -i 'DIR="`pwd`" &&
mkdir -p /build &&
cd /build && "${DIR}"/configure --enable-dtls &&
make -j `nproc` check AM_DEFAULT_VERBOSITY=1
' || exit 1

"${DIR}"/run-in-docker.sh -i 'DIR="`pwd`" &&
mkdir -p /build &&
cd /build && "${DIR}"/configure --enable-embedded SMCP_CONF_TRANS_ENABLE_BLOCK2=1 SMCP_CONF_TRANS_ENABLE_OBSERVING=1 &&
make -j `nproc` check AM_DEFAULT_VERBOSITY=1
' || exit 1

"${DIR}"/run-in-docker.sh -i 'DIR="`pwd`" &&
mkdir -p /build &&
cd /build && "${DIR}"/configure &&
make -j `nproc` distcheck AM_DEFAULT_VERBOSITY=1
' || exit 1

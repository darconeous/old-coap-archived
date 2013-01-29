#!/bin/sh

DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib ./smcp-plugtest-server > /dev/stderr &
SERVER_PID=$!

DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib ./smcp-plugtest-client > /dev/stderr
RESULT=$?

kill $SERVER_PID

exit $RESULT

#!/bin/sh

./smcp-plugtest-server > /dev/stderr &
SERVER_PID=$!

./smcp-plugtest-client > /dev/stderr
RESULT=$?

kill $SERVER_PID

exit $RESULT

#!/bin/sh

MallocScribble=1 MallocPreScribble=1 MallocGuardEdges=1 MallocCheckHeapStart=1 MallocCheckHeapEach=1 MALLOC_PERTURB_=1 MALLOC_CHECK_=1 DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib ./smcp-plugtest-server 39813 > /dev/stderr &
SERVER_PID=$!

trap "kill $SERVER_PID" EXIT INT TERM

MallocScribble=1 MallocPreScribble=1 MallocGuardEdges=1 MallocCheckHeapStart=1 MallocCheckHeapEach=1 MALLOC_PERTURB_=1 MALLOC_CHECK_=1 DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib ./smcp-plugtest-client coap://127.0.0.1:39813 10 > /dev/stderr
RESULT=$?

exit $RESULT

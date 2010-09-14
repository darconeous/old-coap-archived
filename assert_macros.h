/*
 *  assert_macros.h
 *  SMCP
 *
 *  Created by Robert Quattlebaum on 8/31/10.
 *  Copyright 2010 deepdarc. All rights reserved.
 *
 */

#ifndef __SMCP_ASSERT_MACROS__
#define __SMCP_ASSERT_MACROS__

#if HAS_ASSERTMACROS_H
 #include <AssertMacros.h>
#else
#if DEBUG
 #define check_string(c, s)   do { } while(0)
 #define require_action_string(c, l, a, s) \
    do { if(!(c)) { \
			 a; goto l; \
		 } \
	} while(0)
#else
 #define check_string(c, s) \
    do { if(!(c)) fprintf(stderr, \
				__FILE__ ":%d: Check Failed (%s)\n", \
				__LINE__, \
				s); } while(0)
 #define require_action_string(c, l, a, s) \
    do { if(!(c)) { \
			 fprintf(stderr, \
				__FILE__ ":%d: Assert Failed (%s)\n", \
				__LINE__, \
				s); a; goto l; \
		 } \
	} while(0)
#endif

 #define check(c)   check_string(c, "")
 #define require_quiet(c, l)   do { if(!(c)) goto l; } while(0)
 #define require(c, l)   require_action_string(c, l, {}, "")

 #define require_noerr(c, l)   require((c) == 0, l)
 #define require_action(c, l, a)   require_action_string(c, l, a, "")
 #define require_string(c, l, s) \
    require_action_string(c, l, \
	    do {} while(0), s)
#endif

#endif

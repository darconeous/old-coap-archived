/*	@file assert-macros.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**
**	Originally published 2010-8-31.
**
**	This file was written by Robert Quattlebaum <darco@deepdarc.com>.
**
**	This work is provided as-is. Unless otherwise provided in writing,
**	Robert Quattlebaum makes no representations or warranties of any
**	kind concerning this work, express, implied, statutory or otherwise,
**	including without limitation warranties of title, merchantability,
**	fitness for a particular purpose, non infringement, or the absence
**	of latent or other defects, accuracy, or the present or absence of
**	errors, whether or not discoverable, all to the greatest extent
**	permissible under applicable law.
**
**	To the extent possible under law, Robert Quattlebaum has waived all
**	copyright and related or neighboring rights to this work. This work
**	is published from the United States.
**
**	I, Robert Quattlebaum, dedicate any and all copyright interest in
**	this work to the public domain. I make this dedication for the
**	benefit of the public at large and to the detriment of my heirs and
**	successors. I intend this dedication to be an overt act of
**	relinquishment in perpetuity of all present and future rights to
**	this code under copyright law. In jurisdictions where this is not
**	possible, I hereby release this code under the Creative Commons
**	Zero (CC0) license.
**
**	 * <http://creativecommons.org/publicdomain/zero/1.0/>
**
**	See <http://www.deepdarc.com/> for other cool stuff.
**
**	-------------------------------------------------------------------
**
**	See <http://www.mactech.com/articles/develop/issue_11/Parent_final.html>
**	for an explanation about how to use these macros and justification
**	for using this pattern in general.
*/

#ifndef __DARC_ASSERT_MACROS__
#define __DARC_ASSERT_MACROS__

#if CONTIKI
#define assert_error_stream     stdout
#else
#define assert_error_stream     stderr
#endif

#if HAS_ASSERTMACROS_H
 #include <AssertMacros.h>
#else
#include <stdio.h>
#include <assert.h>
#if !DEBUG && !VERBOSE_DEBUG
 #define assert_printf(fmt, ...) do { } while(0)
 #define check_string(c, s)   do { } while(0)
 #define require_action_string(c, l, a, s) \
    do { if(!(c)) { \
			 a; goto l; \
		 } \
	} while(0)
#else
 #if __AVR__
  #define assert_printf(fmt, ...) \
    fprintf_P(assert_error_stream, \
				PSTR(__FILE__ ":%d: "fmt"\n"), \
				__LINE__, \
				__VA_ARGS__)
 #else
  #define assert_printf(fmt, ...) \
    fprintf(assert_error_stream, \
				__FILE__ ":%d: "fmt"\n", \
				__LINE__, \
				__VA_ARGS__)
 #endif
 #define check_string(c, s) \
   do { if(!(c)) assert_printf("Check Failed (%s)", \
			s); } while(0)
 #define require_action_string(c, l, a, s) \
	do { if(!(c)) { \
		assert_printf("Requirement Failed (%s)", \
			s); a; goto l; \
		 } \
	} while(0)
#endif

 #define check(c)   check_string(c, # c)
 #define require_quiet(c, l)   do { if(!(c)) goto l; } while(0)
 #define require(c, l)   require_action_string(c, l, {}, # c)

 #define require_noerr(c, l)   require((c) == 0, l)
 #define require_action(c, l, a)   require_action_string(c, l, a, # c)
 #define require_string(c, l, s) \
    require_action_string(c, l, \
	    do {} while(0), s)
#endif

#endif
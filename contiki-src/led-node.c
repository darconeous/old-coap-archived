/*	@file led-node.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
**
**	Copyright (C) 2011,2012 Robert Quattlebaum
**
**	Permission is hereby granted, free of charge, to any person
**	obtaining a copy of this software and associated
**	documentation files (the "Software"), to deal in the
**	Software without restriction, including without limitation
**	the rights to use, copy, modify, merge, publish, distribute,
**	sublicense, and/or sell copies of the Software, and to
**	permit persons to whom the Software is furnished to do so,
**	subject to the following conditions:
**
**	The above copyright notice and this permission notice shall
**	be included in all copies or substantial portions of the
**	Software.
**
**	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
**	KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
**	WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
**	PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
**	OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
**	OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
**	OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
**	SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "led-node.h"
#include "assert-macros.h"
#include "dev/leds.h"
#include <smcp/smcp-variable_node.h>

smcp_status_t
led_var_func(
	smcp_variable_node_t node,
	uint8_t action,
	uint8_t i,
	char* value
) {
	smcp_status_t ret = 0;
	uint8_t mask = (1<<i);

	if(!(mask&LEDS_ALL)) {
		ret = SMCP_STATUS_NOT_FOUND;
	} else if(action==SMCP_VAR_GET_KEY) {
		value[0] = i+'0';
		value[1] = 0;
	} else if(action==SMCP_VAR_GET_VALUE) {
		value[0] = !!(leds_get()&mask)+'0';
		value[1] = 0;
	} else if(action==SMCP_VAR_SET_VALUE) {
		if(	value[0]=='1'
			|| value[0]=='t'
			|| value[0]=='y'
		) {
			leds_on(mask);
		} else if( value[0]=='0'
			|| value[0]=='f'
			|| value[0]=='n'
		) {
			leds_off(mask);
		} else if( value[0]=='!'
			&& value[1]=='v'
			&& value[2]==0
		) {
			leds_toggle(mask);
		} else {
			ret = SMCP_STATUS_FAILURE;
		}
	} else {
		ret = SMCP_STATUS_NOT_IMPLEMENTED;
	}

	return ret;
}

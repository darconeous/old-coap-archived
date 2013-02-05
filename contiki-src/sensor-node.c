/*	@file sensor-node.c
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

#include "sensor-node.h"
#include "assert-macros.h"
#include "lib/sensors.h"
#include <smcp/smcp-variable_node.h>

const extern struct sensors_sensor *sensors[];

smcp_status_t
sensor_var_func(
	smcp_variable_node_t node,
	uint8_t action,
	uint8_t i,
	char* value
) {
	smcp_status_t ret = 0;
	const struct sensors_sensor *sensor;
	static uint8_t sensor_count;

	if(!sensor_count)
		for(sensor_count = 0; sensors[sensor_count] != NULL; ++sensor_count) {}

	if(i>=sensor_count) {
		ret = SMCP_STATUS_NOT_FOUND;
		goto bail;
	}

	sensor = sensors[i];

	if(action==SMCP_VAR_GET_KEY) {
		strcpy(value,sensor->type);
	} else if(action==SMCP_VAR_GET_VALUE) {
		int32_to_dec_cstr(value,sensor->value(0));
	} else if(action==SMCP_VAR_SET_VALUE) {
		ret = SMCP_STATUS_NOT_IMPLEMENTED;
	} else {
		ret = SMCP_STATUS_NOT_IMPLEMENTED;
	}

bail:
	return ret;
}


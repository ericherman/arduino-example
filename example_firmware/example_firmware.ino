// modified from: http://www.windmeadow.com/node/38

// Arduino firmware for a Serial "Rotate 13" service

/*
 Copyright (C) 2012,2013 Eric Herman <eric@freesa.org>
 Copyright (C) 2013 Kendrick Shaw <kms15@case.edu>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
*/

#include <Arduino.h>
#include "eh-arduino-serialobj.h"
#ifndef SKETCH_SKIP_EHBI
#include "ehbigint-arduino.h"
#include "bi-calc.h"
#endif
#include "eh-printf.h"
#include "rot13.h"
#include "print-data-type-sizes.h"

unsigned long loop_counter;
unsigned long blink_state;

void setup(void)
{
	// set the LED on
	pinMode(13, OUTPUT);
	digitalWrite(13, HIGH);

	SERIAL_OBJ.begin(115200);

	loop_counter = 0;
	blink_state = 0;
}

void loop(void)
{
	loop_counter++;
	if ((loop_counter % 262144) == 0) {
		if (blink_state) {
			digitalWrite(13, HIGH);
		} else {
			digitalWrite(13, LOW);
		}
		loop_counter = 0;
		blink_state = !blink_state;
	}
	// loop until data available
	if (SERIAL_OBJ.available() == 0) {
		return;
	}
	// read an available byte:
	char incoming_byte = SERIAL_OBJ.read();

	// transform incoming byte
	char outgoing_byte = rotate_letter(incoming_byte);

	SERIAL_OBJ.print(outgoing_byte);

	if (incoming_byte == '^' || incoming_byte == '~') {
		print_data_type_sizes();
	}
#ifndef SKETCH_SKIP_EHBI
	if (incoming_byte == '*') {
		size_t len = 80;
		char buf[80];
		int verbose = 1;
		buf[0] = '\0';
		bi_calc("987654321", '*', "1000000000000", buf, len, verbose);
		SERIAL_OBJ.println(buf);
	}
#endif /* SKETCH_SKIP_EHBI */
}

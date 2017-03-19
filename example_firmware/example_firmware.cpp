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
#include <HardwareSerial.h>
#include "rot13.h"

#ifdef _VARIANT_ARDUINO_DUE_X_
#if ARDUINO_DUE_USB_PROGRAMMING == 1
#define SERIAL_OBJ Serial
#else // default to the NATIVE port
#define SERIAL_OBJ SerialUSB
#endif
#endif

#ifndef SERIAL_OBJ
#define SERIAL_OBJ Serial
#endif

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
}

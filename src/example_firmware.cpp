// modified from: http://www.windmeadow.com/node/38

// Arduino firmware for a Serial "Rotate 13" service

/*
 Copyright (C) 2012,2013 Eric Herman <eric@freesa.org>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
*/

#include <Arduino.h>
#include "rot13.h"

void setup(void)
{
	// set the LED on
	pinMode(13, OUTPUT);
	digitalWrite(13, HIGH);

	Serial.begin(115200);
}

void loop(void)
{
	// loop until data available
	if (Serial.available() == 0) {
		return;
	}
	// read an available byte:
	char incoming_byte = Serial.read();

	// transform incoming byte
	incoming_byte = rotate_letter(incoming_byte);

	Serial.print(incoming_byte);
}

int main(void)
{
	init();
	setup();
	while (1) {
		loop();
	}
}

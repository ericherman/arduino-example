// modified from: http://www.windmeadow.com/node/38

// See: http://arduino.cc/forum/index.php?topic=92364.0
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

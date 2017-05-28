/*
eh-sys-context-arduino.cpp: Arduino specific system calls
Copyright (C) 2016 Eric Herman

This work is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later
version.

This work is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License (COPYING) along with this library; if not, see:

        https://www.gnu.org/licenses/old-licenses/lgpl-2.1.txt

*/
#include <Arduino.h>
#include "ehbigint-arduino.h"

#ifndef EHBI_SKIP_IS_PROBABLY_PRIME

static const uint8_t Bogus_random[] = {
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
        71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
        149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
        227, 229, 233, 239, 241, 251,
	0
};
static size_t Bogus_randon_len = 54;

extern "C" {

int totally_bogus_random_bytes(unsigned char *buf, size_t len)
{
	size_t i, pos;
	unsigned long jump;

	jump = micros();

	for (i = 0; i < len; ++i) {
		pos = (i + jump);
		if (pos > Bogus_randon_len) {
			pos -= Bogus_randon_len;
		}
		*(buf + i) = Bogus_random[pos];
		if ((i % 31) == 0) {
			jump = micros();
		}
	}
	return 0;
}

} /* extern "C" */

#endif /* EHBI_SKIP_IS_PROBABLY_PRIME */

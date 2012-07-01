/*
 * Copyright (C) 2012 Eric Herman <eric@freesa.org>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "rot13.h"

char rotate_letter(char c)
{
	if (c >= 'a' && c <= 'm') {
		return c += 13;
	} else if (c >= 'n' && c <= 'z') {
		return c -= 13;
	} else if (c >= 'A' && c <= 'M') {
		return c += 13;
	} else if (c >= 'N' && c <= 'Z') {
		return c -= 13;
	}

	return c;
}

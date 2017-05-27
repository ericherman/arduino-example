
/*
 * Copyright (C) 2012,2017 Eric Herman <eric@freesa.org>
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

#ifndef SERIALOBJ_H
#define SERIALOBJ_H

#include <Arduino.h>
#include <HardwareSerial.h>

#if defined( _VARIANT_ARDUINO_DUE_X_ ) || defined( ARDUINO_SAM_DUE )
#if ARDUINO_DUE_USB_PROGRAMMING == 1
#define SERIAL_OBJ Serial
#else // default to the NATIVE port
#define SERIAL_OBJ SerialUSB
#endif
#endif

#ifndef SERIAL_OBJ
#define SERIAL_OBJ Serial
#endif

#endif /* SERIALOBJ_H */

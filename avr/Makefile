# Makefile for building and flashing an ArduinoMega

# Copyright (C) 2012,2013 Kendrick Shaw <kms15@case.edu>
# Copyright (C) 2012,2013 Eric Herman <eric@freesa.org>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# the name of the main file and sources to be used
APPNAME=example_firmware
SRC_DIR=../$(APPNAME)
SOURCES=$(APPNAME).o \
 rot13.o \
 print-data-type-sizes.o \
 eh-printf.o \
 eh-sys-context-arduino.o

#ARDUINO_ROOT=/usr/share/arduino
ARDUINO_ROOT=/home/eric/arduino-1.6.12
ARDUINO_ARCH_ROOT=$(ARDUINO_ROOT)/hardware/arduino/avr
ARDUINO_SOURCES_DIR=$(ARDUINO_ARCH_ROOT)/cores/arduino
ARDUINO_VARIANT_DIR=$(ARDUINO_ARCH_ROOT)/variants/mega

ARDUINO_LIBRARY_ROOT=$(ARDUINO_ARCH_ROOT)/libraries

ARDUINO_SPI_SRC_DIR=$(ARDUINO_LIBRARY_ROOT)/SPI/src
ARDUINO_HID_SRC_DIR=$(ARDUINO_LIBRARY_ROOT)/HID/src
ARDUINO_EEPROM_SRC_DIR=$(ARDUINO_LIBRARY_ROOT)/EEPROM/src
#ARDUINO_SOFTWARESERIAL_SRC_DIR=$(ARDUINO_LIBRARY_ROOT)/SoftwareSerial/src
ARDUINO_WIRE_SRC_DIR=$(ARDUINO_LIBRARY_ROOT)/Wire/src
ARDUINO_WIRE_UTIL_SRC_DIR=$(ARDUINO_LIBRARY_ROOT)/Wire/src/utility

# if you have used the arduino IDE you can use this:
#AVRDUDE_CONF=-C$(ARDUINO_ROOT)/hardware/tools/avr/etc/avrdude.conf

# port the arduino is connected to
# and CPU type as defined by gcc and AVR-DUDE
ifeq ($(wildcard /dev/ttyACM0),)
PORT=/dev/ttyUSB0
GCC_MMCU=atmega1280
AVRDUDE_MCU=m1280
AVRDUDE_STK=stk500v1
AVRDUDE_BAUD=57600
else
PORT=/dev/ttyACM0
GCC_MMCU=atmega2560
AVRDUDE_MCU=atmega2560
AVRDUDE_STK=stk500v2
AVRDUDE_BAUD=115200
endif

# for "Uno" use:
#PORT=/dev/ttyACM0
#GCC_MMCU=atmega328p
#AVRDUDE_MCU=atmega328p
#AVRDUDE_STK=arduino
#AVRDUDE_BAUD=115200
#ARDUINO_VARIANT_DIR=$(ARDUINO_ARCH_ROOT)/variants/standard


# CPU Clock speed (cycles per second)
CLOCKSPEED=16000000
#CLOCKSPEED=8000000

CC=avr-gcc
CXX=avr-g++

SHAREDFLAGS= -gstabs -Os \
		-funsigned-char -funsigned-bitfields -fpack-struct \
		-fshort-enums \
		-I$(ARDUINO_SOURCES_DIR) \
		-I$(ARDUINO_VARIANT_DIR) \
		-mmcu=$(GCC_MMCU) -DF_CPU=$(CLOCKSPEED)

CFLAGS=-std=gnu11 -Wstrict-prototypes $(SHAREDFLAGS)
CXXFLAGS=$(SHAREDFLAGS)
NOISYFLAGS=-Wall -Wextra -pedantic -Werror
#NOISYFLAGS=
CXX_WORKAROUND_FLAGS=-Wno-variadic-macros -Wno-ignored-qualifiers

ARDUINO_SOURCES := $(shell find $(ARDUINO_ARCH_ROOT) -name "*.c" -o -name "*.cpp" | grep -v bootloaders | grep -v firmwares | grep -v SoftwareSerial | sed -e's@.*/@@' -e's@\.c.*@.o@')

%.o : $(SRC_DIR)/%.ino
	$(CXX) $(NOISYFLAGS) $(CXXFLAGS) $(CXX_WORKAROUND_FLAGS) \
		-c -x c++ $< -o $@

%.o : $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(NOISYFLAGS) -c $< -o $@

%.o : $(SRC_DIR)/%.cpp
	$(CXX) $(NOISYFLAGS) $(CXXFLAGS) $(CXX_WORKAROUND_FLAGS) -c $< -o $@


%.o : $(ARDUINO_SOURCES_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o : $(ARDUINO_SOURCES_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@


%.o : $(ARDUINO_SPI_SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o : $(ARDUINO_SPI_SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@


%.o : $(ARDUINO_HID_SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o : $(ARDUINO_HID_SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@


%.o : $(ARDUINO_EEPROM_SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o : $(ARDUINO_EEPROM_SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@


%.o : $(ARDUINO_SOFTWARESERIAL_SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o : $(ARDUINO_SOFTWARESERIAL_SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@


%.o : $(ARDUINO_WIRE_SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o : $(ARDUINO_WIRE_SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@


%.o : $(ARDUINO_WIRE_UTIL_SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o : $(ARDUINO_WIRE_UTIL_SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@




all: $(APPNAME).hex
	echo YAY

clean:
	rm -f *.o *.a *.hex *.bin

upload: $(APPNAME).hex
	stty -F $(PORT) hupcl # e.g. reset the arduino
	avrdude $(AVRDUDE_CONF) -v -c $(AVRDUDE_STK) -p $(AVRDUDE_MCU) \
		-b $(AVRDUDE_BAUD) -P $(PORT) -U flash:w:$(APPNAME).hex:i

%.hex : %.bin
	avr-objcopy -O ihex -R .eeprom $< $@

libarduinocore.a: $(ARDUINO_SOURCES)
	ar rc $@ $^

echo_vars:
	echo "ARDUINO_ROOT=$(ARDUINO_ROOT)"
	echo "ARDUINO_ARCH_ROOT=$(ARDUINO_ARCH_ROOT)"
	echo "ARDUINO_SOURCES_DIR=$(ARDUINO_SOURCES_DIR)"
	echo "ARDUINO_VARIANT_DIR=$(ARDUINO_VARIANT_DIR)"
	echo "ARDUINO_LIBRARY_ROOT=$(ARDUINO_LIBRARY_ROOT)"
	echo "ARDUINO_SPI_SRC_DIR=$(ARDUINO_SPI_SRC_DIR)"
	echo "ARDUINO_HID_SRC_DIR=$(ARDUINO_HID_SRC_DIR)"
	echo "ARDUINO_EEPROM_SRC_DIR=$(ARDUINO_EEPROM_SRC_DIR)"
	echo "ARDUINO_SOFTWARESERIAL_SRC_DIR=$(ARDUINO_SOFTWARESERIAL_SRC_DIR)"
	echo "ARDUINO_WIRE_SRC_DIR=$(ARDUINO_WIRE_SRC_DIR)"
	echo "ARDUINO_SOURCES=$(ARDUINO_SOURCES)"

$(APPNAME).bin : $(SOURCES) libarduinocore.a
	$(CXX) $(CXXFLAGS) $(NOISYFLAGS) $^ -o $@ -L. -larduinocore


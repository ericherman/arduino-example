# Makefile for building and flashing an Arduino Due

# Copyright (C) 2013 Kendrick Shaw <kms15@case.edu>
# Copyright (C) 2013 Eric Herman <eric@freesa.org>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# the name of the main file and sources to be used
APPNAME=example_firmware
SRC_DIR=../src
APP_OBJS=$(APPNAME).o rot13.o

# port the arduino is connected to
PORT=ttyACM0

ARDUINO_ROOT=$(HOME)/src/Arduino
ARDUINO_SAM_DIR=$(ARDUINO_ROOT)/hardware/arduino/sam
ARDUINO_SOURCES_DIR=$(ARDUINO_SAM_DIR)/cores/arduino
ARDUINO_VARIANT_DIR=$(ARDUINO_SAM_DIR)/variants/arduino_due_x

# see: http://sourceforge.net/projects/b-o-s-s-a/
BOSSAC=$(ARDUINO_ROOT)/build/linux/work/hardware/tools/bossac

# see:  https://github.com/esden/summon-arm-toolchain
#TOOLCHAIN_BIN_DIR=$(HOME)/sat/bin

TOOLCHAIN_BIN_DIR=$(ARDUINO_ROOT)/build/linux/work/hardware/tools/g++_arm_none_eabi/bin

CC=$(TOOLCHAIN_BIN_DIR)/arm-none-eabi-gcc
CXX=$(TOOLCHAIN_BIN_DIR)/arm-none-eabi-g++
OBJCOPY=$(TOOLCHAIN_BIN_DIR)/arm-none-eabi-objcopy
AR=$(TOOLCHAIN_BIN_DIR)/arm-none-eabi-ar

SHAREDFLAGS= -gstabs -Os \
		-ffunction-sections \
		-fdata-sections \
		-nostdlib \
		--param max-inline-insns-single=500 \
		-Dprintf=iprintf \
		-mcpu=cortex-m3 \
		-DF_CPU=84000000L \
		-DARDUINO=155 \
		-DARDUINO_SAM_DUE \
		-DARDUINO_ARCH_SAM \
		-D__SAM3X8E__ \
		-mthumb \
		-DUSB_VID=0x2341 \
		-DUSB_PID=0x003e \
		-DUSBCON \
		-I$(ARDUINO_SOURCES_DIR) \
		-I$(ARDUINO_VARIANT_DIR) \
		-I$(ARDUINO_SAM_DIR)/system/libsam \
		-I$(ARDUINO_SAM_DIR)/system/CMSIS/CMSIS/Include \
		-I$(ARDUINO_SAM_DIR)/system/CMSIS/Device/ATMEL

BROKENFLAGS= -DUSB_MANUFACTURER="Unknown" -DUSB_PRODUCT="Arduino Due"


CFLAGS=-std=gnu99 -Wstrict-prototypes $(SHAREDFLAGS)
CXXFLAGS=$(SHAREDFLAGS) -fno-rtti -fno-exceptions

#NOISYFLAGS=-Wall -Wextra -pedantic -Werror
NOISYFLAGS=-Wall -Wextra -Werror
#NOISYFLAGS=

ARDINIO_SAM_OBJS=variant.o
ARDUINO_CORE_OBJS=CDC.o \
			cortex_handlers.o \
			cxxabi-compat.o \
			HID.o \
			hooks.o \
			iar_calls_sam3.o \
			IPAddress.o \
			itoa.o \
			main.o \
			Print.o \
			Reset.o \
			RingBuffer.o \
			Stream.o \
			syscalls_sam3.o \
			UARTClass.o \
			USARTClass.o \
			USBCore.o \
			WInterrupts.o \
			wiring_analog.o \
			wiring.o \
			wiring_digital.o \
			wiring_pulse.o \
			wiring_shift.o \
			WMath.o \
			WString.o

%.o : $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(NOISYFLAGS) -c $< -o $@

%.o : $(SRC_DIR)/%.cpp
	$(CXX) $(NOISYFLAGS) $(CXXFLAGS) -c $< -o $@

%.o : $(ARDUINO_SOURCES_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o : $(ARDUINO_SOURCES_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o : $(ARDUINO_SOURCES_DIR)/USB/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o : $(ARDUINO_VARIANT_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

all: $(APPNAME).bin
	echo YAY

clean:
	rm -f *.o *.a *.elf *.bin *.map

upload: $(APPNAME).bin
	./reset-device.rb $(PORT)
	$(BOSSAC) -i -d --port=$(PORT) -U false -e -w -v -b $(APPNAME).bin -R

%.bin : %.elf
	$(OBJCOPY) -O binary $< $@

libarduinocore.a: $(ARDUINO_CORE_OBJS)
	$(AR) rcs $@ $^

libarduinosam.a: $(ARDUINO_SAM_OBJS)
	$(AR) rcs $@ $^

$(APPNAME).elf : $(APP_OBJS) libarduinocore.a libarduinosam.a
	$(CXX) $(NOISYFLAGS) \
		-Os -Wl,--gc-sections -mcpu=cortex-m3 \
		-T$(ARDUINO_VARIANT_DIR)/linker_scripts/gcc/flash.ld \
		-Wl,-Map,$(APPNAME).map -o $@ \
		-L. -lm -lgcc -mthumb -Wl,--cref -Wl,--check-sections \
		-Wl,--gc-sections -Wl,--entry=Reset_Handler \
		-Wl,--unresolved-symbols=report-all -Wl,--warn-common \
		-Wl,--warn-section-align -Wl,--warn-unresolved-symbols \
		-Wl,--start-group $^ -Wl,--end-group

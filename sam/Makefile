# Makefile for building and flashing an Arduino Due

# Copyright (C) 2013 Kendrick Shaw <kms15@case.edu>
# Copyright (C) 2013 Eric Herman <eric@freesa.org>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# the name of the main file and sources to be used
APPNAME=example_firmware

SRC_DIR=../$(APPNAME)

C_PLATFORM_HEADERS=\
 -include $(SRC_DIR)/ehbigint-arduino.h

CPP_PLATFORM_HEADERS=\
 -include $(SRC_DIR)/eh-arduino-serialobj.h \
 $(C_PLATFORM_HEADERS)

# manual dependencies
APP_OBJS=$(APPNAME).o \
 rot13.o \
 print-data-type-sizes.o \
 bi-calc.o \
 eba.o \
 ehstr.o \
 ehbigint-eba.o \
 ehbigint-priv.o \
 ehbigint-str.o \
 ehbigint-util.o \
 ehbigint.o \
 ehbigint-util-arduino.o \
 eh-printf.o \
 eh-sys-context-arduino.o


# set this flag if you plan to communicate to the firmware running on
# the ardiuno DUE using the "programming" (not the "native") port
APP_FLAGS=-DARDUINO_DUE_USB_PROGRAMMING=0
#APP_FLAGS=-DARDUINO_DUE_USB_PROGRAMMING=1

# port the arduino is connected to while flashing new firmware
PORT=ttyACM0
# This is linux specific
RESET_PORT=stty -F /dev/$(PORT) 1200; sleep 1

# set the "BOSSAC_USB_NATIVE" to "false" if you plan to flash the firmware
# using the "programming" (not the "native") port
#BOSSAC_USB_NATIVE=false
BOSSAC_USB_NATIVE=true

ARDUINO_ROOT=$(HOME)/arduino-1.5.5
#ARDUINO_ROOT=$(HOME)/arduino-1.6.12
ARDUINO_SAM_DIR=$(ARDUINO_ROOT)/hardware/arduino/sam
ARDUINO_SPI_DIR=$(ARDUINO_SAM_DIR)/libraries/SPI
ARDUINO_SOURCES_DIR=$(ARDUINO_SAM_DIR)/cores/arduino
ARDUINO_VARIANT_DIR=$(ARDUINO_SAM_DIR)/variants/arduino_due_x
ARDIUNO_TOOLS_DIR=$(ARDUINO_ROOT)/hardware/tools

# see:  https://github.com/esden/summon-arm-toolchain
#TOOLCHAIN_BIN_DIR=$(HOME)/sat/bin

TOOLCHAIN_BIN_DIR=$(ARDIUNO_TOOLS_DIR)/g++_arm_none_eabi/bin

CC=$(TOOLCHAIN_BIN_DIR)/arm-none-eabi-gcc
CXX=$(TOOLCHAIN_BIN_DIR)/arm-none-eabi-g++
OBJCOPY=$(TOOLCHAIN_BIN_DIR)/arm-none-eabi-objcopy
AR=$(TOOLCHAIN_BIN_DIR)/arm-none-eabi-ar

# see: http://sourceforge.net/projects/b-o-s-s-a/
BOSSAC=$(ARDIUNO_TOOLS_DIR)/bossac

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
		-DUSB_MANUFACTURER='"Unknown"' \
		-DUSB_PRODUCT='"Arduino Due"' \
		-I$(SRC_DIR) \
		-I$(ARDUINO_SOURCES_DIR) \
		-I$(ARDUINO_VARIANT_DIR) \
		-I$(ARDUINO_SPI_DIR) \
		-I$(ARDUINO_SPI_DIR)/utility \
		-I$(ARDUINO_SAM_DIR)/system/libsam \
		-I$(ARDUINO_SAM_DIR)/system/CMSIS/CMSIS/Include \
		-I$(ARDUINO_SAM_DIR)/system/CMSIS/Device/ATMEL \
		-I$(ARDUINO_SOURCES_DIR)/avr

CFLAGS=-std=gnu99 -Wstrict-prototypes $(SHAREDFLAGS)
CXXFLAGS=$(SHAREDFLAGS) -fno-rtti -fno-exceptions

#NOISYFLAGS=-Wall -Wextra -pedantic -Werror
NOISYFLAGS=-Wall -Wextra -Werror
#NOISYFLAGS=

ARDUINO_MISC_OBJS=syscalls_sam3.o SPI.o

ARDUINO_CORE_OBJS=itoa.o \
		wiring.o \
		cortex_handlers.o \
		WInterrupts.o \
		hooks.o \
		wiring_shift.o \
		wiring_analog.o \
		iar_calls_sam3.o \
		wiring_digital.o \
		dtostrf.o \
		WMath.o \
		main.o \
		IPAddress.o \
		USARTClass.o \
		cxxabi-compat.o \
		USBCore.o \
		HID.o \
		CDC.o \
		Reset.o \
		RingBuffer.o \
		UARTClass.o \
		Stream.o \
		WString.o \
		Print.o \
		wiring_pulse.o \
		variant.o

%.o : $(SRC_DIR)/%.ino
	$(CXX) $(NOISYFLAGS) $(CXXFLAGS) $(APP_FLAGS) \
		 $(CPP_PLATFORM_HEADERS) -c -x c++ $< -o $@

%.o : $(SRC_DIR)/%.c
	$(CC) $(NOISYFLAGS) $(CFLAGS) $(APP_FLAGS) \
		 $(C_PLATFORM_HEADERS) -c $< -o $@

%.o : $(SRC_DIR)/%.cpp
	$(CXX) $(NOISYFLAGS) $(CXXFLAGS) $(APP_FLAGS) \
		 $(CPP_PLATFORM_HEADERS) -c $< -o $@

%.o : $(ARDUINO_SOURCES_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o : $(ARDUINO_SOURCES_DIR)/avr/%.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o : $(ARDUINO_SOURCES_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o : $(ARDUINO_SOURCES_DIR)/USB/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o : $(ARDUINO_SPI_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o : $(ARDUINO_VARIANT_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

all: $(APPNAME).bin
	echo YAY

clean:
	rm -f *.o *.a *.elf *.bin *.map

upload: $(APPNAME).bin
	#./reset-device.rb $(PORT)
	$(RESET_PORT)
	$(BOSSAC) -i -d --port=$(PORT) -U $(BOSSAC_USB_NATIVE) -e -w -v -b $(APPNAME).bin -R

%.bin : %.elf
	$(OBJCOPY) -O binary $< $@

libarduinocore.a: $(ARDUINO_CORE_OBJS)
	$(AR) rcs $@ $^

$(APPNAME).elf : $(APP_OBJS) $(ARDUINO_MISC_OBJS) libarduinocore.a
	$(CXX) $(NOISYFLAGS) \
		-Os -Wl,--gc-sections -mcpu=cortex-m3 \
		-T$(ARDUINO_VARIANT_DIR)/linker_scripts/gcc/flash.ld \
		-Wl,-Map,$(APPNAME).map -o $@ \
		-L. -lm -lgcc -mthumb -Wl,--cref -Wl,--check-sections \
		-Wl,--gc-sections -Wl,--entry=Reset_Handler \
		-Wl,--unresolved-symbols=report-all -Wl,--warn-common \
		-Wl,--warn-section-align -Wl,--warn-unresolved-symbols \
		-Wl,--start-group \
		$^ \
		$(ARDUINO_VARIANT_DIR)/libsam_sam3x8e_gcc_rel.a \
		-Wl,--end-group

#!/usr/bin/perl
# modified from: http://www.windmeadow.com/node/38

# send and recieve words to and from a Serial port

# Copyright (C) 2012,2013 Eric Herman <eric@freesa.org>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

use strict;
use warnings;

# Sample Perl script to transmit number
# to Arduino then listen for the Arduino
# to echo it back

use Device::SerialPort;

# Set up the serial port
# 19200, 81N on the USB ftdi driver
my $port;
if ( -e "/dev/ttyACM0" ) {
    $port = Device::SerialPort->new("/dev/ttyACM0");
}
else {
    $port = Device::SerialPort->new("/dev/ttyUSB0");
}
$port->databits(8);
$port->baudrate(115200);
$port->parity("none");
$port->stopbits(1);

my @words = qw(
  The
  quick
  brown
  fox
  jumped
  over
  the
  lazy
  dog!
);

my $count       = 0;
my $idx         = 0;
my $should_echo = 0;
while (1) {
    sleep(1);

    # Poll to see if any data is coming in
    my $received = $port->lookfor();
    chomp $received;

    # If we get data, then print it
    my $first_word = '';
    if ($received) {
        print "Received '$received'\n";
        ($first_word) = split( ' ', $received );
    }
    my $word;

    if ( $first_word and not grep( /$first_word/, @words ) ) {
        $word = $first_word;
    }
    else {
        $word = $words[$idx];
        if ( ++$idx >= ( scalar @words ) ) {
            $idx = 0;
        }
    }
    $count++;

    my $send      = "$word $count";
    my $count_out = $port->write( $send . "\n" );
    print "Sent     '$send'\n";
}

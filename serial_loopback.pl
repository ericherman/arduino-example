#!/usr/bin/perl
# modified from: http://www.windmeadow.com/node/38

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

#!/usr/bin/perl
use strict;
use warnings;

use Net::Frame::Simple;
use Net::Frame::IPv4 qw(:consts);
use Net::Frame::ICMPv4;
use Net::Frame::ICMPv4::Echo;

my $ip = Net::Frame::IPv4->new(protocol => NP_IPv4_PROTOCOL_ICMPv4);

my $icmp = Net::Frame::ICMPv4->new(
   icmpType => Net::Frame::ICMPv4::Echo->new(payload => 'test'),
);

my $oSimple = Net::Frame::Simple->new(
   layers => [ $ip, $icmp, ],
);
print $oSimple->print."\n";
print unpack('H*', $oSimple->raw)."\n";

my $oSimple2 = Net::Frame::Simple->new(
   raw        => $oSimple->raw,
   firstLayer => 'IPv4',
);
print $oSimple2->print."\n";
print unpack('H*', $oSimple2->raw)."\n";

#!/usr/bin/perl
use strict;
use warnings;

use Net::Frame::Simple;
use Net::Frame::IPv4 qw(:consts);
use Net::Frame::ICMPv4 qw(:consts);
use Net::Frame::ICMPv4::AddressMask;

my $ip = Net::Frame::IPv4->new(protocol => NP_IPv4_PROTOCOL_ICMPv4);

my $i  = Net::Frame::ICMPv4->new(type => NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST);
my $i2 = Net::Frame::ICMPv4::AddressMask->new(data => 'test');

my $s = Net::Frame::Simple->new(
   layers => [ $ip, $i, $i2, ],
);
print $s->print."\n";
print unpack('H*', $s->raw)."\n";

my $s2 = Net::Frame::Simple->new(
   raw        => $s->raw,
   firstLayer => 'IPv4',
);
print $s2->print."\n";
print unpack('H*', $s2->raw)."\n";

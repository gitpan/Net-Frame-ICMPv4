#!/usr/bin/perl
use strict;
use warnings;

use Net::Frame::Simple;
use Net::Frame::IPv4 qw(:consts);
use Net::Frame::ICMPv4;
use Net::Frame::ICMPv4::Echo;

my $ip = Net::Frame::IPv4->new(protocol => NP_IPv4_PROTOCOL_ICMPv4);

my $i  = Net::Frame::ICMPv4->new;
my $i2 = Net::Frame::ICMPv4::Echo->new(data => 'test');

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

#!/usr/bin/perl
use strict;
use warnings;

my $target = shift || die("Specify target\n");

use Net::Frame::Device;
use Net::Frame::Dump::Online;
use Net::Write::Layer3;

use Net::Frame::Simple;
use Net::Frame::IPv4 qw(:consts);
use Net::Frame::ICMPv4;
use Net::Frame::ICMPv4::Echo;

my $oDevice = Net::Frame::Device->new(target => $target);

my $ip = Net::Frame::IPv4->new(
   src      => $oDevice->ip,
   dst      => $target,
   protocol => NP_IPv4_PROTOCOL_ICMPv4,
);
my $ihdr = Net::Frame::ICMPv4->new;
my $icmp = Net::Frame::ICMPv4::Echo->new(payload => 'test');

my $oSimple = Net::Frame::Simple->new(
   layers => [ $ip, $ihdr, $icmp, ],
);

my $oDump = Net::Frame::Dump::Online->new(dev => $oDevice->dev);
$oDump->start;

my $oWrite = Net::Write::Layer3->new(dst => $target);
$oWrite->open;
$oSimple->send($oWrite);

until ($oDump->timeout) {
   if (my $r = $oSimple->recv($oDump)) {
      print "RECV:\n";
      print $r->print."\n";
      last;
   }
}

END {
   $oDump  && $oDump->isRunning && $oDump->stop;
   $oWrite && $oWrite->close;
}

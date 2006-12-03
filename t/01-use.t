use Test;
BEGIN { plan(tests => 1) }

use Net::Frame::ICMPv4 qw(:consts);
use Net::Frame::ICMPv4::AddressMask;
use Net::Frame::ICMPv4::Echo;
use Net::Frame::ICMPv4::Redirect;
use Net::Frame::ICMPv4::Timestamp;
use Net::Frame::ICMPv4::DestUnreach;
use Net::Frame::ICMPv4::Information;
use Net::Frame::ICMPv4::TimeExceed;

ok(1);

use Test;
BEGIN { plan(tests => 1) }

use Net::Frame::ICMPv4::Timestamp;

my $l = Net::Frame::ICMPv4::Timestamp->new;
$l->pack;
$l->unpack;

print $l->print."\n";

my $encap = $l->encapsulate;
$encap ? print "[$encap]\n" : print "[none]\n";

ok(1);

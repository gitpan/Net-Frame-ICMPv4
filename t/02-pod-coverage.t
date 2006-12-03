eval "use Test::Pod::Coverage tests => 8";
if ($@) {
   use Test;
   plan(tests => 1);
   skip("Test::Pod::Coverage required for testing");
}
else {
   my $trustparents = { coverage_class => 'Pod::Coverage::CountParents' };

   pod_coverage_ok("Net::Frame::ICMPv4",              $trustparents);
   pod_coverage_ok("Net::Frame::ICMPv4::AddressMask", $trustparents);
   pod_coverage_ok("Net::Frame::ICMPv4::Echo",        $trustparents);
   pod_coverage_ok("Net::Frame::ICMPv4::Redirect",    $trustparents);
   pod_coverage_ok("Net::Frame::ICMPv4::Timestamp",   $trustparents);
   pod_coverage_ok("Net::Frame::ICMPv4::DestUnreach", $trustparents);
   pod_coverage_ok("Net::Frame::ICMPv4::Information", $trustparents);
   pod_coverage_ok("Net::Frame::ICMPv4::TimeExceed",  $trustparents);
}

#
# $Id: Makefile.PL,v 1.4 2006/12/09 19:10:05 gomor Exp $
#
use ExtUtils::MakeMaker;

require v5.6.1;

WriteMakefile(
   NAME          => 'Net::Frame::ICMPv4',
   VERSION_FROM  => 'lib/Net/Frame/ICMPv4.pm',
   LICENSE       => 'Artistic',
   ABSTRACT_FROM => 'lib/Net/Frame/ICMPv4.pm',
   AUTHOR        => 'GomoR <perl@gomor.org>',
   PREREQ_PM     => {
      Net::Frame => 0,
   },
);

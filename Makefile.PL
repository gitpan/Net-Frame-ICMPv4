#
# $Id: Makefile.PL,v 1.3 2006/12/03 16:54:18 gomor Exp $
#
use ExtUtils::MakeMaker;

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

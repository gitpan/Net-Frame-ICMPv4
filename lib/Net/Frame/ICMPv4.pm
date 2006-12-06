#
# $Id: ICMPv4.pm,v 1.7 2006/12/06 21:24:23 gomor Exp $
#
package Net::Frame::ICMPv4;
use strict;
use warnings;

our $VERSION = '1.00_03';

use Net::Frame::Layer qw(:consts);
require Exporter;
our @ISA = qw(Net::Frame::Layer Exporter);

our %EXPORT_TAGS = (
   consts => [qw(
      NP_ICMPv4_HDR_LEN
      NP_ICMPv4_CODE_ZERO
      NP_ICMPv4_TYPE_DESTUNREACH
      NP_ICMPv4_CODE_NETWORK
      NP_ICMPv4_CODE_HOST
      NP_ICMPv4_CODE_PROTOCOL
      NP_ICMPv4_CODE_PORT
      NP_ICMPv4_CODE_FRAGMENTATION_NEEDED
      NP_ICMPv4_CODE_SOURCE_ROUTE_FAILED
      NP_ICMPv4_TYPE_TIMEEXCEED
      NP_ICMPv4_CODE_TTL_IN_TRANSIT
      NP_ICMPv4_CODE_FRAGMENT_REASSEMBLY
      NP_ICMPv4_TYPE_PARAMETERPROBLEM
      NP_ICMPv4_CODE_POINTER
      NP_ICMPv4_TYPE_SOURCEQUENCH
      NP_ICMPv4_TYPE_REDIRECT
      NP_ICMPv4_CODE_FOR_NETWORK
      NP_ICMPv4_CODE_FOR_HOST
      NP_ICMPv4_CODE_FOR_TOS_AND_NETWORK
      NP_ICMPv4_CODE_FOR_TOS_AND_HOST
      NP_ICMPv4_TYPE_ECHO_REQUEST
      NP_ICMPv4_TYPE_ECHO_REPLY
      NP_ICMPv4_TYPE_TIMESTAMP_REQUEST
      NP_ICMPv4_TYPE_TIMESTAMP_REPLY
      NP_ICMPv4_TYPE_INFORMATION_REQUEST
      NP_ICMPv4_TYPE_INFORMATION_REPLY
      NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST
      NP_ICMPv4_TYPE_ADDRESS_MASK_REPLY
   )],
);
our @EXPORT_OK = (
   @{$EXPORT_TAGS{consts}},
);

use constant NP_ICMPv4_HDR_LEN                      => 8;
use constant NP_ICMPv4_CODE_ZERO                    => 0;
use constant NP_ICMPv4_TYPE_DESTUNREACH             => 3;
use constant NP_ICMPv4_CODE_NETWORK                 => 0;
use constant NP_ICMPv4_CODE_HOST                    => 1;
use constant NP_ICMPv4_CODE_PROTOCOL                => 2;
use constant NP_ICMPv4_CODE_PORT                    => 3;
use constant NP_ICMPv4_CODE_FRAGMENTATION_NEEDED    => 4;
use constant NP_ICMPv4_CODE_SOURCE_ROUTE_FAILED     => 5;
use constant NP_ICMPv4_TYPE_TIMEEXCEED              => 11;
use constant NP_ICMPv4_CODE_TTL_IN_TRANSIT          => 0;
use constant NP_ICMPv4_CODE_FRAGMENT_REASSEMBLY     => 1;
use constant NP_ICMPv4_TYPE_PARAMETERPROBLEM        => 12;
use constant NP_ICMPv4_CODE_POINTER                 => 0;
use constant NP_ICMPv4_TYPE_SOURCEQUENCH            => 4;
use constant NP_ICMPv4_TYPE_REDIRECT                => 5;
use constant NP_ICMPv4_CODE_FOR_NETWORK             => 0;
use constant NP_ICMPv4_CODE_FOR_HOST                => 1;
use constant NP_ICMPv4_CODE_FOR_TOS_AND_NETWORK     => 2;
use constant NP_ICMPv4_CODE_FOR_TOS_AND_HOST        => 3;
use constant NP_ICMPv4_TYPE_ECHO_REQUEST            => 8;
use constant NP_ICMPv4_TYPE_ECHO_REPLY              => 0;
use constant NP_ICMPv4_TYPE_TIMESTAMP_REQUEST       => 13;
use constant NP_ICMPv4_TYPE_TIMESTAMP_REPLY         => 14;
use constant NP_ICMPv4_TYPE_INFORMATION_REQUEST     => 15;
use constant NP_ICMPv4_TYPE_INFORMATION_REPLY       => 16;
use constant NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST    => 17; # RFC 950
use constant NP_ICMPv4_TYPE_ADDRESS_MASK_REPLY      => 18; # RFC 950

our @AS = qw(
   type
   code
   checksum
   icmpType
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

#no strict 'vars';

use Carp;
use Net::Frame::Utils qw(inetChecksum);
require Net::Frame::ICMPv4::AddressMask;
require Net::Frame::ICMPv4::DestUnreach;
require Net::Frame::ICMPv4::Echo;
require Net::Frame::ICMPv4::Information;
require Net::Frame::ICMPv4::Redirect;
require Net::Frame::ICMPv4::TimeExceed;
require Net::Frame::ICMPv4::Timestamp;

sub new {
   shift->SUPER::new(
      type     => NP_ICMPv4_TYPE_ECHO_REQUEST,
      code     => NP_ICMPv4_CODE_ZERO,
      checksum => 0,
      @_,
   );
}

sub match {
   my $self = shift;
   my ($with) = @_;
   if ($self->type eq NP_ICMPv4_TYPE_ECHO_REQUEST
   &&  $with->type eq NP_ICMPv4_TYPE_ECHO_REPLY) {
      return 1;
   }
   #elsif () {
   #}
   0;
}

# XXX: may be better, by keying on type also
sub getKey        { shift->layer }
sub getKeyReverse { shift->layer }

#sub recv {
#   my $self = shift;
#   my ($frame) = @_;
#
#   my $env = $frame->env;
#
#   for ($env->dump->frames) {
#      next unless $_->timestamp ge $frame->timestamp;
#
#      if ($frame->l3) {
#         if ($_->isIcmpv4 && $_->l3->src eq $frame->l3->dst) {
#            if ($self->[$__type] == NP_ICMPv4_TYPE_ECHO_REQUEST
#            &&  $_->l4->type     == NP_ICMPv4_TYPE_ECHO_REPLY) {
#               return $_;
#            }
#            elsif ($self->[$__type] == NP_ICMPv4_TYPE_TIMESTAMP_REQUEST
#               &&  $_->l4->type     == NP_ICMPv4_TYPE_TIMESTAMP_REPLY) {
#               return $_;
#            }
#            elsif ($self->[$__type] == NP_ICMPv4_TYPE_INFORMATION_REQUEST
#               &&  $_->l4->type     == NP_ICMPv4_TYPE_INFORMATION_REPLY) {
#               return $_;
#            }
#            elsif ($self->[$__type] == NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST
#               &&  $_->l4->type     == NP_ICMPv4_TYPE_ADDRESS_MASK_REPLY) {
#               return $_;
#            }
#         }
#      }
#      # DescL4 recv, warning, it may receive a packet targetted at another
#      # host, since no L3 headers is kept at D4 for packet matching
#      else {
#         if ($self->[$__type] == NP_ICMPv4_TYPE_ECHO_REQUEST
#         &&  $_->l4->type     == NP_ICMPv4_TYPE_ECHO_REPLY) {
#               return $_;
#         }
#         elsif ($self->[$__type] == NP_ICMPv4_TYPE_TIMESTAMP_REQUEST
#            &&  $_->l4->type     == NP_ICMPv4_TYPE_TIMESTAMP_REPLY) {
#            return $_;
#         }
#         elsif ($self->[$__type] == NP_ICMPv4_TYPE_INFORMATION_REQUEST
#            &&  $_->l4->type     == NP_ICMPv4_TYPE_INFORMATION_REPLY) {
#            return $_;
#         }
#         elsif ($self->[$__type] == NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST
#            &&  $_->l4->type     == NP_ICMPv4_TYPE_ADDRESS_MASK_REPLY) {
#            return $_;
#         }
#      }
#   }
#
#   undef;
#}

sub getLength {
   my $self = shift;
   my $len = 4;
   if ($self->icmpType) {
      $len += $self->icmpType->getLength;
   }
   $len;
}

sub pack {
   my $self = shift;

   my $raw = $self->SUPER::pack('CCn',
      $self->type, $self->code, $self->checksum,
   ) or return undef;

   if ($self->icmpType) {
      $raw .= $self->icmpType->pack
         or return undef;

      $self->payload($self->icmpType->payload);
      $self->icmpType->payload(undef);
   }

   $self->raw($raw);
}

sub unpack {
   my $self = shift;

   my ($type, $code, $checksum, $payload) =
      $self->SUPER::unpack('CCn a*', $self->raw)
         or return undef;

   $self->type($type);
   $self->code($code);
   $self->checksum($checksum);

   if ($payload) {
      if ($type eq NP_ICMPv4_TYPE_ECHO_REQUEST
      ||  $type eq NP_ICMPv4_TYPE_ECHO_REPLY) {
         $self->icmpType(Net::Frame::ICMPv4::Echo->new(raw => $payload));
      }
      elsif ($type eq NP_ICMPv4_TYPE_TIMESTAMP_REQUEST
         ||  $type eq NP_ICMPv4_TYPE_TIMESTAMP_REPLY) {
         $self->icmpType(Net::Frame::ICMPv4::Timestamp->new(raw => $payload));
      }
      elsif ($type eq NP_ICMPv4_TYPE_INFORMATION_REQUEST
         ||  $type eq NP_ICMPv4_TYPE_INFORMATION_REPLY) {
         $self->icmpType(Net::Frame::ICMPv4::Information->new(raw => $payload));
      }
      elsif ($type eq NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST
         ||  $type eq NP_ICMPv4_TYPE_ADDRESS_MASK_REPLY) {
         $self->icmpType(Net::Frame::ICMPv4::AddressMask->new(raw => $payload));
      }
      elsif ($type eq NP_ICMPv4_TYPE_DESTUNREACH) {
         $self->icmpType(Net::Frame::ICMPv4::DestUnreach->new(raw => $payload));
      }
      elsif ($type eq NP_ICMPv4_TYPE_REDIRECT) {
         $self->icmpType(Net::Frame::ICMPv4::Redirect->new(raw => $payload));
      }
      elsif ($type eq NP_ICMPv4_TYPE_TIMEEXCEED) {
         $self->icmpType(Net::Frame::ICMPv4::TimeExceed->new(raw => $payload));
      }
      $self->icmpType->unpack;
      if ($self->icmpType->payload) {
         $self->payload($self->icmpType->payload);
         $self->icmpType->payload(undef);
      }
   }

   $self;
}

sub computeChecksums {
   my $self = shift;

   my $packed = $self->SUPER::pack('CCna*',
      $self->type, $self->code, 0, $self->icmpType->pack,
   ) or return undef;

   $self->checksum(inetChecksum($packed));

   1;
}

sub encapsulate {
   my $self = shift;
   if ($self->payload) {
      my $type = $self->type;
      if ($type eq NP_ICMPv4_TYPE_DESTUNREACH
      ||  $type eq NP_ICMPv4_TYPE_REDIRECT
      ||  $type eq NP_ICMPv4_TYPE_TIMEEXCEED) {
         return 'IPv4';
      }
   }

   NP_LAYER_NONE;
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   my $buf = sprintf "$l: type:%d  code:%d  checksum:0x%04x",
      $self->type, $self->code, $self->checksum;

   if ($self->icmpType) {
      $buf .= "\n".$self->icmpType->print;
   }

   $buf;
}

1;

__END__

=head1 NAME

Net::Frame::ICMPv4 - Internet Control Message Protocol v4 layer object

=head1 SYNOPSIS

   use Net::Packet::Consts qw(:icmpv4);
   require Net::Packet::ICMPv4;

   # Build echo-request header
   my $echo = Net::Packet::ICMPv4->new(data => '0123456789');

   # Build information-request header
   my $info = Net::Packet::ICMPv4->new(
      type => NP_ICMPv4_TYPE_INFORMATION_REQUEST,
      data => '0123456789',
   );

   # Build address-mask request header
   my $mask = Net::Packet::ICMPv4->new(
      type => NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST,
      data => '0123456789',
   );

   # Build timestamp request header
   my $timestamp = Net::Packet::ICMPv4->new(
      type => NP_ICMPv4_TYPE_TIMESTAMP_REQUEST,
      data => '0123456789',
   );
   $timestamp->pack;

   print 'RAW: '.unpack('H*', $timestamp->raw)."\n";

   # Read a raw layer
   my $layer = Net::Packet::ICMPv4->new(raw => $raw);

   print $layer->print."\n";
   print 'PAYLOAD: '.unpack('H*', $layer->payload)."\n"
      if $layer->payload;

=head1 DESCRIPTION

This modules implements the encoding and decoding of the ICMPv4 layer.

RFC: ftp://ftp.rfc-editor.org/in-notes/rfc792.txt

See also B<Net::Packet::Layer> and B<Net::Packet::Layer4> for other attributes a
nd methods.

=head1 ATTRIBUTES

=over 4

=item B<type>

=item B<code>

Type and code fields. See B<CONSTANTS>.

=item B<checksum>

The checksum of ICMPv4 header.

=item B<identifier>

Identification number.

=item B<sequenceNumber>

Sequence number.

=item B<originateTimestamp>

=item B<receiveTimestamp>

=item B<transmitTimestamp>

Three timestamps used by the B<NP_ICMPv4_TYPE_TIMESTAMP_REQUEST> message.

=item B<addressMask>

Used by the B<NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST> message.

=item B<gateway>

Used by the B<NP_ICMPv4_TYPE_REDIRECT> message.

=item B<unused>

Zero value field used in various ICMP messages.

=item B<error>

A pointer to a B<Net::Packet::Frame> object, usually set when an ICMP error message has been returned.

=item B<data>

Additionnal data can be added to an ICMP message, traditionnaly used in B<NP_ICMPv4_TYPE_ECHO_REQUEST>.

=back

=head1 METHODS

=over 4

=item B<new>

=item B<computeLengths>

=item B<computeChecksums>

=item B<pack>

=item B<unpack>

=item B<getLength>

=item B<getKey>

=item B<getKeyReverse>

=item B<match>

=item B<encapsulate>

=item B<print>

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:icmpv4);

=over 4

=item B<NP_ICMPv4_CODE_ZERO>

ICMP code zero, used by various ICMP messages.

=item B<NP_ICMPv4_TYPE_DESTINATION_UNREACHABLE>

=item B<NP_ICMPv4_CODE_NETWORK>

=item B<NP_ICMPv4_CODE_HOST>

=item B<NP_ICMPv4_CODE_PROTOCOL>

=item B<NP_ICMPv4_CODE_PORT>

=item B<NP_ICMPv4_CODE_FRAGMENTATION_NEEDED>

=item B<NP_ICMPv4_CODE_SOURCE_ROUTE_FAILED>

Destination unreachable type, with possible code numbers.

=item B<NP_ICMPv4_TYPE_REDIRECT>

=item B<NP_ICMPv4_CODE_FOR_NETWORK>

=item B<NP_ICMPv4_CODE_FOR_HOST>

=item B<NP_ICMPv4_CODE_FOR_TOS_AND_NETWORK>

=item B<NP_ICMPv4_CODE_FOR_TOS_AND_HOST>

Redirect type message, with possible code numbers.

=item B<NP_ICMPv4_TYPE_TIME_EXCEEDED>

=item B<NP_ICMPv4_CODE_TTL_IN_TRANSIT>

=item B<NP_ICMPv4_CODE_FRAGMENT_REASSEMBLY>

Time exceeded message, with possible code numbers.

=item B<NP_ICMPv4_TYPE_ECHO_REQUEST>

=item B<NP_ICMPv4_TYPE_ECHO_REPLY>

=item B<NP_ICMPv4_TYPE_TIMESTAMP_REQUEST>

=item B<NP_ICMPv4_TYPE_TIMESTAMP_REPLY>

=item B<NP_ICMPv4_TYPE_INFORMATION_REQUEST>

=item B<NP_ICMPv4_TYPE_INFORMATION_REPLY>

=item B<NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST>

=item B<NP_ICMPv4_TYPE_ADDRESS_MASK_REPLY>

Other request/reply ICMP messages types.

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut

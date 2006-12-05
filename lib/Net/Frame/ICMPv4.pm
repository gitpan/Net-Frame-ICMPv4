#
# $Id: ICMPv4.pm,v 1.6 2006/12/05 19:38:56 gomor Exp $
#
package Net::Frame::ICMPv4;
use strict;
use warnings;

our $VERSION = '1.00_02';

use Net::Frame::Layer qw(:consts);
require Exporter;
our @ISA = qw(Net::Frame::Layer Exporter);

our %EXPORT_TAGS = (
   consts => [qw(
      NP_ICMPv4_HDR_LEN
      NP_ICMPv4_CODE_ZERO
      NP_ICMPv4_TYPE_DESTINATION_UNREACHABLE
      NP_ICMPv4_CODE_NETWORK
      NP_ICMPv4_CODE_HOST
      NP_ICMPv4_CODE_PROTOCOL
      NP_ICMPv4_CODE_PORT
      NP_ICMPv4_CODE_FRAGMENTATION_NEEDED
      NP_ICMPv4_CODE_SOURCE_ROUTE_FAILED
      NP_ICMPv4_TYPE_REDIRECT
      NP_ICMPv4_CODE_FOR_NETWORK
      NP_ICMPv4_CODE_FOR_HOST
      NP_ICMPv4_CODE_FOR_TOS_AND_NETWORK
      NP_ICMPv4_CODE_FOR_TOS_AND_HOST
      NP_ICMPv4_TYPE_TIME_EXCEEDED
      NP_ICMPv4_CODE_TTL_IN_TRANSIT
      NP_ICMPv4_CODE_FRAGMENT_REASSEMBLY
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
use constant NP_ICMPv4_TYPE_DESTINATION_UNREACHABLE => 3;
use constant NP_ICMPv4_CODE_NETWORK                 => 0;
use constant NP_ICMPv4_CODE_HOST                    => 1;
use constant NP_ICMPv4_CODE_PROTOCOL                => 2;
use constant NP_ICMPv4_CODE_PORT                    => 3;
use constant NP_ICMPv4_CODE_FRAGMENTATION_NEEDED    => 4;
use constant NP_ICMPv4_CODE_SOURCE_ROUTE_FAILED     => 5;
use constant NP_ICMPv4_TYPE_TIME_EXCEEDED           => 11;
use constant NP_ICMPv4_CODE_TTL_IN_TRANSIT          => 0;
use constant NP_ICMPv4_CODE_FRAGMENT_REASSEMBLY     => 1;
use constant NP_ICMPv4_TYPE_PARAMETER_PROBLEM       => 12;
use constant NP_ICMPv4_CODE_POINTER                 => 0;
use constant NP_ICMPv4_TYPE_SOURCE_QUENCH           => 4;
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
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

#no strict 'vars';

use Carp;
use Net::Frame::Utils qw(inetChecksum);

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

sub getLength { 4 }

sub pack {
   my $self = shift;

   $self->raw($self->SUPER::pack('CCn',
      $self->type, $self->code, $self->checksum,
   )) or return undef;

   $self->raw;
}

sub unpack {
   my $self = shift;

   my ($type, $code, $checksum, $payload) =
      $self->SUPER::unpack('CCn a*', $self->raw)
         or return undef;

   $self->type($type);
   $self->code($code);
   $self->checksum($checksum);
   $self->payload($payload);

   $self;
}

sub computeChecksums {
   my $self = shift;
   my ($h)  = @_;

   my $raw = $h->{icmpType}->pack;

   my $packed = $self->SUPER::pack('CCn', $self->type, $self->code, 0)
      or return undef;

   $self->checksum(inetChecksum($packed.$raw));

   1;
}

sub encapsulate {
   my $types = {
      NP_ICMPv4_TYPE_ECHO_REQUEST()            => 'ICMPv4::Echo',
      NP_ICMPv4_TYPE_ECHO_REPLY()              => 'ICMPv4::Echo',
      NP_ICMPv4_TYPE_TIMESTAMP_REQUEST()       => 'ICMPv4::Timestamp',
      NP_ICMPv4_TYPE_TIMESTAMP_REPLY()         => 'ICMPv4::Timestamp',
      NP_ICMPv4_TYPE_INFORMATION_REQUEST()     => 'ICMPv4::Information',
      NP_ICMPv4_TYPE_INFORMATION_REPLY()       => 'ICMPv4::Information',
      NP_ICMPv4_TYPE_ADDRESS_MASK_REQUEST()    => 'ICMPv4::AddressMask',
      NP_ICMPv4_TYPE_ADDRESS_MASK_REPLY()      => 'ICMPv4::AddressMask',
      NP_ICMPv4_TYPE_DESTINATION_UNREACHABLE() => 'ICMPv4::DestUnreach',
      NP_ICMPv4_TYPE_REDIRECT()                => 'ICMPv4::Redirect',
      NP_ICMPv4_TYPE_TIME_EXCEEDED()           => 'ICMPv4::TimeExceed',
   };

   $types->{shift->type} || NP_LAYER_UNKNOWN;
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   my $buf = sprintf "$l: type:%d  code:%d  checksum:0x%04x",
      $self->type, $self->code, $self->checksum;

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

Object constructor. You can pass attributes that will overwrite default ones. Default values:

type:               NP_ICMPv4_TYPE_ECHO_REQUEST

code:               NP_ICMPv4_CODE_ZERO

checksum:           0

identifier:         getRandom16bitsInt()

sequenceNumber:     getRandom16bitsInt()

originateTimestamp: time()

receiveTimestamp:   0

transmitTimestamp:  0

addressMask:        0

gateway:            "127.0.0.1"

unused:             0

data:               ""

=item B<recv>

Will search for a matching replies in B<framesSorted> or B<frames> from a B<Net::Packet::Dump> object.

=item B<getDataLength>

Returns the length in bytes of B<data> attribute.

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=item B<isTypeEchoRequest>

=item B<isTypeEchoReply>

=item B<isTypeTimestampRequest>

=item B<isTypeTimestampReply>

=item B<isTypeInformationRequest>

=item B<isTypeInformationReply>

=item B<isTypeAddressMaskRequest>

=item B<isTypeAddressMaskReply>

=item B<isTypeDestinationUnreachable>

Returns 1 if the B<type> attribute is of specified type.

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

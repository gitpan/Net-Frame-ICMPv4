#
# $Id: Redirect.pm,v 1.4 2006/12/05 21:11:44 gomor Exp $
#
package Net::Frame::ICMPv4::Redirect;
use strict;
use warnings;

use Net::Frame::Layer qw(:consts);
require Exporter;
our @ISA = qw(Net::Frame::Layer Exporter);

our %EXPORT_TAGS = (consts => []);
our @EXPORT_OK   = ( @{$EXPORT_TAGS{consts}} );

our @AS = qw(
   gateway
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

#no strict 'vars';

use Carp;
use Net::Frame::Utils qw(inetAton inetNtoa);

sub new {
   shift->SUPER::new(
      gateway => '127.0.0.1',
      payload => '',
      @_,
   );
}

sub getPayloadLength { shift->SUPER::getPayloadLength }

sub getLength { 4 + shift->getPayloadLength }

sub pack {
   my $self = shift;

   $self->raw($self->SUPER::pack('a4 a*',
      inetAton($self->gateway), $self->payload,
   )) or return undef;

   $self->raw;
}

sub unpack {
   my $self = shift;

   my ($gateway, $payload) = $self->SUPER::unpack('a4 a*', $self->raw)
      or return undef;

   $self->gateway(inetNtoa($gateway));
   $self->payload($payload);

   $self;
}

sub encapsulate { shift->payload ? 'IPv4' : NP_LAYER_NONE }

sub print {
   my $self = shift;

   my $l = $self->layer;
   sprintf "$l: gateway:%s", $self->gateway;
}

1;

__END__

=head1 NAME

Net::Frame::ICMPv4::Redirect - ICMPv4 Redirect type object

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

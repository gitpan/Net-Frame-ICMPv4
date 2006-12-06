#
# $Id: AddressMask.pm,v 1.5 2006/12/06 21:25:27 gomor Exp $
#
package Net::Frame::ICMPv4::AddressMask;
use strict;
use warnings;

use Net::Frame::Layer qw(:consts);
our @ISA = qw(Net::Frame::Layer);

our @AS = qw(
   identifier
   sequenceNumber
   addressMask
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

#no strict 'vars';

use Carp;
use Net::Frame::Utils qw(getRandom16bitsInt inetAton inetNtoa);

sub new {
   shift->SUPER::new(
      identifier     => getRandom16bitsInt(),
      sequenceNumber => getRandom16bitsInt(),
      addressMask    => '0.0.0.0',
      payload        => '',
      @_,
   );
}

sub getPayloadLength { shift->SUPER::getPayloadLength }

sub getLength { 8 + shift->getPayloadLength }

sub pack {
   my $self = shift;

   $self->raw($self->SUPER::pack('nna4 a*',
      $self->identifier, $self->sequenceNumber, inetAton($self->addressMask),
      $self->payload,
   )) or return undef;

   $self->raw;
}

sub unpack {
   my $self = shift;

   my ($identifier, $sequenceNumber, $addressMask, $payload) =
      $self->SUPER::unpack('nna4 a*', $self->raw)
         or return undef;

   $self->identifier($identifier);
   $self->sequenceNumber($sequenceNumber);
   $self->addressMask(inetNtoa($addressMask));
   $self->payload($payload);

   $self;
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   sprintf "$l: identifier:%d  sequenceNumber:%d  addressMask:%s",
      $self->identifier, $self->sequenceNumber, $self->addressMask;
}

1;

__END__

=head1 NAME

Net::Frame::ICMPv4::AddressMask - ICMPv4 AddressMask type object

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

=item B<pack>

=item B<unpack>

=item B<getLength>

=item B<getPayloadLength>

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

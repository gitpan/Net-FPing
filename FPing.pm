=head1 NAME

Net::FPing - quickly ping a large number of hosts

=head1 SYNOPSIS

 use Net::FPing;

=head1 DESCRIPTION

This module was written for a single purpose only: sendinf ICMP EHCO
REQUEST packets as quickly as possible to a large number of hosts
(thousands to millions).

It employs a sending thread and is fully event-driven (using AnyEvent), so
you have to run an event model supported by AnyEvent to use this module.

=head1 FUNCTIONS

=over 4

=cut

package Net::FPing;

use strict;
no warnings;

use AnyEvent;

BEGIN {
   our $VERSION = '0.02';
   our @ISA = qw(Exporter);

   require Exporter;
   #Exporter::export_ok_tags (keys %EXPORT_TAGS);

   require XSLoader;
   XSLoader::load (__PACKAGE__, $VERSION);
}

our ($THR_REQ_FD, $THR_RES_FD, $ICMP4_FD, $ICMP6_FD);

our $THR_REQ_FH; open $THR_REQ_FH, ">&=$THR_REQ_FD" or die "FATAL: cannot fdopen";
our $THR_RES_FH; open $THR_RES_FH, "<&=$THR_RES_FD" or die "FATAL: cannot fdopen";

our $THR_REQ_W;
our $THR_RES_W = AnyEvent->io (fh => $THR_RES_FH, poll => 'r', cb => sub {
   my $sv = _read_res
      or return;

   $sv->();
});

our $THR_REQ_BUF;

sub _send_req($) {
   $THR_REQ_BUF .= $_[0];

   $THR_REQ_W ||= AnyEvent->io (fh => $THR_REQ_FH, poll => 'w', cb => sub {
      my $len = syswrite $THR_REQ_FH, $THR_REQ_BUF;
      substr $THR_REQ_BUF, 0, $len, "";

      undef $THR_REQ_W unless length $THR_REQ_BUF;
   });
}

=item Net::FPing::ipv4_supported

Returns true if IPv4 is supported in this module and on this system.

=item Net::FPing::ipv6_supported

Returns true if IPv6 is supported in this module and on this system.

=item Net::FPing::icmp4_pktsize

Returns the number of bytes each IPv4 ping packet has.

=item Net::FPing::icmp6_pktsize

Returns the number of bytes each IPv4 ping packet has.

=item Net::FPing::icmp_ping [ranges...], $send_interval, $payload, \&callback

Ping the given IPv4 address ranges. Each range is an arrayref of the
form C<[lo, hi, interval]>, where C<lo> and C<hi> are octet strings with
either 4 octets (for IPv4 addresses) or 16 octets (for IPV6 addresses),
representing the lowest and highest address to ping (you can convert a
dotted-quad IPv4 address to this format by using C<inet_aton $address>. The
range C<interval> is the minimum time in seconds between pings to the
given range. If omitted, defaults to C<$send_interval>.

The C<$send_interval> is the minimum interval between sending any two
packets and is a way to make an overall rate limit. If omitted, pings will
be send as fast as possible.

The C<$payload> is a 32 bit unsigned integer given as the ICMP ECHO
REQUEST ident and sequence numbers (in unspecified order :).

The request will be queued and all requests will be served by a background
thread in order. When all ranges have been pinged, the C<callback> will be
called.

Algorithm: Each range has an associated "next time to send packet"
time. The algorithm loops as long as there are ranges with hosts to be
pinged and always serves the range with the most urgent packet send
time. It will at most send one packet every C<$send_interval> seconds.

This will ensure that pings to the same range are nicely interleaved with
other ranges - this can help reduce per-subnet bandwidth while maintaining
an overall high packet rate.

The algorithm to send each packet is O(log n) on the number of ranges, so
even a large number of ranges (many thousands) is managable.

No storage is allocated per address.

Performance: On my 2 GHz Opteron system with a pretty average nvidia
gigabit network card I can ping around 60k to 200k adresses per second,
depending on routing decisions.

Example: ping 10.0.0.1-10.0.0.15 with at most 100 packets/s, and
11.0.0.1-11.0.255.255 with at most 1000 packets/s. Do not, however, exceed
1000 packets/s overall:

   my $done = AnyEvent->condvar;

   Net::FPing::icmp_ping
      [v10.0.0.1, v10.0.0.15, .01],
      [v11.0.0.1, v11.0.255.255, .001],
      .001, 0x12345678,
      sub {
         warn "all ranges pinged\n";
         $done->broadcast;
      }
   ;

   $done->wait;

=cut

sub icmp_ping($$$&) {
   _send_req _req_icmp_ping @_;
}

our $ICMP4_FH;
our $ICMP4_W = (open $ICMP4_FH, "<&=$ICMP4_FD") && AnyEvent->io (fh => $ICMP4_FH, poll => 'r', cb => \&_recv_icmp4);
our $ICMP6_FH;
our $ICMP6_W = (open $ICMP6_FH, "<&=$ICMP6_FD") && AnyEvent->io (fh => $ICMP6_FH, poll => 'r', cb => \&_recv_icmp6);

=item Net::FPing::register_cb \&cb

Register a callback that is called for every received ping reply
(regardless of whether a ping is still in process or not and regardless of
whether the reply is actually a reply ot a ping sent earlier).

The code reference gets a single parameter - an arrayref with an
entry for each received packet (replies are beign batched for greater
efficiency). Each packet is represented by an arrayref with three members:
the source address (an octet string of either 4 (IPv4) or 16 (IPv6) octets
length), the payload as passed to C<icmp_ping> and the round trip time in
seconds.

Example: a single ping reply with payload of 1 from C<::1> gets passed
like this:

   [ [
     "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1",
     "0.000280141830444336",
     1
   ] ]

Example: ping replies for C<127.0.0.1> and C<127.0.0.2>, with a payload of
C<0x12345678>:

   [
      [
        "\177\0\0\1",
        "0.00015711784362793",
        305419896
      ],
      [
        "\177\0\0\2",
        "0.00090184211731",
        305419896
      ]
   ]

=item Net::FPing::unregister_cb \&cb

Unregister the callback again (make sure you pass the same codereference
as to C<register_cb>).

=cut

our @CB;

sub register_cb(&) {
   push @CB, $_[0];
}

sub unregister_cb($) {
   @CB = grep $_ != $_[0], @CB;
}

1;

=back

=head1 AUTHOR

 Marc Lehmann <schmorp@schmorp.de>
 http://home.schmorp.de/

=head1 AUTHOR

 This software is distributed under the GENERAL PUBLIC LICENSE,
 version 2 or any later.

=cut


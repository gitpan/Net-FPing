print "1..4\n";

use strict;
use Net::FPing;

use AnyEvent;

my $done = AnyEvent->condvar;

print "ok 1\n";

Net::FPing::icmp_ping
   [[v127.0.0.1, v127.0.0.255], [v127.0.1.1, v127.0.1.5, 0.05]], 0, 0,
   sub { print "ok 3\n"; $done->broadcast };

print "ok 2\n";

$done->wait;

print "ok 4\n";

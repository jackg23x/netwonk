#!/usr/bin/perl
#jackg@uic.edu 
## prints IP and hostname for all in the given zone ##

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/util//;
#print "=> $installpath <=\n";
#use lib "$installpath/lib";

## HELP OUTPUT:
if ($ARGV[0] eq "")  {
   print "syntax:  DNSzone.pl <arg>\n";
   print "   where arg = gw, rtr, asa, fw, switch, etc.\n";
   exit;
}
my $z = $ARGV[0];

use Net::DNS;
require "$installpath/lib/servers.pl";
my $dns1 = dns1();
my $dns2 = dns2();
my $dns3 = dns3();
my $dnssuffix = dnssuffix();
my $res  = Net::DNS::Resolver->new;
$res->nameservers($dns1,$dns2,$dns3);
$res->tcp_timeout(10);
my @zone = $res->axfr("$z.$dnssuffix");

my $count;
if (@zone)  {
   foreach my $rr (@zone) {
     unless ($rr->type eq "A")  { next; }
     print $rr->address, "        ", $rr->name, "\n";
     $count++;
     ## print $rr->name, "        ", $rr->address, "\n";
   }
}
else  { print 'Zone transfer failed: ', $res->errorstring, "\n"; }

print "===== $count entries in $z.$dnssuffix\n";

exit;


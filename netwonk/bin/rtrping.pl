#!/usr/bin/perl
#jackg@uic.edu
#
# rtrping.pl - Child process of rtrseeker.pl - ping ONE rtr, insert data to rtr.ping
# puts info into rtr.ping db table on world
#

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use lib "$installpath/lib";
use SshSwcon;
use Net::Ping;
use IO::File;

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

## my $of  = "../forensic/rtr/rtrping.out";
## my $ofh = IO::File->new(">>$of");
my ($date,$time)=SshSwcon::date_time();
my $tstamp = "$date $time";

my ($rtrname,$rip);
my $args;
@$args = @ARGV;
my $rip   = $args->[0];
my $rname = $args->[1];
($rname,undef) = split /\./, $rname;

my $p = Net::Ping->new() or  print "pingfail: $rip\n";
my $ping_ret = $p->ping($rip);
if ($ping_ret eq "")  {  $ping_ret = 0; }
$p->close;
my $query = "INSERT INTO rtr.ping (rname,rip,ping) VALUES(?,?,?)";
my $insert_h = $dbh->prepare($query);
$insert_h->execute($rname,$rip,$ping_ret);
#####  print $ofh "$rname  $rip  $ping_ret\n";
#print "$rname  $rip  $ping_ret\n";

exit;

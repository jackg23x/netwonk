#!/usr/bin/perl
#jackg@uic.edu
#
# swping.pl  - ping all the switches
# child process of swseeker.pl -- collects arp info off a single switch
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

## my $of  = "$path/swping.out";
## my $ofh = IO::File->new(">>$of");
my ($date,$time)=SshSwcon::date_time();
my $tstamp = "$date $time";

my ($swname,$swip,$table);
my $args;
@$args  = @ARGV;
$swip   = $args->[0];
$swname = $args->[1];
$table  = $args->[2];

my $p = Net::Ping->new() or  print "pingfail: $swip\n";
my $ping_ret = $p->ping($swip);
if ($ping_ret eq "")  {  $ping_ret = 0; }
$p->close;
my $query = "INSERT INTO switch.$table (swname,swip,ping) VALUES(?,?,?)";
my $insert_h = $dbh->prepare($query);
$insert_h->execute($swname,$swip,$ping_ret);
   #####  print $ofh "$swname  $swip  $ping_ret\n";

exit;

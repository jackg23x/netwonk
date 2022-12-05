#!/usr/bin/perl
#jackg@uic.edu

## swmacstats.pl

use IO::File;
use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

my $of  = "$installpath/forensic/switches/swmacstats.out";
my $ofh = IO::File->new(">$of");

my $swmacstats_h;    ## hash of all the stats
my $select_h  = $dbh->prepare("SELECT mac,port,swname FROM switch.mac; ");
$select_h->execute();
my $sel_ary = $select_h->fetchall_arrayref;
foreach my $rec (@$sel_ary)  {
   my $mac    = $rec->[0];
   my $port   = $rec->[1];
   my $swname = $rec->[2];
   $swmacstats_h->{"$mac $port $swname"}++;
}

my $swmac_ary;
foreach my $swmac (keys %$swmacstats_h)  {
   my $total = $swmacstats_h->{$swmac};
   push @$swmac_ary,"$total $swmac";
}
@$swmac_ary = reverse(sort { $a <=> $b } @$swmac_ary);

foreach my $tot (@$swmac_ary)  {  print $ofh "$tot\n";  }

exit;

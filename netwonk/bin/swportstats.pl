#!/usr/bin/perl
#jackg@uic.edu

## swportstats.pl

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use IO::File;

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

my $of  = "$installpath/forensic/switches/swportstats.out";
my $ofh = IO::File->new(">$of");

my $swportstats_h;    ## hash of all the stats
my $select_h  = $dbh->prepare("SELECT swname,port FROM switch.mac; ");
$select_h->execute();
my $sel_ary = $select_h->fetchall_arrayref;
foreach my $rec (@$sel_ary)  {
   my $swname = $rec->[0];
   my $port   = $rec->[1];
   $swportstats_h->{"$swname $port"}++;
}

my $swpo_ary;
foreach my $swport (keys %$swportstats_h)  {
   my $total = $swportstats_h->{$swport};
   push @$swpo_ary,"$total $swport";
}
@$swpo_ary = reverse(sort { $a <=> $b } @$swpo_ary);

foreach my $tot (@$swpo_ary)  {  print $ofh "$tot\n";  }

exit;

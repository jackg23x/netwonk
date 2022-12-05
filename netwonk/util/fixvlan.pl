#!/usr/bin/perl
## jackg@uic.edu 
## 
## script to fix the vlan label problems caused by using nameif nicknames
##

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/util//;

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

my $contextary;
my $contexth;
my $query = "SELECT vlan,context FROM asa.arp WHERE vlan NOT REGEXP \"\^[0-9]+\$\" ORDER by context ";
my $select_h  = $dbh->prepare($query);
$select_h->execute();
if ($select_h->rows != 0) {
   my $sel_ary = $select_h->fetchall_arrayref;
   foreach my $row (@$sel_ary)   {
      my ($vlan,$context) = @$row;
      $contexth->{"$context     $vlan"} = 1;
   }
}

foreach my $cv (keys %$contexth)    {  push @$contextary,$cv;  }
if ($contextary)  {
   @$contextary = sort(@$contextary);
   foreach my $cvc (@$contextary)   {  print "$cvc\n";  }
}

exit;


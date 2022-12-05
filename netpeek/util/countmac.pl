#!/usr/bin/perl
#
# by jackg@uic.edu
#
# ./countmac.pl <-d threshhold date in yyyy-mm-dd format>  list_of_vlan_numbers
# finds the total mac addresses in arp.reapIP for each vlan, and gives a summary total for entire script instance run 
#

use strict;

use vars qw( $datethresh );

use FindBin qw($Bin);
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/util//;

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit("server1");
#my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,"$p",{RaiseError => 1});

my $args;
if ($ARGV[0] eq "")  {
   help();
   exit;
}
if ($ARGV[0] eq "-d")  {
   shift @ARGV;
   $datethresh = shift @ARGV;
}
@$args = @ARGV;

print "\n";
if ($datethresh =~ /\A\d{4}-\d{2}-\d{2}/) { print "Date threshold $datethresh enabled for display data.\n"; }
else  { print "No date threshhold entered\n"; }

my $total; ### all macs in query - good for multiples
foreach my $vlan (@$args)  {
   my $mac_count = count_macs($vlan);
   if (!$mac_count)  { $mac_count = 0; }
   print " vlan $vlan - macs found: $mac_count\n";
   $total = $total + $mac_count;
}

print "\n  Total query mac count: $total\n\n";

#########################################

sub count_macs   {

   my $vlan = shift;

   my $mac_count;
   my $query  = "SELECT mac,recent FROM arp.reapIP WHERE vlan = \"$vlan\" "; 
   my $select_h = $dbh->prepare($query);  
   $select_h->execute();
   my $sel_ary = $select_h->fetchall_arrayref;
   foreach my $rec (@$sel_ary)  {
      my $mac    = $rec->[0];
print "$mac\n";
      my $recent = $rec->[1];
      if ($recent lt $datethresh)  {  next;  }
      $mac_count++;
   }
   return($mac_count);
}

#########################################

sub help  {

print "\ncountmac.pl\n\n";
print "countmac.pl <-d threshhold date in yyyy-mm-dd format> list_of_vlan_numbers \n";
print "finds the total number of mac addresses in arp.reapIP for each vlan listed\n";
print "gives a summary total for entire script instance run\n\n";

}

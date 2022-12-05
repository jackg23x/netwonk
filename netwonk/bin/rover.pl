#!/usr/bin/perl
## jackg@uic.edu 
## 
## rover.pl                                                                   
##
## rover is a good dog - he searches for mac addresses on routers which may be
## eluding an existing macfilter, and then sends them into network.swmacfilterQ 
## for switch-level processing
##

use strict;
use Time::Local;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

my $datetime = datetime();

print "rover.pl - checking all mac databases for active filtered machines...\n";

my $activeh;
my $query = "SELECT mac,vlan,router FROM router.arp WHERE active = 1; ";
my $select_h  = $dbh->prepare($query);
$select_h->execute();
if ($select_h->rows != 0) {
   my $sel_ary = $select_h->fetchall_arrayref;
   foreach my $row (@$sel_ary)   {
      my ($mac,$vlan,$router) = @$row;
      $activeh->{$mac} =  "$vlan $router";
   }
}

my $query = "SELECT mac,vlan,rtr FROM rtr.arp WHERE active = 1; ";
my $select_h  = $dbh->prepare($query);
$select_h->execute();
if ($select_h->rows != 0) {
   my $sel_ary = $select_h->fetchall_arrayref;
   foreach my $row (@$sel_ary)   {
      my ($mac,$vlan,$rtr) = @$row;
      $activeh->{$mac} =  "$vlan $rtr";
   }
}

my $query = "SELECT mac,vlan,context FROM fw.arp WHERE active = 1; ";
my $select_h  = $dbh->prepare($query);
$select_h->execute();
if ($select_h->rows != 0) {
   my $sel_ary = $select_h->fetchall_arrayref;
   foreach my $row (@$sel_ary)   {
      my ($mac,$vlan,$context) = @$row;
      $activeh->{$mac} =  "$vlan $context";
   }
}

my $filtered_h;
my $query = "SELECT mac,vlan,router FROM network.macfilters; ";
my $select_h  = $dbh->prepare($query);
$select_h->execute();
if ($select_h->rows != 0) {
   my $sel_ary = $select_h->fetchall_arrayref;
   foreach my $row (@$sel_ary)   {
      my ($mac,$vlan,$router) = @$row;
      $filtered_h->{$mac} = "$vlan $router";
   }
}

## if it's already in network.smacfilterQ, this will help avoid inserting it again
my $filterQ_h;
my $query = "SELECT mac,operation FROM network.swmacfilterQ; ";
my $select_h  = $dbh->prepare($query);
$select_h->execute();
if ($select_h->rows != 0) {
   my $sel_ary = $select_h->fetchall_arrayref;
   foreach my $row (@$sel_ary)   {
      my ($address,$operation) = @$row;
      $filterQ_h->{"$address $operation"} = 1;
   }
}
#foreach my $qv (keys %$filterQ_h)  { print "$qv\n"; } #print "=============================\n";

my $filtered_active;
foreach my $mac (keys %$filtered_h)  {  
   if (exists $activeh->{$mac})  {
      $filtered_active = 1;
      my ($vlan,$context) = split " ", $activeh->{$mac};
      if (exists $filterQ_h->{"$mac filter"})   {  next;  }  ## it's already in swmacfilterQ, no need to overload
      ## get metadata on most recent entry into network.macfilterlog for this mac address
      my $query = "SELECT who,datefilt,operation,comment FROM network.macfilterlog where mac = \"$mac\" ORDER BY dateQ desc; ";
      my $select_h  = $dbh->prepare($query);
      $select_h->execute();
      my ($who,$datefilt,$operation,$comment);
      if ($select_h->rows != 0) {
         my $sel_ary = $select_h->fetchall_arrayref;
         $who       = $sel_ary->[0]->[0] ;
         $datefilt  = $sel_ary->[0]->[1] ;
         $operation = $sel_ary->[0]->[2] ;
         $comment   = $sel_ary->[0]->[3] ;
      }
      if ($who eq "")       { $who = "network"; }
      if ($comment eq "")   { $comment = "existing filter"; }
      my ($prtreason,undef) = split /\(/, $comment; 
      my ($date,undef)      = split " ", $datefilt; 
      if ($date eq "")      {
         ($date,undef) = split " ", $datetime;
      }
      if ($vlan !~ /wireless/)  {
         my $now = timelocal(localtime());
         my ($dt,undef) = split " ", $datefilt;
         my ($y,$m,$d)  = split "-", $dt;
         my $dflt = timelocal(0,0,0,$d,$m,$y); 
         my $diff = $now - $dflt;
         print "now  = $now\n";
         print "datefilt = $dflt\n";
         print "diff ", $diff, "\n"; 
         if ($diff < 600000)  {  next;  print "bailing on short date $diff\n";  } 
      }

      # network.swmacfilterQ inserts    #mac operation dateQ netid comment
      my $insert_h = $dbh->prepare("INSERT IGNORE INTO network.swmacfilterQ VALUES(?,?,?,?,?);");
      $insert_h->execute($mac,"filter",$datetime,"rover","$who $date $comment");

      printf "%-14s %-6s %-20s %-3s %-1s %-8s %-2s\n", $mac,"filter",$datetime,"rover","0","$who $date $comment";  
      printf "rover: %-10s  %-16s %-5s %-10s by: %-8s  reason: %-32s \n", $date, $mac, $vlan, $operation, $who, $prtreason;  
   }
}
if ($filtered_active == 0)  {  print "No filtered macs found active.\n";  }

#@$contextary = sort(@$contextary);
#foreach my $cvc (@$contextary)     {  print "$cvc\n";  }

exit;

####################

sub datetime  {
   my ($sec,$min,$hour,$mday,$mon,$year,undef,undef,undef) = localtime(time);
   $mon += 1;
   if ($mon  < 10) { $mon  = "0"."$mon"; }
   if ($mday < 10) { $mday = "0"."$mday"; }
   # Y2K fix:
   my $yr=1900+$year;
   my $date = "$yr-$mon-$mday";
   if ( $hour < 10 )  { $hour = "0"."$hour"; }
   if ( $min  < 10 )  { $min  = "0"."$min"; }
   if ( $sec  < 10 )  { $sec  = "0"."$sec"; }
   my $time = "$hour:$min:$sec";
   return("$date $time");
}  ## date_time


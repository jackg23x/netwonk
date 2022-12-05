#!/usr/bin/perl
#jackg@uic.edu 
#
# swvlan.pl 
# child process -- collects vlan info off a single switch -- writes to switch.vlan
#

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use lib "$installpath/lib";
use SshSwcon;
use IO::File;

my ($date,$time)=SshSwcon::date_time();
my $tstamp = "$date $time";

my $args;
@$args  = @ARGV;
my $swip   = $args->[0];
my $swname = $args->[1];

if ($swip !~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {
   print "\nBad input - first argument must switch IP, second switch name.\nExiting...\n\n";
   exit;
}
require "$installpath/lib/servers.pl";
my $domain = dnssuffix();
$swname =~ s/\.rtr\.$domain//;
$swname =~ s/\.switch\.$domain//;

my $of  = "$installpath/forensic/switches/$swname.swvlan";

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

my $ofh  = IO::File->new(">$of");
print $ofh "swvlan.pl   $swip   $swname  \n";

my $session = SshSwcon->new($swip);
my $state = $session->connect();
if ($state eq "notconnected")  {
   ## print $errfh "$tstamp $swname $swip - Session state = $state\n"; # from swmisc.pl, output: ./forensic-swmisc/ZXerr.out
   exit;
}
my $ena_ret;
if ($state ne "enabled")  { $ena_ret = $session->enable(); }
$session->command("term len 0");
my $intlns = $session->command("show interface status");
my $numlns = scalar($intlns);
if ($numlns > 5)  {         ## this checks if we really got a valid return


   ## CLEAR DATABASE TABLE
   #my $cmd = "DELETE from switch.vlan WHERE swname = \"$swname\" ";
   #my $delete_h = $dbh->prepare($cmd);
   #$delete_h->execute();
   my $query = "SELECT swname,port FROM switch.vlan where swname = \"$swname\"; ";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      foreach my $row (@$sel_ary)   {
         my ($swname,$port) = @$row;
         my $dquery = "DELETE FROM switch.vlan WHERE swname=\"$swname\" AND port=\"$port\" ";
         my $delete_h = $dbh->prepare($dquery);
         $delete_h->execute();
      }
   }

   ## Port      Name               Status       Vlan       Duplex  Speed Type
   my ($lport,$lname,$lstatus,$lvlan,$lduplex,$lspeed,$ltype);   ## field lengths - defined in the headers data return only
   foreach my $ln (@$intlns)  {
      if ($ln =~ /show/)  {  next;  }   ## the command reflection line
      if ($ln =~ /\A\s*\z/)      { next; }   ## blank line
      if ($ln =~ /\A$swname\#/)  { next; }   ## last return line
      my ($port,$name,$status,$vlan,$duplex,$speed,$type);   ## fields 
      if ($ln =~ /Port/)  {
         ($port,$name,$status,$vlan,$duplex,$speed,$type) = $ln =~ m/(\w+\s+)/g;
         ## Duplex and Speed fields are one character shifted from the header -- weird, huh?  Cisco...
         $lport=length($port); $lname=length($name); $lstatus=length($status); $lvlan=length($vlan); 
         $lduplex=length($duplex)-1; $lspeed=length($speed);
         $ltype = 80-$lport-$lname-$lstatus-$lvlan-$lduplex-$lspeed+20;  ## +20 is for scooch room
      }
      else  {
         ($port,$name,$status,$vlan,$duplex,$speed,$type) = unpack("a$lport a$lname a$lstatus a$lvlan a$lduplex a$lspeed a$ltype",$ln);
         if ($name =~ /\A\s*\z/)  { $name = "0"; }  ## need meaningful filler
         if ($type =~ /\A\s*\z/)  { $type = "0"; }  ## need meaningful filler
         $port   =~ s/\s+//g;
         $name   =~ s/\s+//g;
         $status =~ s/\s+//g;
         $vlan   =~ s/\s+//g;
         $duplex =~ s/\s+//g;
         $speed  =~ s/\s+//g;
         $type   =~ s/\s+//g;
         my $insert_h;  # insert new row
         $insert_h = $dbh->prepare("INSERT into switch.vlan (tstamp,swip,swname,port,name,status,vlan,duplex,speed,type)
                                    VALUES (?,?,?,?,?,?,?,?,?,?)" );
         $insert_h->execute($tstamp,$swip,$swname,$port,$name,$status,$vlan,$duplex,$speed,$type);
         print $ofh "INSERT: $port  $name  $status  $vlan  $duplex  $speed  $type\n";
      }
   }  ## foreach
}  ## if numlns
$session->close();

$dbh->disconnect();

exit;

#######################


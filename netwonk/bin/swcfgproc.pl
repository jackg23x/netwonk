#!/usr/bin/perl
# jackg@uic.edu
#
# swcfgproc.pl
#
# Child of swseeker.pl
# Reads a single switch configs.
# Re-creates essential config data for each switch/port in switch.intcfg  
#

use strict;

use IO::File;
use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});
my ($insert_h,$update_h,$select_h);

#my $jf  = "/root/switches/bin/swseeker/swcfgproc.log";
#my $jfh = IO::File->new(">$jf");

#####
if (!@ARGV)  {
   print "\n syntax:  swcfgproc.pl <switch>.cfg  \n\n"; 
   exit;
}
my $args;
@$args = @ARGV;

my $swname;
my $cfg_path = "$installpath/configs/switches";
my $cfgfile = $args->[0];
($swname,undef) = split /\./, $cfgfile;
my $f = "$cfg_path/$cfgfile";
if (-e  $f )  {    ## a single config file as argument - manual run
   my $fh = IO::File->new("$f");
   my $cfg;  ## array ref - one config
   while (my $ln = <$fh>)  {
      chomp($ln);
      push @$cfg, $ln;
   }
   process_swcfg($cfg); 
}
else  { print "No argument entered -- argument is <switch>.cfg full filename.\n"; }

exit;

#######################################

sub process_swcfg  {

   my $cfg = shift;

   ## CLEAR DATABASE TABLE 
   #my $cmd = "DELETE from switch.intcfg WHERE swname = \"$swname\" ";
   #my $delete_h = $dbh->prepare($cmd);
   #$delete_h->execute();
   my $query = "SELECT swname,port FROM switch.intcfg where swname = \"$swname\"; ";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      foreach my $row (@$sel_ary)   {
         my ($swname,$port) = @$row;
         my $dquery = "DELETE FROM switch.intcfg WHERE swname=\"$swname\" AND port=\"$port\" ";
         my $delete_h = $dbh->prepare($dquery);
         $delete_h->execute();
      }
   }

   ## go through switch cfg (new 2020-07-03)
   my $tempifh;  ## array of one interface worth of config
   foreach my $ln (@$cfg)  {
      #if ($pr)  {  print "$ln \n";  }
      chomp $ln;
      if ($ln =~ /\A\s*shutdown/)  {
         %$tempifh = ();  ## go for another interface group
         next;
      }
      if ($ln =~ /^interface/)    {
         my (undef,$interface) = split " ", $ln;
         ## PORT = INTERFACE instance
         if ($interface =~ /^FastEthernet/)         {  $interface =~ s/stEthernet//;  }
         if ($interface =~ /^GigabitEthernet/)      {  $interface =~ s/gabitEthernet//;  }
         if ($interface =~ /^TwoGigabitEthernet/)   {  $interface =~ s/oGigabitEthernet//;  }
         if ($interface =~ /^TenGigabitEthernet/)   {  $interface =~ s/nGigabitEthernet//;  }
         if ($interface =~ /^FortyGigabitEthernet/) {  $interface =~ s/rtyGigabitEthernet//;  }
         $tempifh->{"port"} = $interface;
      } 
      if ($ln =~ /ip address/)    {
         if ($ln =~ /no ip address/)    { next; }  ## Don't process null interfaces!
         my (undef,undef,$gw,$mask) = split " ", $ln;
         $tempifh->{"gw"}     = $gw;
         $tempifh->{"mask"}   = $mask;
      }
      ## 'switchport mode access' not used on all switches -  may have to get mode info
      ## from 'switchport access vlan' -- but remember a 'trunk' statement overrides a
      ## 'switchport' statment, so check 'trunk' and assign mode AFTER 'switchport access'
      my $mode;
      if ($ln =~ /switchport mode access/)    {
         $mode = "access";
         $tempifh->{"mode"} = $mode;
         ## this is needed if there is a 'switchport mode' only to set up a 'switchport voice'
         ## statment for a VoIP connection.
      }
      if ($ln =~ /switchport access vlan/)    {
         my (undef,undef,undef,$vlan) = split " ", $ln;
         $tempifh->{"vlan"} = $vlan;
         $mode = "access";  ## can be overridden by following trunk statment!
         $tempifh->{"mode"} = $mode;
      }
      if ($ln =~ /switchport mode trunk/)    {
         $mode = "trunk";
         $tempifh->{"mode"} = $mode;
      }
      if ($ln =~ /switchport trunk /)    {
         if ($mode ne "trunk")  {
            $mode = "trunk_auto";
            $tempifh->{"mode"} = $mode;
         }
      }
      if ($ln =~ /switchport voice vlan/)    {
         my (undef,undef,undef,$voice) = split " ", $ln;
         $tempifh->{"voice"} = $voice;
      }
      if ($ln =~ /speed/)    {
         my (undef,$speed) = split " ", $ln;
         $tempifh->{"speed"} = $speed;
      }
      if ($ln =~ /duplex/)    {
         my (undef,$duplex) = split " ", $ln;
         $tempifh->{"duplex"} = $duplex;
      }
      if ($ln =~ /switchport port-security/)    {
         $tempifh->{"port_sec"}  = 1;
      }
      if ($ln =~ /switchport port-security maximum/)    {
         my (undef,undef,undef,$ps_max) = split " ", $ln;
         $tempifh->{"ps_max"}  = $ps_max;
      }
      if ($ln =~ /switchport port-security aging time/)    {
         my (undef,undef,undef,undef,$ps_age) = split " ", $ln;
         $tempifh->{"ps_age"}  = $ps_age;
      }
      if ($ln =~ /switchport port-security violation/)    {
         my (undef,undef,undef,$ps_viol) = split " ", $ln;
         $tempifh->{"ps_viol"}  = $ps_viol;
      }
      if ($ln =~ /switchport port-security aging type/)    {
         my (undef,undef,undef,undef,$ps_age_type) = split " ", $ln;
         $tempifh->{"ps_age_type"}  = $ps_age_type;
      }
      if ($ln =~ /storm-control broadcast level/)    {
         my (undef,undef,undef,$scb_level) = split " ", $ln;
         $tempifh->{"scb_level"}  = $scb_level;
      }
      if ($ln =~ /storm-control action/)    {
         my (undef,undef,$sc_action) = split " ", $ln;
         $tempifh->{"sc_action"}  = $sc_action;
      }
      if ($ln =~ /spanning-tree bpduguard enable/)    {
         $tempifh->{"bpdu_ena"}  = 1;
      }
      if ($ln =~ /\s*!\s*\z/)  {         ## meaning we reached the end of this interface block
         if ($tempifh->{"port"} eq "")  {  next;  }  
         ## good interface - write to database, clear hash variable $tempifh
         my $insert_h;  # insert new row
         $insert_h = $dbh->prepare("INSERT into switch.intcfg (swname,port,mode,vlan,voice,speed,duplex,
                                    port_sec,ps_max,ps_age,ps_viol,ps_age_type,scb_level,sc_action,bpdu_ena)
                                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)" );
         #foreach my $k (keys %$tempifh)  { print "$k=", $tempifh->{$k}, " "; }
         #print "\n";
         $insert_h->execute($swname,
                            $tempifh->{"port"}||0,
                            $tempifh->{"mode"}||0,
                            $tempifh->{"vlan"}||0,
                            $tempifh->{"voice"}||0,
                            $tempifh->{"speed"}||0,
                            $tempifh->{"duplex"}||0,
                            $tempifh->{"port_sec"}||0,
                            $tempifh->{"ps_max"}||0,
                            $tempifh->{"ps_age"}||0,
                            $tempifh->{"ps_viol"}||0,
                            $tempifh->{"ps_age_type"}||0,
                            $tempifh->{"scb_level"}||0,
                            $tempifh->{"sc_action"}||0,
                            $tempifh->{"bpdu_ena"}||0    ); 
         %$tempifh = ();
      }

   }
}  ## process_swcfg 

##################################################################


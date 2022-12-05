#!/usr/bin/perl
use strict;
use warnings;

use Time::Local qw(timelocal);
use POSIX qw(strftime);

use DBI ();
require "./world_pw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});
my $update_h  = $dbh->prepare('UPDATE IGNORE network.macflap SET tstamp = ? WHERE mac = ? and vlan = ? and switch =? and port1 = ? and port2 = ?');
my $insert_h  = $dbh->prepare('INSERT into network.macflap (mac,vlan,switch,port1,port2,tstamp) VALUES (?,?,?,?,?,?)');
my $select_h  = $dbh->prepare('SELECT mac from network.macflap where switch = ? and port1 = ? and port2 = ?');

while(1) {
   eval {
      while(1) {
         -e "/tmp/world_macflap.pipe" or system "/usr/bin/mkfifo","/tmp/world_macflap.pipe";
         open PIPEH, "< /tmp/world_macflap.pipe" or die "Couldn't open named_pipe for reading: $!\n";
         while (my $ln = <PIPEH>)   {
            chomp $ln;
            my($tstamp,$switch,$mac,$vlan,$port1,$port2);
            if ($ln =~ /MACFLAP/)  {
               $ln =~ s/,/ /g;
               $ln =~ s/is flapping between port/ /g;
               $ln =~ s/and port/ /g;
               ($switch,undef,undef,undef,undef,undef,undef,undef,undef,$mac,undef,undef,$vlan,$port1,$port2) = split " ", $ln;
            }
            $mac = fix_dhcp_mac($mac);
            if ($mac =~ /[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}/)  {
               $select_h->execute($switch,$port1,$port2);
               if ($select_h->rows == 0) { $insert_h->execute($mac,$vlan,$switch,$port1,$port2,$tstamp); }
               else                      { $update_h->execute($tstamp,$mac,$vlan,$switch,$port1,$port2); }
            }
         }
         close PIPEH;
         sleep 3;
      }
   };
   print "DIED $@\n";
}

##################################

sub fix_dhcp_mac {

   my $addr = shift;

   $addr =~ s/\://g;
   $addr =~ s/\-//g;
   $addr =~ s/\.//g;
   if ($addr =~ /[0-9a-f]{12}/) {
      my $a = substr($addr,0,4);
      my $b = substr($addr,4,4);
      my $c = substr($addr,8,4);
      $addr = "$a.$b.$c";
      return($addr);
   }
}

## fix_dhcp_mac


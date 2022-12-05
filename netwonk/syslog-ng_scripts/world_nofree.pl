#!/usr/bin/perl
use strict;
use warnings;

use Time::Local qw(timelocal);
use POSIX qw(strftime);

## For print debugging:
#use IO::File;
#my $of  = "/var/log/adn/world_nofree.log";
#my $ofh = IO::File->new(">>$of");

use DBI ();
require "./world_pw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});
my $update_h  = $dbh->prepare('UPDATE IGNORE network.nofree_dhcp SET mac = ?, network = ?, tstamp = ? WHERE mac = ? and network = ?');
my $insert_h  = $dbh->prepare('INSERT into network.nofree_dhcp (mac,network,tstamp) VALUES (?,?,?)');
my $select_h  = $dbh->prepare('SELECT mac,network,tstamp from network.nofree_dhcp where mac like ? and network like ?');

while(1) {
   eval {
      while(1) {
         -e "/tmp/world_nofree.pipe" or system "/usr/bin/mkfifo","/tmp/world_nofree.pipe";
         open PIPEH, "< /tmp/world_nofree.pipe" or die "Couldn't open named_pipe for reading: $!\n";
         # dhcp-server1,2011-10-06 16:31:07,dhcpd,dhcpd: DHCPDISCOVER from 00:03:47:fa:58:a4 via 101.222.11.1: network 101.222.11/24: no free leases
         while (my $ln = <PIPEH>)   {
            chomp $ln;
            my($date,$time,$tstamp,$mac,$network);
            if ($ln =~ /no free leases/)  {
               $ln =~ s/,/ /g;
               (undef,$date,$time,undef,undef,undef,$mac,undef,undef,undef,$network,undef,undef,undef) = split " ", $ln;
            }
            ##print $ofh "$ln\n$mac\n";
            $mac = fix_dhcp_mac($mac);
            if ($mac =~ /[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}/)  {
               ##print $ofh "$mac\n#####\n";
               $network =~ s/://;
               $tstamp = "$date $time";
               $select_h->execute($mac,$network);
               if ($select_h->rows == 0) { $insert_h->execute($mac,$network,$tstamp); }
               else                      { $update_h->execute($mac,$network,$tstamp,$mac,$network); }
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

## world_nofree


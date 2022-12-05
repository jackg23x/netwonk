#!/usr/bin/perl
use strict;
use warnings;

use Time::Local qw(timelocal);
use POSIX qw(strftime);

## For print debugging:
#use IO::File;
#my $of  = "/var/log/adn/world_ack.log";
#my $ofh = IO::File->new(">>$of");

use DBI ();
require "./world_pw.pl";
my ($h,$u,$p) = dbigrabit();
my $vmdbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});
my $update_vmh  = $vmdbh->prepare('UPDATE IGNORE network.last_dhcp SET mac = ?, ip = ?, gateway = ?, tstamp = ? WHERE mac = ?               and gateway = ?');
my $insert_vmh  = $vmdbh->prepare('INSERT into network.last_dhcp (mac,ip,gateway,tstamp) VALUES (?,?,?,?)');
my $select_vmh  = $vmdbh->prepare('SELECT mac,ip,gateway,tstamp from network.last_dhcp where mac like ? and gateway like ?');

while(1) {
   eval {
      while(1) {
         -e "/tmp/world_ack.pipe" or system "/usr/bin/mkfifo","/tmp/world_ack.pipe";
         open PIPEH, "< /tmp/world_ack.pipe" or die "Couldn't open named_pipe for reading: $!\n";
         while (my $ln = <PIPEH>)  {
            chomp $ln;
            my($host,$tstamp,$ip,$mac,$gateway,$mess);
            ($host,$tstamp,undef,$mess) = split /,/, $ln;
             # print $ofh "$ln\n$mess\n";
            if ($host) {
               if ($mess =~ /DHCPACK on/)  {
                  my $end;
                  (undef,undef,$ip,undef,$mac,$end) = split ' ', $mess, 6;
                  if ($end =~ /\(/) {
                     my ($more,$hostid);
                     ($hostid,$end) = split /\)/, $end;
                  }
                  (undef,$gateway) = split ' ', $end;
               }
               elsif ($mess =~ /DHCPACK to/)  {
                  my $end;
                  (undef,undef,$ip,$end) = split ' ', $mess, 4;
                  if ($end) {
                     if ($end =~ /via/) {  ($mac,undef,$gateway) = split ' ', $end;  }
                     else               {  $mac = $end;  }
                     $mac =~ s/\(//;
                     $mac =~ s/\)//;
                  }
                  else  {  # jackg 2021-07-31 - it's an ack extending the existing lease
                     ## example $ln: dhcpd,2021-07-31 12:19:34,dhcpd,DHCPACK to 10.111.74.141
                     my $quick_update_vmh  = $vmdbh->prepare('UPDATE IGNORE network.last_dhcp SET tstamp = ? WHERE ip = ?');
                     $quick_update_vmh->execute($tstamp,$ip);
                  }
               }
            }  ## if host
            if ($gateway) {
               $mac = fix_dhcp_mac($mac);
               if ($mac =~ /[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}/)  {
                  $select_vmh->execute($mac,$gateway);
                  ## print $ofh "mac >$mac<  ip >$ip<  gw >$gateway<  tr >$tstamp< \n";
                  if ($select_vmh->rows == 0) {  $insert_vmh->execute($mac,$ip,$gateway,$tstamp); }
                  else                        {  $update_vmh->execute($mac,$ip,$gateway,$tstamp,$mac,$gateway);  }
               }
            }
         }  ## while PIPEH
         close PIPEH;
         sleep 3;
      }
   };   ## eval - need the ";" to complete the eval statement
   print "DIED $@\n";
}

##################

sub fix_dhcp_mac  {

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
   ## else it returns blah
}

##################



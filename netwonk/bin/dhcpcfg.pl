#!/usr/bin/perl

# jackg@uic.edu
#
# dhcpcfg.pl
# Reads dhcpd.conf (/mnt/global/dhcp/dhcpd.conf) 
# creates/updates network.fixies and network.ranges
#

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use IO::File;

use vars qw(%ints );

my $args;
@$args  = @ARGV;

## THIS FILE
my @fn = split /\//, $0;
my $thisfile = @fn[$#fn];
my ($thisfn,undef) = split /\./, $thisfile;

my $of  = "/$installpath/forensic/$thisfn.log";
my $ofh = IO::File->new(">$of");

my $date = `date`;
print $ofh "############## dhcpcfg.pl run - $date\n"; 

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

## control switches
my $db = 1;      ## switch to turn on/off writing to switch.* database
for (my $i = 0; $i <= $#$args; $i++ )  {
   if ($args->[$i] =~ /-db0/)  {
      $db = 0;                   ## turn database execution off
      splice @$args, $i, 1;      ## remove from @args
   }
}

my $fixiehash;     ## hash ref for fixies in the 'group' section
my $range_ips;     ## array ref for range elements
my $subnethash;    ## hash ref for network, lease-times, options, etc. -- not used as of 2021-07-23
my $config_list;   ## array of valid dhcp config files
my ($cfgf,$cfgfh);

## Legacytype giant dhcp config files;
require "$installpath/lib/servers.pl";
my $dhcpcfgfile1 = dhcpcfgfile1();
push @$config_list, $dhcpcfgfile1;

######### local to original environment
## New config files on gateway-1
my $dhcpcfgpath2 = dhcpcfgpath2();
my @ls =  `ls $dhcpcfgpath2`;
foreach my $l (@ls)  {
   chomp $l;
   if ($l =~ /^\d{1,4}-dhcpd.conf/)  {  push @$config_list, "$dhcpcfgpath2/$l";  }
   # print $ofh "$l\n";
}
#########

foreach my $cfgf (@$config_list)   {
   $cfgfh = IO::File->new("$cfgf");
   my $net;            ## used to anchor $subnethash  entries
   my $mac;            ## for assembling fixie relationship
   while (my $ln = <$cfgfh>)  {
      if ($ln =~ /\s*#/)   {  next;  }     ## it's a comment line
      chomp $ln;
         ## the following host code works, but we're not using this dhcp host info in any way
         ## if ($front =~ /\s*host\s*(\S+)\s*{/)  {    my $host = $1;    print "host = >$host<\n"; }
      my $ipformat = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}';
      my $macformat = '\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}';
      ## Hardware ethernet
      if ($ln =~ /\A\s*hardware ethernet\s*($macformat)/)  {  
         $mac =$1;
         $mac = fix_mac_format($mac);
      }
      ## Fixies - we're dependent on the $mac collected in the fixie line above (so we must also reset it)
      if ($ln =~ /\A\s*fixed-address\s*($ipformat)/)  {  
         my $ip = $1;
         if (($mac ne "") && ($mac ne "0000.0000.0000"))  {
            $fixiehash->{"$mac $ip"} = 1;
            $mac = "";       ## reset
         }
      }
      ## Subnet stanza -- not used as of 2021-07-23
      if ($ln =~ /\A\s*subnet\s*($ipformat)\s*netmask\s*($ipformat)/)  {
         my $net = $1;
         $subnethash->{$net}->{"network"} = $1;
         $subnethash->{$net}->{"netmask"} = $2;
      }
         ## Routers (Gateway(s)) -- not used as of 2021-07-23; does not support multiples - are they possible?
      if ($ln =~ /routers\s+($ipformat)\s*;/)  { $subnethash->{$net}->{"routers"} = $1; }
         ## Domain Name Servers -- zero, one or more -- not used as of 2021-07-23
      if ($ln =~ /domain-name-servers/)  {
         my(undef,$rest) = split /domain-name-servers/, $ln;
         $rest =~ s/;//;
         my @dns = split /,/, $rest;
         $subnethash->{$net}->{"domain-name-servers"} = @dns;
      }
      if ($ln =~ /default-lease-time\s+(\d+)\s*;/)  { $subnethash->{$net}->{"default-lease-time"} = $1;  }
      if ($ln =~ /max-lease-time\s+(\d+)\s*;/)      { $subnethash->{$net}->{"max-lease-time"} = $1;      }
      ## Lease Ranges -- when you hit 'range' you have finished the 'subnet' configuraton coding
      if ($ln =~ /\A\s*range\s+$ipformat/)  {    ## generic range statment
         ($ln,undef) = split "#", $ln;
         $ln =~ s/;//g;
         if ($ln =~ /\s*range\s*($ipformat)\s*\z/)     {   push @$range_ips, $1;  }     
         elsif ($ln =~ /\s*range\s*($ipformat)\s*($ipformat)\s*\z/)  {
            my($a,$b,$c,$d) = split /\./, $1;
            my(undef,undef,undef,$e) = split /\./, $2;
            for (my $i=$d; $i<=$e; $i++)          {   push @$range_ips, "$a.$b.$c.$i";  }
         }  
         else  {  print $ofh "format problem?: >$ln< \n";  }   
      }
   }
}  ## foreach my $cfgf
 
## Fixies: Print to log and Insert into network.fixies 
if ($db)  {
   my $delete_h = $dbh->prepare("DELETE FROM network.fixies;");
   $delete_h->execute();
}
foreach my $key (keys %$fixiehash)  {
   my ($mac,$ip) = split / /, $key;
   # print $ofh "fixie $mac   $ip\n";
   if ($db)  {
     my $query = "INSERT into network.fixies VALUES(\"$mac\",\"$ip\"); ";
     my $insert_h = $dbh->prepare($query);
     $insert_h->execute();
   }
}
## Ranges: Print to log and Insert into network.ranges
if ($db)  {
   my $delete_h = $dbh->prepare("DELETE FROM network.ranges;");
   $delete_h->execute();
}
foreach my $r (@$range_ips)  {  
   # print $ofh "$r\n";
   if ($db)  {
     my $query = "INSERT into network.ranges VALUES(\"$r\"); ";
     my $insert_h = $dbh->prepare($query);
     $insert_h->execute();
   }
}

exit;

###########################################

sub fix_mac_format  {

  my $mac  = shift;

  $mac = lc($mac);
  $mac =~ s/\W//g;
  my $aa = substr($mac,0,4);
  my $bb = substr($mac,4,4);
  my $cc = substr($mac,8,4);
  $mac = "$aa.$bb.$cc";
  return($mac);

} ## fix_mac_format

###################################################

sub sort_by_ip  {

my $iplist = shift;   ## array ref

## here's the mapping transform for IP number sorting:
    @$iplist =
        map {$_->[0]}
        sort { ($a->[1] <=>$b->[1])
                    || ($a->[2] <=>$b->[2])
                    || ($a->[3] <=>$b->[3])
                    || ($a->[4] <=>$b->[4]) }
        map {[$_, split( '[ \.]', $_) ]} @$iplist;

return ($iplist);

}  ## sort_by_ip

####################


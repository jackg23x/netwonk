#!/usr/bin/perl
## jackg@uic.edu 
## 
## rtrarp.pl
## called by rseeker.pl
## grabs all the arp data for one layer-3 switch in this one child process                   
##

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

my $xtest = 0;  ## if xtest=1, no sql processing
my ($session,$rname,$rip);

$rip   = $ARGV[0];
$rname = $ARGV[1];

my $errf  = "$installpath/forensic/rtr/$rname.rtrarp.out";
my $errfh = IO::File->new(">$errf");
my $of    = "$installpath/forensic/rtr/rtrarp.all";
## my $of    = "rtrarp.all";
my $ofh   = IO::File->new(">>$of");

print $ofh "Begin $rip  $rname\n";

#print "$errf\n";
#print "$tstamp rtrarp.pl initialized:  $rip   $rname\n";
print $errfh "$tstamp rtrarp.pl initialized:  $rip   $rname\n";

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

## Connect to switch
my $session = SshSwcon->new($rip);
my $state = $session->connect();
if ($state eq "notconnected")  {
   print $errfh "$tstamp $rname $rip - Session state = $state\n";
   exit;
}
my $ena_ret;
if ($state ne "enabled")   {  $ena_ret = $session->enable();  }
$session->command("term len 0");

##### Get all active in rtr.arp
my $arp_active;  ## hash ref, key = "mac ip"
my $select_h  = $dbh->prepare('SELECT * from rtr.arp WHERE rtr = ? AND active = ?');
$select_h->execute($rname,"1");
## all active=1 rows as one single array per row:
my $sel_ary = $select_h->fetchall_arrayref;
foreach my $rec (@$sel_ary)  {
   my $recstr = join " ", @$rec;
   my (undef,undef,undef,undef,$mac,$ip,undef,$vlan,undef) = split " ", $recstr;
   if ($vlan eq /667|4000/)  {  next  };   # skip the cisco switch arps
   $arp_active->{"$mac $ip"} = $recstr;
}

#print  "ARP_ACTIVE: ";
#foreach my $key (%$arp_active)  { print "$key => ",$arp_active->{$key}, " \n;" }

## Do 'sh vrf' to get vrf instances, loop and do 'sh arp vrf <instance>' for each, process together
my $vrfs;  ## array of vrf instances
push @$vrfs, 'DEFAULT';
my $vrf_lns = $session->command("sh vrf");
foreach my $vrf_ln (@$vrf_lns)  {
   if ($vrf_ln =~ /\s*Name/)  { next; }
   if ($vrf_ln =~ /\s*Mgmt-vrf/)  { next; }
   if ($vrf_ln =~ /ipv4/)  {
      my ($vrf, undef) = split " ", $vrf_ln, 2;
      push @$vrfs, $vrf;
   }
}

my %arps;
foreach my $vrf (@$vrfs)  {
   print $errfh "vrf: $vrf \n"; 
   if ($vrf eq 'DEFAULT')  {  $arps{$vrf} = $session->command("show arp","10");            } 
   else                    {  $arps{$vrf} = $session->command("show arp vrf $vrf","10");   } 
}  ## foreach my $vrf

foreach my $vrfa (@$vrfs) {
   foreach my $varps ($arps{$vrfa})  {
    foreach my $arp (@$varps) {
      if ($arp !~ /^\s*Internet/)  {  next;  }   ## the command comes back first, other junk at end...   ;->
      my(undef,$ip,undef,$mac,undef,$vlan) = split " ", $arp;   ## "Internet" up front
      if ($vlan eq /667|4000/)  {  next  };   # skip the cisco switch arps
      if ($mac =~ /Incomplete/)  {  next;  }
      $vlan =~ s/vlan//i;
      ## if an $arp record references an active=1 sql entry, we Update recent field
      if ( exists $arp_active->{"$mac $ip"} )  {
         my $update_h  = $dbh->prepare('UPDATE IGNORE rtr.arp SET recent = ? WHERE mac = ? AND ip = ? AND rtr = ? AND active = ?');
         if ($xtest == 0)  {  $update_h->execute($tstamp,$mac,$ip,$rname,"1");  }  ## turns off sql for testing on $xtest=1
         delete($arp_active->{"$mac $ip"});
         print $errfh "update $mac  $ip\n";
      }
      else  {   ## it's a new mac-ip entity, so insert:
         my $insert_h = $dbh->prepare('INSERT into rtr.arp (birth,recent,mac,ip,rtr,vlan,active) VALUES (?,?,?,?,?,?,?)');
         if ($xtest == 0)   {  $insert_h->execute($tstamp,$tstamp,$mac,$ip,$rname,$vlan,"1");  } ## sql off when $xtest=1
         print $errfh "insert $mac  $ip\n";
      }

      ##### arp.reapIP ######
      my $select_h  = $dbh->prepare('SELECT * from arp.reapIP WHERE ip = ?'); 
      $select_h->execute($ip);
      my $rec = $select_h->fetchrow_arrayref;
      if ($rec->[0] ne "")  {  ## there is an entry, so update recent field in reapIP
         my $recstr = join " ", @$rec;
         my (undef,undef,$last_recent,undef,undef) = split " ", $recstr;
         # $date is a global variable from up top
         if ($last_recent ne $date)  {   ## update if there's an existing entry -- we only record date here, not time
            my $update_h  = $dbh->prepare('UPDATE IGNORE arp.reapIP SET recent = ? , mac = ? , router = ? , vlan = ? WHERE ip = ?');
            if ($xtest == 0)  {  $update_h->execute($date,$mac,$rname,$vlan,$ip);  }  ## sql off when $xtest=1
         }
      }    
      else  {   ## no entry in reapIP -- insert a new one 
            #print "arp.reapIP INSERT PRIV $ip\n";
            my $insert_h = $dbh->prepare('INSERT into arp.reapIP (ip,mac,recent,router,vlan) VALUES (?,?,?,?,?)');
            if ($xtest == 0)  {  $insert_h->execute($ip,$mac,$date,$rname,$vlan);  }  ## sql off when $xtest=1        
      }
   }  ## foreach my $arp
 }
}  ## foreach my $vrfa

## We have processed all arp entries collected.  Anything remaining in %$arp_active sould now be marked active=0
foreach my $key (%$arp_active)  {
   my ($mac,$ip) = split " ", $key;
   my $update_h  = $dbh->prepare('UPDATE IGNORE rtr.arp SET active = ? WHERE mac = ? AND ip = ? AND rtr = ? AND active = ?');
   $update_h->execute("0",$mac,$ip,$rname,"1");
}

$session->close();
print "$tstamp rtrarp.pl $rip $rname completed\n";

$dbh->disconnect();

exit;

###################################

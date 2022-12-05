#!/usr/bin/perl
#jackg@uic.edu

## routerC.pl is used (2022) as a standalone scripte with router name and router ip
## directly invoked as script arguments (i.e. routerC.pl myrouter 192.168.1.254)
## It was originally written as a Child process of routerP.pl, but the parallel 
## structure is not needed here -- maybe in some other environment
## It connects context via OpenSSH and collects arp data 
## Writes to tables router.arp and arp.reapIP
##

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use lib "$installpath/lib";
use Sshcon;
use IO::File;

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});
my ($insert_h,$update_h,$select_h);

## timestamp of this run
my($date,$time) = Sshcon::date_time();
my $tstamp = "$date $time";

#my $args;
#@$args = @ARGV;
my $rname   = @ARGV[0];
my $rip     = @ARGV[1];
my $cmd     = @ARGV[2] || "arp";

#my $outfile = "./routerC.out";
#my $ofh = IO::File->new(">$outfile");

my $session = Sshcon->new($rip);
my $state = $session->connect;
my $ena_ret;
if ($state ne "enabled")  {
   $session->enable();
}
$session->command("term len 0");

my $cmd_ret;
if ($cmd =~ /arp/)  {
   my $cmd = "show arp";
   $cmd_ret = $session->command($cmd);

   $session->command("exit");
   $session->close();

   proc_arp($cmd_ret);
}
## if ($cmd =~ /<some_command>/)  {     # expansion  
## }
$dbh->disconnect();

exit;

##########

sub proc_arp  {

  my $cmd_ret = shift;

  my $active;  ## hash of currently active entries in router.arp on world.cc
  ## we want active ip/mac pairs from the current router only 
  my $select_h  = $dbh->prepare("SELECT ip,mac from router.arp where active = 1 and router = \"$rname\" ");
  $select_h->execute();
  ## all rows as one array each:
  my $sel_ary = $select_h->fetchall_arrayref;
  foreach my $rec (@$sel_ary)  {
     my $ip    = @$rec[0];
     my $mac   = @$rec[1];  
     $active->{"$ip $mac"} = "1";
  }

my $retlns; # array

  ## process arp data
  foreach my $cr (@$cmd_ret)  {
     if ($cr !~ /Internet/i)   {  next;  }
     if ($cr =~ /Incomplete/i) {  next;  }
     chomp($cr);
     $cr =~ s/\s+/ /g;              ## there were weird characters lurking
     my (undef,$arpip,undef,$mac,undef,$vlan) = split / /, $cr;
     ## push @$retlns, "$arpip - $mac - $vlan";
     $vlan =~ s/\s//g;
     $vlan =~ s/\s*vlan//i;
     if (exists $active->{"$arpip $mac"})  {       ## there's an active entry, so update 'recent' timestamp
        $update_h  = $dbh->prepare("UPDATE IGNORE router.arp SET recent = ?, vlan = ?  WHERE ip = ? AND mac = ? AND router = ? AND active = 1");
        $update_h->execute($tstamp,$vlan,$arpip,$mac,$rname);
        my $del_ret = delete($active->{"$arpip $mac"});  ## remove from active  - remaining  will be inactive
     }
     else  {           ## not in active hash -- generate new entry
        $insert_h  = $dbh->prepare("INSERT into router.arp (birth,recent,mac,ip,router,vlan,active) VALUES (?,?,?,?,?,?,?)");
        $insert_h->execute($tstamp,$tstamp,$mac,$arpip,$rname,$vlan,"1");
     }
     ## reapIP
     my $select_h  = $dbh->prepare('SELECT * from arp.reapIP WHERE ip = ?');
     $select_h->execute($arpip);
     if ($select_h->rows != 0) {
        my $rec = $select_h->fetchrow_arrayref;
        my (undef,undef,$last_recent,undef,undef) = @$rec;
        # $date is a global variable from up top
        if ($last_recent ne $date)  {   ## update if there's an existing entry -- we only record date here, not time
           my $update_h = $dbh->prepare('UPDATE IGNORE arp.reapIP SET recent = ? , mac = ? , router = ? , vlan = ? WHERE ip = ?');
           $update_h->execute($date,$mac,$rname,$vlan,$arpip);
           #push @$retlns, "update $date,$mac,$rname,$vlan,$arpip";
        }
     }
     else  {   ## no entry in reapIP -- insert a new one
           my $insert_h = $dbh->prepare('INSERT IGNORE into arp.reapIP (ip,mac,recent,router,vlan) VALUES (?,?,?,?,?)');
           $insert_h->execute($arpip,$mac,$date,$rname,$vlan);
           #push @$retlns, "insert $arpip,$mac,$date,$rname,$vlan";
     }
     ## End reapIP
  }  ## foreach my cr

#print $ofh "Remaining 'active' ip/mac pairs\n";
## things left in %$active are no longer...active!  :-)
while ( my($x,$y) = each(%$active))  {
   my ($arpip,$mac) = split / /, $x;
   $update_h  = $dbh->prepare("UPDATE IGNORE router.arp SET active = ? WHERE ip = ? AND mac = ? AND router = ? ");
   $update_h->execute("0",$arpip,$mac,$rname);
#   print $ofh "ip mac\n";    
}

return;
}  ## proc_arp

#########


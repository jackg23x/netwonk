#!/usr/bin/perl
# jackg@uic.edu
#
# fw-PaC.pl runs arp and xlate routines 
#
# It connects directly to context via OpenSSH and collects xlates and arps 
# - Xlates are processed to fw.xlate 
# - Arps areprocessed to fw.arp          
#


use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use lib "$installpath/lib";
use SshPa;
use IO::File;

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});
my ($insert_h,$update_h,$select_h);

## control switches -- Do Not Edit: change these by command-lime parameters (see below)
my $db = 1;      ## switch to turn on/off writing to database - Do Not Edit
my $pr = 0;      ## switch to turn on/off informational printing - Do Not Edit

my($date,$time) = SshPa::date_time();
my $tstamp = "$date $time";

my $args;
@$args = @ARGV;
## check for print-only override
my $p0;
for (my $i = 0; $i <= $#$args; $i++ )  {
    if ($args->[$i] =~ /p0/)  {
       print "*** print-only override - no database processing\n";
       $p0 = 1; $pr = 1; $db = 0;        ## print Only Override
       splice @$args, $i, 1;      ## remove from @args
    }
}
## process variables
my $aip     = $args->[0];
my $context = $args->[1];
my $cmd     = $args->[2];
print "\$pr = $pr   \$db = $db\n";  
print "\$aip = >$aip<   \$context = >$context<   \$cmd = >$cmd<\n";  
if (($context eq "") || ($cmd eq ""))  {
   ## if ($pr == 0)  {  print "\$aip = >$aip<   \$context = >$context<   \$cmd = >$cmd<\n";  }
   print "Must have valid ip, context and cmd entries -- please correct input data.\nExiting...\n";
   exit;
}

#my $outfile = "../forensic/fw/Pa.$context.$cmd.out";
#my $ofh = IO::File->new(">$outfile");

my $session = SshPa->new($aip);
my $state = $session->connect;
#print $ofh "connect return: >$state<\n";
#if ($state =~ /passive/)  {  print $ofh "passive interface - exiting...\n";  exit;  }
if ($state =~ /passive/)  {  print "passive interface - exiting...\n";  exit;  }

$session->command("set cli pager off");
my $cmd_ret;
if ($cmd =~ /arp/)  {
   my $pacmd = "show arp all";
   $cmd_ret = $session->command($pacmd);
   $session->command("exit");
   $session->close();
   proc_arp($cmd_ret);
}
if ($cmd =~ /xlate/)  {
   my $pacmd = "show session all";
   $cmd_ret = $session->command($pacmd);
   $session->command("exit");
   $session->close();
   proc_xlate($cmd_ret);
}
$dbh->disconnect();

exit;

##########

sub proc_arp  {

  my $cmd_ret = shift;

  my $arpip;
  my $mac;
  my $active;  ## hash of currently active entries in fw.arp 

  ## get current active entries in fw.arp -- create 'active' hash
  my $select_h  = $dbh->prepare("SELECT arpip,mac from fw.arp where active = 1 and context = \"$context\" ");
  $select_h->execute();
  my $sel_ary = $select_h->fetchall_arrayref;
  foreach my $rec (@$sel_ary)  {
     $arpip = @$rec[0];
     $mac   = @$rec[1];  
     $active->{"$arpip $mac"} = "1";
  }

  ## process arp data
  foreach my $cr (@$cmd_ret)  {
     chomp($cr);
     #  ae6.2247  10.100.90.83   00:08:e3:ff:fc:94 ae6   c   648
     my ($intf,$arpip,$mac,undef) = split " ", $cr;
     unless ($arpip =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)  {  next;  }
     if ($arpip eq "0.0.0.0")    {  next;  }
     $intf =~ s/\s//g;
     my (undef,$vlan) = split /\./, $intf;
     $mac = fix_mac($mac);
     if (exists $active->{"$arpip $mac"})  {
        ## there's an active entry, so let's update 'recent' timestamp to show that the arp is still there
        if ($db)  {
           my $cmd = "UPDATE IGNORE fw.arp SET recent = ?, vlan = ? WHERE arpip = ? AND mac = ? AND active = 1";
           $update_h  = $dbh->prepare($cmd);
           $update_h->execute($tstamp,$vlan,$arpip,$mac);
        }
        #print $ofh "update   $arpip     $mac      $vlan \n";       
        my $del_ret = delete($active->{"$arpip $mac"});  ## remove from active  - remaining  will be inactive
     }
     else  {
        ## not in active hash -- generate new entry
        if ($db)  {
           $insert_h  = $dbh->prepare("INSERT into fw.arp (birth,recent,arpip,mac,vlan,context,active) VALUES (?,?,?,?,?,?,?)");
           $insert_h->execute($tstamp,$tstamp,$arpip,$mac,$vlan,$context,"1");
        }
        #print $ofh "insert:  $arpip     $mac      $vlan \n";
     }

     ## reapIP
     my $select_h  = $dbh->prepare('SELECT * from arp.reapIP WHERE ip = ?');
     $select_h->execute($arpip);
     if ($select_h->rows != 0) {
        my $rec = $select_h->fetchrow_arrayref;
        my (undef,undef,$last_recent,undef,undef) = @$rec;
        # $date is a global variable from up top
        if ($last_recent ne $date)  { ## update if there's an existing entry - only record date here, not time
           if ($db)  {
              my $cmd = "UPDATE IGNORE arp.reapIP SET recent = ? , mac = ? , router = ? , vlan = ? WHERE ip = ?";
              my $update_h = $dbh->prepare($cmd);
              $update_h->execute($date,$mac,$context,$vlan,$arpip);
           }
           #print $ofh "update arp.reapIP:  >$arpip<  >$mac<  >$date< \n";
        }
     }
     else  {   ## no entry in reapIP -- insert a new one
           if ($db)  {
              my $insert_h = $dbh->prepare('INSERT IGNORE into arp.reapIP (ip,mac,recent,router,vlan) VALUES (?,?,?,?,?)');
              $insert_h->execute($arpip,$mac,$date,$context,$vlan);
           }
           #print $ofh "insert arp.reapIP:  >$arpip<  >$mac<  >$date< \n";
     }
     ## End reapIP

  }  ## foreach my cr

  ## things left in %$active are no longer...active!  :-)
  while ( my($x,$y) = each(%$active))  {
        my ($arpip,$mac) = split / /, $x;
        $update_h  = $dbh->prepare("UPDATE IGNORE fw.arp SET active = ? WHERE arpip = ? AND mac = ? ");
        $update_h->execute("0",$arpip,$mac);
  }
  
  return;
} ## proc_arp
  
#########

sub proc_xlate  {

  my $cmd_ret = shift;

  my $priv_ip;
  my $pub_ip;
  my $active;  ## hash of currently active entries in fw.xlate 

  ## get current active entries in fw.xlate -- create 'active' hash
  my $select_h  = $dbh->prepare("SELECT priv_ip,pub_ip from fw.xlate where active = 1 and context = \"$context\" ");
  $select_h->execute();
  ## all rows as one array each:
  my $sel_ary = $select_h->fetchall_arrayref;
  foreach my $rec (@$sel_ary)  {
     $priv_ip = @$rec[0];
     $pub_ip  = @$rec[1];
     $active->{"$priv_ip $pub_ip"} = "1";      
  }
  ## TEST ## if ($pr)  { # while (my($x,$y) = each(%$active))  {  print $ofh "$x => $y\n";  }   }

  ## process xlate data
  my $xl_h;
  foreach my $cr (@$cmd_ret)  {
     chomp($cr);
     # 8858508      ssl            ACTIVE  FLOW  NS   10.5.208.61[42930]/vlan876/6  (131.193.147.176[42930])
     my (undef,undef,undef,undef,undef,$priv_ip,$pub_ip) = split " ", $cr;
     if ($priv_ip !~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)  {  next;  }
     if ($pub_ip  !~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)  {  next;  }
     ($priv_ip,undef) = split /\[/, $priv_ip;
     if ($priv_ip =~ /0.0.0.0/)  {  next;  }
     $pub_ip =~ s/\(//;
     ($pub_ip,undef) = split /\[/, $pub_ip;
     if ($priv_ip eq $pub_ip)       {  next;  } 
     $xl_h->{"$priv_ip $pub_ip"} = 1;
  }
  foreach my $xx (keys %$xl_h)  {
     my ($priv_ip,$pub_ip) = split " ", $xx;
     if (exists $active->{"$priv_ip $pub_ip"})  {
        if ($db)  {
           $update_h  = $dbh->prepare("UPDATE IGNORE fw.xlate SET recent = ? WHERE priv_ip = ?  AND pub_ip = ? AND active = 1");
           $update_h->execute($tstamp,$priv_ip,$pub_ip);
        }
        my $del_ret = delete($active->{"$priv_ip $pub_ip"});  ## remove from active hash
        #print $ofh  "update: $priv_ip       $pub_ip\n";
     }
     else  {
        if ($db)  {     
           $insert_h  = $dbh->prepare("INSERT into fw.xlate (birth,recent,priv_ip,pub_ip,context,active) VALUES (?,?,?,?,?,?)");
           $insert_h->execute($tstamp,$tstamp,$priv_ip,$pub_ip,$context,"1");
        }
        #print $ofh  "insert: $priv_ip       $pub_ip\n";
     }
  }

## things left in %$active are no longer...active!  :-)
#print $ofh "Active removals:\n";
while ( my($x,$y) = each(%$active))  {
   my ($priv_ip,$pub_ip) = split / /, $x;
   #print $ofh "$priv_ip, $pub_ip\n";
   if ($db)  {
      $update_h  = $dbh->prepare("UPDATE IGNORE fw.xlate SET active = ? WHERE priv_ip = ? AND pub_ip = ? ");
      $update_h->execute("0",$priv_ip,$pub_ip);
   }
}

return;
}  ## proc_xlate

#################################################################################

sub fix_mac  {

  my $addr = shift;

  $addr = lc($addr);   ## I'm case chauvanistic  ;->
  $addr =~ s/\.//g;
  $addr =~ s/\://g;
  $addr =~ s/\-//g;
  my $aa = substr($addr,0,4);
  my $bb = substr($addr,4,4);
  my $cc = substr($addr,8,4);
  $addr = "$aa.$bb.$cc";
  return($addr);

}  ## fix_mac

#################################################################################

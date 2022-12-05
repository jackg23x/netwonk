#!/usr/bin/perl
# jackg@uic.edu
#
# fw-asaC.pl is a Child process of fw-asaP.pl
#
# It connects directly to context via OpenSSH and collects xlates and arps 
# - Xlates are processed to fw.xlate 
# - Arps areprocessed to fw.arp          
#
#

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

## control switches -- Do Not Edit: change these by command-lime parameters (see below)
my $db = 1;      ## switch to turn on/off writing to database - Do Not Edit
my $pr = 0;      ## switch to turn on/off informational printing - Do Not Edit

my($date,$time) = Sshcon::date_time();
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

#my $outdir = "/root/netwonk/data/asaC/;    
#my $outfile = "$installpath/forensic/asa/$context.asaC.out";
#my $ofh = IO::File->new(">$outfile");

print "\$pr = $pr   \$db = $db\n";  
print "\$aip = >$aip<   \$context = >$context<   \$cmd = >$cmd<\n";  
if (($context eq "") || ($cmd eq ""))  {
   ## if ($pr == 0)  {  print "\$aip = >$aip<   \$context = >$context<   \$cmd = >$cmd<\n";  }
   print "Must have valid asa ip, context and cmd entries -- please correct input data.\nExiting...\n";
   exit;
}

my $session = Sshcon->new($aip);
my $state = $session->connect;
#print $ofh "session state: >$state<\n";
if ($state eq "notconnected")  {
   print "no connection...exiting process\n";
   exit;
}

my $ena_ret;
if ($state ne "enabled")  {
   $ena_ret = $session->enable();
}
$session->command("term pager 0");

my $cmd_ret;
if ($cmd =~ /arp/)  {
   my $asacmd = "show arp";
   $cmd_ret = $session->command($asacmd);
   $session->command("exit");
   $session->close();
   proc_arp($cmd_ret);
}
if ($cmd =~ /xlate/)  {  
   my $asacmd = "show xlate ";
   $cmd_ret = $session->command($asacmd);
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
  my $active;  ## hash of currently active entries in fw.arp on world.cc

  ## get current active entries in fw.arp -- create 'active' hash
  my $select_h  = $dbh->prepare("SELECT arpip,mac from fw.arp where active = 1 and context = \"$context\" ");
  $select_h->execute();
  ## all rows as one array each:
  my $sel_ary = $select_h->fetchall_arrayref;
  foreach my $rec (@$sel_ary)  {
     $arpip = @$rec[0];
     $mac   = @$rec[1];  
     $active->{"$arpip $mac"} = "1";
  }

  ## process arp data
  foreach my $cr (@$cmd_ret)  {
     chomp($cr);
     #  vlan2035 10.133.32.11 0020.4a87.196e 140 
     unless ($cr =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)  {  next;  }
     my ($vlan,$arpip,$mac,undef) = split / /, $cr;
     $vlan =~ s/\s//g;
     $vlan =~ s/\s*vlan//i;
     if ($vlan !~ /^[0-9]+$/)  {
        my $query = "SELECT vlan from network.ipvlanmap where ip = \"$arpip\"; ";
        my $select_h  = $dbh->prepare($query);
        $select_h->execute();
        my $sel_ary = $select_h->fetchall_arrayref;
        $vlan = $sel_ary->[0]->[0];
     }
     if (exists $active->{"$arpip $mac"})  {
        ## there's an active entry, so let's update 'recent' timestamp to show that the arp is still there
        if ($db)  {
           my $cmd = "UPDATE IGNORE fw.arp SET recent = ?, vlan = ? WHERE arpip = ? AND mac = ? AND active = 1";
           $update_h  = $dbh->prepare($cmd);
           $update_h->execute($tstamp,$vlan,$arpip,$mac);
        }
        my $del_ret = delete($active->{"$arpip $mac"});  ## remove from active  - remaining  will be inactive
     }
     else  {
        ## not in active hash -- generate new entry
        if ($db)  {
           $insert_h  = $dbh->prepare("INSERT into fw.arp (birth,recent,arpip,mac,vlan,context,active) VALUES (?,?,?,?,?,?,?)");
           if ($vlan eq "")  {  $vlan = "none";  }
           $insert_h->execute($tstamp,$tstamp,$arpip,$mac,$vlan,$context,"1");
        }
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
        }
     }
     else  {   ## no entry in reapIP -- insert a new one
           if ($db)  {
              my $insert_h = $dbh->prepare('INSERT IGNORE into arp.reapIP (ip,mac,recent,router,vlan) VALUES (?,?,?,?,?)');
              $insert_h->execute($arpip,$mac,$date,$context,$vlan);
           }
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
}  ## proc_arp
  
#########

sub proc_xlate  {

  my $cmd_ret = shift;

  my $priv_ip;
  my $pub_ip;
  my $active;  ## hash of currently active entries in fw.xlate on world.cc

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

  ## process xlate data
  foreach my $cr (@$cmd_ret)  {
     chomp($cr);
     # NAT from inside:10.133.16.207 to outside:128.222.17.111 flags i idle 0:00:01 timeout 3:00:00
     # TCP PAT from vlan941:10.5.206.120/50459 to vlan3244:132.153.254.254/50459 flags ri....etc.
     unless ($cr =~ /NAT from|TCP PAT from/)  {  next;  }
     if     ($cr =~ /any/)                    {  next;  }
     if     ($cr =~ /,/)                      {  next;  }
     my ($stuff,undef) = split / flags/, $cr;
     my (undef,$priv_ip,$pub_ip) = split /:/, $stuff;
     ($priv_ip,undef) = split / /, $priv_ip;
     ($priv_ip,undef) = split /\//, $priv_ip;  ## get rid of the port on the private side
     ($pub_ip,undef)  = split /\//, $pub_ip;  ## get rid of the port on the private side
     if ($pub_ip eq $priv_ip)       {  next;  } 
 
     if (exists $active->{"$priv_ip $pub_ip"})  {
        if ($db)  {
           $update_h  = $dbh->prepare("UPDATE IGNORE fw.xlate SET recent = ? WHERE priv_ip = ?  AND pub_ip = ? AND active = 1");
           $update_h->execute($tstamp,$priv_ip,$pub_ip);
        }
        my $del_ret = delete($active->{"$priv_ip $pub_ip"});  ## remove from active hash
     }
     else  {
        if ($db)  {     
           $insert_h  = $dbh->prepare("INSERT into fw.xlate (birth,recent,priv_ip,pub_ip,context,active) VALUES (?,?,?,?,?,?)");
           $insert_h->execute($tstamp,$tstamp,$priv_ip,$pub_ip,$context,"1");
        }
     }
  }

## things left in %$active are no longer...active!  :-)
while ( my($x,$y) = each(%$active))  {
      my ($priv_ip,$pub_ip) = split / /, $x;
      if ($db)  {
         $update_h  = $dbh->prepare("UPDATE IGNORE fw.xlate SET active = ? WHERE priv_ip = ? AND pub_ip = ? ");
         $update_h->execute("0",$priv_ip,$pub_ip);
      }
}

return;
}  ## proc_xlate

##################


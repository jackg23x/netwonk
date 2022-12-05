#!/usr/bin/perl
#jackg@uic.edu 
#
# swmac.pl 
# child process of swseeker.pl -- collects arp info off a single switch
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

my ($swname,$swip,$forensic);
my $args;
@$args    = @ARGV;
$swip     = $args->[0];
$swname   = $args->[1];
$forensic = $args->[2]; ## for printing to per-switch file in forensic directory 

##### TEST! SYSTEM-WIDE FORENSIC OVERRIDE
#      $forensic = "forensic";
#####

if ($swip eq "") {
   print "\nswmac.pl - no arguments found\n";
   print "Syntax:  swmac.pl <swip> <swname> [option]\n";
   print "         option:  'f' or 'forensic' for print to <swname>.swmac file in forensic directory\n";
   print "...exiting\n\n";
   exit;
}
require "$installpath/lib/servers.pl";
my $domain = dnssuffix();
$swname =~ s/\.rtr\.$domain//;
$swname =~ s/\.switch\.$domain//;


use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

my ($of,$ofh);
if ($forensic =~ /^f/)  {
   $of  = "$installpath/forensic/switches/$swname.swmac";
   $ofh = IO::File->new(">$of");
   $forensic = 1;      print "FORENSIC: >$forensic<\n\n";
}
else  { $forensic = 0; print "FORENSIC: >$forensic<\n\n";  }
#print $ofh "FORENSIC: >$forensic<\n\n";
my ($date,$time)=SshSwcon::date_time();
my $recent = "$date $time";

if ($forensic)  {  print $ofh "swmac.pl ENTRY:  $swip  $swname \n";  }

my $sql_cmd  = "DELETE from switch.errdis where swname = \"$swname\"; ";
my $delete_h = $dbh->prepare($sql_cmd);
$delete_h->execute();

## Connect to switch
my $session = SshSwcon->new($swip);
my $state = $session->connect();
if ($state eq "notconnected")  {
   ## print $errfh "$tstamp $swname $swip - Session state = $state\n"; # from swmisc.pl, output: ./forensic-swmisc/ZXerr.out
   exit;
}
my $ena_ret;
if ($state ne "enabled")   {  $ena_ret = $session->enable();  }
$session->command("term len 0",0);  

## ERR-DIS
my $errlns;
$errlns = $session->command("show interface status err-dis",1);
my ($lport,$l2,$l3,$lreason,$l5);   ## field lengths - defined in the headers data return only
foreach my $err (@$errlns)  {
   if ($err =~ /show/)  {  next;  }       ## command reflection line
   ## 2021-12-19 attampt to dump garbage entries: 
   if ($err =~ /$swname/)  {  next;  }    ## command reflection line
   if ($err =~ /Invalid/i)  {  next;  }   ## command reflection line
   if ($err =~ /\s*--/)  {  next;  }      ## divider line
   my ($port,$f2,$f3,$reason,$f5);
   if ($err =~ /\A\s*\z/)       { next; }   ## blank line
   if ($err eq "")              { next; }   ## blank line
   ### if ($err =~ /\A$swname\#/i)  { next; }   ## last return line
   if ($err =~ /\#\s*\z/)  { next; }   ## if it ends in '#' it must be a return line
   if ($err =~ /Port/)  {
      $err =~ s/-/_/g;
      $err =~ s/(\w)\s(\w)/$1_$2/g;  ## glues together any multi-word field, like Name, usually
      # analyze lengths in this header line:     Port  Name  Status  Reason    Err-disabled_Vlans
      # changed to \s* on 2021-09-20; it's greedy, should be fine, correct loss of last field
      ($port,$f2,$f3,$reason,$f5) = $err =~ m/(\w+\s*)/g;
      $lport=length($port); $l2=length($f2); $l3=length($f3); $lreason=length($reason); $l5=length($f5);
      if ($lport < 2)  {  next;  }  ## corrects switch glitches in errdis returns
      if ($lreason == 0)  {  $lreason = 20;  }  ## kludge fix for weird short status switches
      ###print $ofh "errdis field lengths: >$lport< >$l2< >$l3< >$lreason< >$l5<\n";
      ###print $ofh "errdis PORT: >$swip< >$swname< >$port< >$recent< >$reason<\n";
   }
   else  {
      ($port,$f2,$f3,$reason,$f5) = unpack("a$lport a$l2 a$l3 a$lreason a$l5",$err);
      if ($forensic)  { print $ofh "errdis field lengths: >$lport< >$l2< >$l3< >$lreason< >$l5<\n"; }
      $port   =~ s/\s+//g;
      $reason =~ s/\s+//g;
      $reason =~ s/^led//;   ## 6500 text return formatting kludge -- I know how to fix it right, but not worth it for comrb! :)
      ## kludge fixes for switches with output issues:
      if ($reason =~ /^di/)     {  $reason = "diagnostics";  }
      if ($reason =~ /^bpdug/)  {  $reason = "bpduguard";    }
      my $sql_cmd  = "INSERT into switch.errdis (swip,swname,port,tstamp,reason) VALUES (?,?,?,?,?)";
      my $insert_h = $dbh->prepare($sql_cmd);
      $insert_h->execute($swip,$swname,$port,$recent,$reason);
      if ($forensic)  { 
         print $ofh "errdis line: $err\n"; 
         print $ofh "errdis components: >$swip< >$swname< >$port< >$recent< >$reason<\n";
      }
   }
   ##print $ofh "errdis: >$swip< >$swname< >$port< >$recent< >$reason<\n";
}

my $active_h;  ## hash of currently active entries in switch.mac on world.cc

## ACTIVE: get current active entries in switch.mac -- create 'active' hash
my $select_h  = $dbh->prepare("SELECT mac,port,vlan from switch.mac where active = 1 and swname = \"$swname\" order by birth desc");
$select_h->execute();
my $sel_ary = $select_h->fetchall_arrayref;
foreach my $rec (@$sel_ary)  {
   my $mac   = $rec->[0];            
   my $port  = $rec->[1];            
   my $vlan  = $rec->[2];            
   $active_h->{"$mac $port $vlan"} = 1;
}

if ($forensic)  {   foreach my $m (keys %$active_h) { print $ofh "ACTIVE: $m \n"; }  }

my $trunk_hash;  ## hash of trunk ports
my $tr_count;
while ((!keys %$trunk_hash) && ($tr_count < 3))  {
   my $tr_ret = $session->command("show int status | inc trunk",3);
   foreach my $tr (@$tr_ret)  {
      if ($tr =~ /show/)  { next; }
      if ($tr =~ /trunk/)  {
         my($tr_int,undef) = split " ", $tr;
         if ($tr_int =~ /^Eth/)  {
            my $tr_int2 = $tr_int;
            $tr_int2 =~ s/Eth/Ethernet/;  ## add extended version
            $trunk_hash->{$tr_int}  = 1;
            $trunk_hash->{$tr_int2} = 1;
         }
         if ($tr_int =~ /^Fa/)  {
            my $tr_int2 = $tr_int;
            $tr_int2 =~ s/Fa/FastEthernet/;  ## add extended version
            $trunk_hash->{$tr_int}  = 1;
            $trunk_hash->{$tr_int2} = 1;
         }
         if ($tr_int =~ /^Gi/)  {
            my $tr_int2 = $tr_int;
            $tr_int2 =~ s/Gi/GigabitEthernet/;  ## add extended version
            $trunk_hash->{$tr_int}  = 1;
            $trunk_hash->{$tr_int2} = 1;
         }
         if ($tr_int =~ /Te/)  {
            my $tr_int2 = $tr_int;
            $tr_int2 =~ s/Te/TenGigabitEthernet/;
            my $tr_int3 = $tr_int;
            $tr_int3 =~ s/Te/TenGi/;
            $trunk_hash->{$tr_int}  = 1;
            $trunk_hash->{$tr_int2} = 1;
            $trunk_hash->{$tr_int3} = 1;
         }
         if ($tr_int =~ /Tw/)  {
            my $tr_int2 = $tr_int;
            $tr_int2 =~ s/Tw/TwoGigabitEthernet/;
            $trunk_hash->{$tr_int}  = 1;
            $trunk_hash->{$tr_int2} = 1;
         }
      }
   }
   $tr_count++;
}
if (!keys %$trunk_hash)  {
   exit;  ## BETTER LUCK NEXT RUN!
}

if ($forensic)  {   while (my($x,$y) = each(%$trunk_hash))  {  print $ofh "TRUNK: $swname   $x \n"; }  }

require "$installpath/lib/core_routers.pl";
my $ipprefix = routeripprefix();
my $mac_ret;
if ($swip =~ /$ipprefix/)  { $mac_ret = $session->command("show mac address dyn",30); }  ## 6500 cisco
else                       { $mac_ret = $session->command("show mac address",20); }

$session->close();

my $macs;   ## array -- 'sh mac addr' data
my $mac_h;  ## hash for checking primary keys and avaoiding multi-vlan script die
my $switch_type;
foreach my $mr (@$mac_ret)  {
   if    ($mr =~ /vlan\s+mac address\s+type\s+learn\s+age\s+ports/i)  {
      $switch_type = "6500"; 
      last;
   }
   elsif ($mr =~ /vlan\s+mac address\s+type\s+learn\s+qos\s+ports/i)  {
      $switch_type = "6500"; 
      last;
   }
   elsif ($mr =~ /vlan\s+mac address\s+type\s+protocols\s+port/i)  {
      $switch_type = "4500"; 
      last;
   }
   elsif ($mr =~ /VLAN\s+Mac Address\s+Type\s+age\s+Secure\s+NTFY\s+Ports/i)  {
      $switch_type = "Nexus"; 
      last;
   }
   elsif ($mr =~ /Vlan\s+Mac Address\s+Type\s+Ports/i)  {
      $switch_type = "standard";
      last;
   }
   else  {   $switch_type = "standardX"; }     
}

foreach my $mr (@$mac_ret)  {
   $mr =~ s/\*//g;  ## old format output: 6500, etc.
   if ($mr !~ /[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}/)  {  next;  }
   if ($mr =~ /CPU/i)     {  next;  }
   if ($mr =~ /Switch/i)  {  next;  }
   if ($mr =~ /Router/i)  {  next;  }
   if ($mr =~ /sup-/i)    {  next;  }
   my ($vlan,$mac,$type,$port);
   if    ($switch_type =~ /6500/)     { ($vlan,$mac,$type,undef,undef,$port)       = split " ", $mr; }
   elsif ($switch_type =~ /4500/)     { ($vlan,$mac,$type,undef,$port)             = split " ", $mr; }
   elsif ($switch_type =~ /Nexus/)    { ($vlan,$mac,$type,undef,undef,undef,$port) = split " ", $mr; }
   elsif ($switch_type =~ /standard/) { ($vlan,$mac,$type,$port)                   = split " ", $mr; }
   else                               { ($vlan,$mac,$type,$port)                   = split " ", $mr; }
   if ($port eq "")       { next; }  ## avoid these - they are cisco switch macs
   if ($port =~ /,/)      { next; }  ## 6500 multiport switch entries
   ## Tried grabbing this Po data 2021-04-12 to 2022-05-31 -- it was a mistake.  If you need this history, put it in another table.
   if ($port =~ /Po\d/)   { next; }  ## leave out PortChanel macs
   if ($vlan =~ /ALL/)    { next; }  ## leave out
   if ($port =~ /<drop/)   {  $port = "drop";  }
   if ($port =~ /Drop/i)  { next; }  ## leave out Drop ports       { $port = "Drop"; }   ##  print $ofh "$mr\n"; }
   $port =~ s/gabitEthernet//g;
   # trunk check, insert into array
   if ($vlan eq "667")      { next; }  # mgmt
   if ($vlan =~ /^4\d{3}/)  { next; }  # mgmt in 4000 series of vlans
   if ($vlan eq "1")        { next; }  # mgmt
   if (exists $trunk_hash->{$port})  {  next; }
   ###print $ofh "== MR: $mac  $vlan  $port  $swip  $swname  $type  -\n";
   $type = lc($type);
   if ($type =~ /dynamic/i) { $type = "d"; }
   if ($type =~ /static/i)  { $type = "s"; }
   ## if (exists $trunk_hash->{$port})  { next; } 
   push @$macs, "$mac $vlan $port $type";
   
   if (exists $active_h->{"$mac $port $vlan"})  {
      my $sql_cmd = "UPDATE IGNORE switch.mac SET recent = \"$recent\" 
                     WHERE mac = \"$mac\" and port = \"$port\" and vlan = \"$vlan\" and active = \"1\" ";
      my $update_h = $dbh->prepare($sql_cmd);
      $update_h->execute();
      if ($forensic)  {  print $ofh "UPDATE $mac  $vlan  $port  $swip  $swname  <birth>  $recent  $type  1\n";  }
      my $del_ret = delete($active_h->{"$mac $port $vlan"});  ## remove from active - remaining will be inactive
   }
   else  {
      ## if (exists $mac_h->{"$mac-$port-$swname"})  { next; }  ## avoid die from primary key constraint on multi
      my $sql_cmd = "INSERT into switch.mac (mac,vlan,port,swip,swname,birth,recent,type,active) VALUES (?,?,?,?,?,?,?,?,?)";
      my $insert_h = $dbh->prepare($sql_cmd);
      my $active = 1;
      $insert_h->execute($mac,$vlan,$port,$swip,$swname,$recent,$recent,$type,$active);    ## new, so birth = recent
      ## $mac_h->{"$mac-$port-$swname"} = $port;
      if ($forensic)  {  print $ofh "INSERT into switch.mac $mac  $vlan  $port  $swip  $swname  $recent  $recent  $type  $active\n";  }
   }
   ## arp.reapmac
   ## if you ever decide to include Po mac entries, leave them out of reapmac processing here; i.e. if ($port =~ /^Po/)
   ## we select recent because to know there is an entry, and also to compare dates
   my $query = "SELECT recent FROM arp.reapmac WHERE mac = \"$mac\" AND vlan = \"$vlan\" ";
   my $select_h  = $dbh->prepare($query);
   my $recs = $select_h->execute();
   if ($recs != 0) {   # there is one
      my $sel_ary = $select_h->fetchall_arrayref;
      my $reap_recent = $sel_ary->[0]->[0];
      if ($reap_recent lt $date)  {
         ##if ($forensic)  {  print $ofh "reapmac: $reap_recent < $date\n";  }
         my $sql_cmd = "UPDATE IGNORE arp.reapmac SET recent=\"$date\",port=\"$port\",swname=\"$swname\" WHERE mac=\"$mac\" and vlan=\"$vlan\" ";
         my $update_h = $dbh->prepare($sql_cmd);
         $update_h->execute();
         if ($forensic)  {  print $ofh "reapmac update: $mac $vlan $date --- port=$port \n";  }
      } 
   }
   else  {             # there is no such entry 
      ##print $ofh "new reapmac: $mac $vlan $date\n";      
      my $sql_cmd = "INSERT into arp.reapmac (mac,recent,port,swname,vlan) VALUES (?,?,?,?,?)";
      my $insert_h = $dbh->prepare($sql_cmd);
      $insert_h->execute($mac,$date,$port,$swname,$vlan);    ## new, so birth = recent
      if ($forensic)  {  print $ofh "reapmac insert: $mac $vlan $date --- port=$port \n";  }
   }
}

while ( my($x,$y) = each(%$active_h))  {
   my ($mac,$port,$vlan) = split / /, $x;
   if ($forensic)  {  print $ofh "ACTIVE_H: $mac  $port $vlan\n";  }
   my $update_h = $dbh->prepare("UPDATE IGNORE switch.mac SET active = ? WHERE mac = ? AND port = ? AND vlan = ? ");
   $update_h->execute("0",$mac,$port,$vlan);
}

#foreach my $m (@$macs)  {  print $ofh "MACS: macs: $m\n";  }
#foreach my $mh (keys %$mac_h)  {  print $ofh "MAC_H Insert:  $mh => ", $mac_h->{$mh}, "\n"; }
#print "switch_type = $switch_type\n";

$dbh->disconnect();
exit:

####################################


#!/usr/bin/perl
## jackg@uic.edu
##
## script to filter/unfilter hosts on switches
## world database tables:
## - network.swmacfilters 
## - network.swmacfilterQ 
## - network.swmacfilterlog 
## related web script:
## - netfire:/var/www/bluestem-cgi/swmacfilter.cgi
##
##

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use lib "$installpath/lib";
use SshSwcon;

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});
my ($insert_h,$update_h,$select_h,$delete_h);

## control switches
my $ex = 1;      ## switch to turn on/off execution of config line processing 
my $db = 1;      ## switch to turn on/off writing to databases 
my $pr = 1;      ## switch to turn on/off informational printing
##

my ($date,$time)=SshSwcon::date_time();
my $datefilt = "$date $time";

if ($pr) { print "===== swmacfilter run: datefilt = $datefilt\n"; }

## Deal with parms:
if (!@ARGV)  {  help();  exit;  }
if ( grep /-h/ , @ARGV )  {  help();  exit;  }
my $args;
@$args = @ARGV;

my $flags;                   ## array of args control flags
## check for print-only override
my $p0;
for (my $i = 0; $i <= $#$args; $i++ )  {
    if ($args->[$i] =~ /p0/)  {
       $p0 = 1; $pr = 1; $ex = 0; $db = 0;        ## print Only Override
       push @$flags, $args->[$i];
       splice @$args, $i, 1;      ## remove from @args
    }
}
if ($p0 == 0)  {                     ## that is, $p0 is not enabled above
   for (my $i = 0; $i <= $#$args; $i++ )  {
       if ($args->[$i] =~ /-ex0/)  {
          $ex = 0;                   ## turn router execution off
          push @$flags, $args->[$i];
          splice @$args, $i, 1;      ## remove from @args
       }
   }
   for (my $i = 0; $i <= $#$args; $i++ )  {
       if ($args->[$i] =~ /-db0/)  {
          $db = 0;                   ## turn database execution off
          push @$flags, $args->[$i];
          splice @$args, $i, 1;      ## remove from @args
       }
   }
   for (my $i = 0; $i <= $#$args; $i++ )  {
       if ($args->[$i] =~ /-pr0/)  {
          $pr = 0;                   ## turn printing off
          push @$flags, $args->[$i];
          splice @$args, $i, 1;      ## remove from @args
       }
   }
}
if ($pr) {
   print "swmacfilter.pl ";
   foreach my $arg (@$args)    {  print "$arg ";   }   print "\n";
   foreach my $flag (@$flags)  {  print "$flag ";  }   print "\n";
   print "\$ex = $ex ::  \$db = $db :: \$pr = $pr \n";
}

my $filt_h;
my $parm = $args->[0];    ## filter/unfilter/Q
my $mac  = $args->[1];    ## the address being filtered/unfiltered - blank when 'Q'

## swmacfilterQ
if ($parm =~ /^Q/)  {
   ## Here we get the $mac from the swmacfilterQ, not from the ARGV
   my $query = "SELECT * FROM network.swmacfilterQ ORDER by dateQ ASC; ";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      foreach my $row (@$sel_ary)   {
         ## loop local version of $mac, but that's ok
         my ($mac,$operation,undef,$netid,$comment) = @$row;
         $filt_h->{$mac}->{"operation"} = $operation;
         $filt_h->{$mac}->{"datefilt"}  = $datefilt;
         $filt_h->{$mac}->{"netid"}     = $netid;
         $filt_h->{$mac}->{"comment"}   = $comment;
         $select_h = $dbh->prepare("SELECT vlan,swname FROM arp.reapmac WHERE mac = \"$mac\" ORDER BY recent DESC; ");
         $select_h->execute();
         if ($select_h->rows != 0) {
            my $sel_ary = $select_h->fetchall_arrayref;
            my $vlan    = $sel_ary->[0]->[0];
            my $swname  = $sel_ary->[0]->[1];
            print "switch.mac:  $vlan   $swname\n";
            $filt_h->{$mac}->{"vlan"}   = $vlan;
            $filt_h->{$mac}->{"swname"} = $swname;
         }
         else  {  print "no data in switch.mac for $mac\n";  }
      }
      print "Processing swmacfilterQ...\n";
   }
   else  {
      print "No entries in network.swmacfilterQ\n";
      exit;
   }
}
elsif ($parm +~ /^f|^u/)  {
   for (my $i = 0; $i <= $#$args; $i++ ) { if ($args->[$i] =~ /$parm/) {  splice @$args, $i, 1; } }  ## drop $parm
   for (my $i = 0; $i <= $#$args; $i++ ) { if ($args->[$i] =~ /$mac/)  {  splice @$args, $i, 1; } }  ## drop $mac
   my $comment = join " ", @$args;   ## remaining is the comment field
   if ($comment eq "")  {  $comment = "gregson console";  }
   if ($mac !~ /^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$/) {  fix_mac($mac);  }                          ## check format
   if ($mac !~ /^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$/) {  print "bad mac format! \n";   help();  }   ## check bad mac
   if ($parm =~ /^f/)  {  $parm = "filter";    }
   if ($parm =~ /^u/)  {  $parm = "unfilter";  }
   $filt_h->{$mac}->{"operation"} = $parm;
   $filt_h->{$mac}->{"datefilt"}  = $datefilt;
   $filt_h->{$mac}->{"netid"}     = "network";
   $filt_h->{$mac}->{"comment"}   = $comment;
   $select_h = $dbh->prepare("SELECT vlan,swname FROM arp.reapmac WHERE mac = \"$mac\" ORDER BY recent DESC; ");
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      my $vlan    = $sel_ary->[0]->[0];
      my $swname  = $sel_ary->[0]->[1];
      $filt_h->{$mac}->{"vlan"}   = $vlan;
      $filt_h->{$mac}->{"swname"} = $swname;
   }
   print "$parm"."ing $mac\n";
}
elsif ($parm eq "s")  { print "Display Current filters on switch config =>  mac address-table static <mac> vlan <vlan> drop\n"; }
else  {
   print "Error in input formatting:  parameter >$parm<    mac >$mac<   ...exiting\n\n";
   exit;
}

## Console print check of filt_h
foreach my $a (keys %$filt_h)  {
   foreach my $p (keys %{$filt_h->{$a}})  {  print "filt_h->$a->$p  ", $filt_h->{$a}->{$p}, "\n";  }
}

my $session;
my $all_log_h;   ## all log entries added to network.swmacfilterlog 

### Filtering and Unfiltering:
foreach my $mac (sort keys %$filt_h)  {
   if ($filt_h->{$mac}->{"operation"} eq "unfilter")  {
      unfilter_mac($mac);
      next;
   }
   ## Past this point, it's all about filtering
   my $swname = $filt_h->{$mac}->{"swname"};
   my $vlan   = $filt_h->{$mac}->{"vlan"}; 
   print "filt_h mac >$mac<   swname >$swname<   vlan >$vlan< \n";
   my $port;
   my $mac_found;
   ## Connect
   if ($swname eq "")  {
      print "Cannot find switch $swname for $mac.  Moving on to next entry.  Removing $mac swmacfilterQ entry\n";
      if ($db)  {
         $select_h = $dbh->prepare("DELETE from network.swmacfilterQ where mac = \"$mac\";  ");
         $select_h->execute();
      }
      next;  ## done with this mac, move on
   }
   my $alreadyfiltered;   ## used to avoid reprocessing entries
   if ($ex)  {
      $session = SshSwcon->new($swname);
      my $state = $session->connect();
      if ($state eq "notconnected")  {
         print "CONNECT ERROR: $swname - Session state = $state\n";
         exit;
      }
      my $ena_ret;
      if ($state ne "enabled")  {
         $ena_ret = $session->enable();
      }
      $session->command("terminal length 0",2);
      ## try finding the right port, turn off port-security, filter, turn on port-security
      my $op    = $filt_h->{$mac}->{"operation"};
      my $netid = $filt_h->{$mac}->{"netid"};
      my $ret;
      $ret = $session->command("show mac address | inc $mac",10);
      foreach my $ln (@$ret)  {
         $alreadyfiltered = 0;
         if ($ln =~ /show mac/)  {  next;  }
         if ($ln !~ /[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}/)  {  next;  }
         if ($ln =~ /drop/i)  {
            $alreadyfiltered = 1;
            print "\n *** $op $mac already in effect, removing from swmacfilterQ ***\n";
            if ($db)  {
               $delete_h = $dbh->prepare("DELETE FROM network.swmacfilterQ WHERE mac = \"$mac\" ; ");
               $delete_h->execute();
               next;
            }
         }
         $ln =~ s/\*//;
         $ln =~ s/Yes//;
         $ln =~ s/ - //;
         (undef,undef,undef,$port) = split " ", $ln;
      }
      ## print "\nPORT >$port<\n";
      ## if we don't have a port, try and find the most recent port in arp.reapmac
      print "/n...checking arp.reapmac for port...\n";
      if ($port eq "")  {
         $select_h = $dbh->prepare("SELECT port FROM arp.reapmac WHERE mac = \"$mac\"; ");
         $select_h->execute();
         if ($select_h->rows != 0) {
            my $sel_ary = $select_h->fetchall_arrayref;
            $port       = $sel_ary->[0]->[0];
            print "reapmac port: >$port< \n";
         }
      }
      print "ALREADY FILTERED >$alreadyfiltered< \n";
      if ($alreadyfiltered == 0)   {
         if ($port eq "")  {
            if ($vlan eq "")  {  $vlan = "unknown";  }
            print "\n *** cannot $op $mac, removing from swmacfilterQ\n";
            if ($db)  {
               $delete_h = $dbh->prepare("DELETE FROM network.swmacfilterQ WHERE mac = \"$mac\" ; ");
               $delete_h->execute();
               $insert_h = $dbh->prepare('INSERT IGNORE into network.swmacfilterlog (datefilt,operation,mac,vlan,swname,netid,comment) VALUES(?,?,?,?,?,?,?)');
               $insert_h->execute($datefilt,$op,$mac,$vlan,$swname,$netid,"cannot $op $mac, removing from swmacfilterQ");
               next;
            }
         }
         $session->command("conf t",1);
         $session->command("int $port",1);
         $session->command("no switchport port-security",1);
         $session->command("mac address-table static $mac vlan $vlan drop",1);
         $session->command("int $port",1);
         $session->command("switchport port-security",1);
         $session->command("end",1);
         $session->command("wr mem");
         ## check process success
         my $proc_ret = $session->command("show config | inc address-table static $mac vlan $vlan drop");
         foreach my $procln (@$proc_ret)  {
            if ($procln =~ /address-table static $mac vlan $vlan drop/)  {  $mac_found = 1; } 
            ##print "\$procln >$procln<      \$mac_found >$mac_found<\n";
         }
      }  ## if alreadyfiltered
   }  ## if ($ex) 
   ## vars for swmacfilterlog processing
   if ($alreadyfiltered == 0)  {
      my $dt = $filt_h->{$mac}->{"datefilt"};
      my $op = $filt_h->{$mac}->{"operation"};
      my $nt = $filt_h->{$mac}->{"netid"};
      my $cm = $filt_h->{$mac}->{"comment"};
      ## db process
      if ($mac_found == 1)  {
         print "Success filtering $mac on vlan $vlan, port $port\n";
         $all_log_h->{"$dt $op $mac $vlan $swname $nt $cm"} = 1;     ## set up for insert to swmacfilterlog
         if ($db)  {                 ## put data into swmacfilterslog and swmacfilters; clear Queue entry if needed
            $select_h = $dbh->prepare("SELECT * FROM network.swmacfilters WHERE mac = \"$mac\" and swname = \"$swname\" and vlan = \"$vlan\" LIMIT 1;  ");
            $select_h->execute();
            if ($select_h->rows == 0) { 
               $insert_h = $dbh->prepare('INSERT IGNORE into network.swmacfilters (mac,swname,vlan,datefilt) VALUES(?,?,?,?)');
               $insert_h->execute($mac,$swname,$vlan,$datefilt);
            }
            $select_h->finish;  ## need this to avoid "disconnect invalidates" trouble with $dbh->disconnect below outer loop
            if ($parm eq "Q")  {
               $delete_h = $dbh->prepare("DELETE FROM network.swmacfilterQ WHERE mac = \"$mac\" and operation = \"filter\"; ");
               $delete_h->execute();
            }
         }
      }
      if ($db)  {
         if ($mac_found == 0)  { 
            print "*** ERROR: No Return of filter success from 'show config' command.  filter $mac not processed to network.swmacfilters, not removed from network.swmacfilterQ\n";  
         }
      }
   }  ## if alreadyfiltered (second time)
}  ## foreach my mac

print "\n";
## filters only -- this avoids duplicates in swmacfilterlog --- unfilters inserted above
foreach my $ln (keys %$all_log_h)  {
   my ($dt,$tm,$op,$mac,$vlan,$swname,$nt,$cm) = split " ", $ln, 8; 
   my $dtflt = "$dt $tm";
   if ($db)  {
      $insert_h = $dbh->prepare('INSERT IGNORE into network.swmacfilterlog (datefilt,operation,mac,vlan,swname,netid,comment) VALUES (?,?,?,?,?,?,?)');
      $insert_h->execute($dtflt,$op,$mac,$vlan,$swname,$nt,$cm); 
   }
   ##printf "%-16s %-10s %-16 %-12 %-24s %-8s %-64s \n", $dt,$op,$mac,$vlan,$swname,$nt,$cm;
   print "swmacfilterlog: $dt  $op  $mac  $vlan  $swname  $nt  $cm\n";;
}

if ($ex)  { 
   if ($session)  { $session->command("exit"); }  
}
#$session->close();

exit;

###################################

sub unfilter_mac  {

   my $mac = shift;

   print "\n{unfilter_mac}: $mac\n";

   my $unfilterhash;
   my $lastreapmac;
   ## check for a very recent entry -- i.e., since the last switch config grab
   $select_h = $dbh->prepare("SELECT port,swname,vlan FROM arp.reapmac WHERE mac = \"$mac\" ORDER BY recent DESC LIMIT 1; ");
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      my $port    = $sel_ary->[0]->[0];
      my $swname  = $sel_ary->[0]->[1];
      my $vlan    = $sel_ary->[0]->[2];
      $lastreapmac = "$port $swname no mac address-table static $mac vlan $vlan drop";
      print "reapmac - unfilter_mac $mac  $swname  $vlan\n";
      ##push @{$unfilterhash->{$swname}}, "no mac address-table static $mac vlan $vlan drop";
      $unfilterhash->{$swname}->{"no mac address-table static $mac vlan $vlan drop"} = 1;
   }
   my $unfilts;
   my $swcfgpath = "$installpath/configs/switches";
   @$unfilts = `grep "address-table static $mac" $swcfgpath/*`;
   ## split up the unfilt lines by switch
   my $vlan;
   foreach my $unfilt (@$unfilts)  {
      chomp($unfilt);
      my ($swname,$rest) = split ":", $unfilt;
      $swname =~ s/$swcfgpath\///;
      ($swname,undef) = split /\./, $swname;
       if ($rest =~ /mac-address-table/)  {      ## one part label
          (undef,undef,undef,undef,$vlan,undef) = split " ", $rest;
       }
       if ($rest =~ /mac address-table/)  {      ## two part label
          (undef,undef,undef,undef,undef,$vlan,undef) = split " ", $rest;
       }
      ##push @{$unfilterhash->{$swname}}, "no mac address-table static $mac vlan $vlan drop";
      $unfilterhash->{$swname}->{"no mac address-table static $mac vlan $vlan drop"} = 1;
      print "grepcfg - unfilter_mac $mac  $swname  $vlan\n";
   }
   ## process unfilters by switch for multiples
   foreach my $swname (%$unfilterhash)  {
      if ($swname =~ /HASH/)  {  next;  }   ## this ignores a bad entry of ref(HASH) that gets appended somehow -- weird
      ## Connect
      if ($ex)  {
         $session = SshSwcon->new($swname);
         my $state = $session->connect();
         if ($state eq "notconnected")  {
            print "CONNECT ERROR: $swname - Session state = $state\n";
            exit;
         }
         my $ena_ret;
         if ($state ne "enabled")  {  $ena_ret = $session->enable();  }
         $session->command("terminal length 0",1);
         ##foreach my $cmd (@{$unfilterhash->{$swname}})  {
         foreach my $cmd ( keys %{$unfilterhash->{$swname}} )  {
            $session->command("conf t",1);
            $session->command("$cmd",1); 
            $cmd =~ s/drop//i;           ## second command sent processes old switches that don't like the 'drop"
            $session->command("$cmd",1); 
         }            
         $session->command("end",1);
         $session->command("wr mem");
         $session->command("exit",1);
         my $filtdb_h;
         ##foreach my $cmd (@{$unfilterhash->{$swname}})  {
         foreach my $cmd ( keys %{$unfilterhash->{$swname}} )  {
            (undef,undef,undef,undef,undef,undef,$vlan,undef) = split " ", $cmd;  ## cmd has a 'no' prefix, so vlan is one later  ;-P
            my $op = $filt_h->{$mac}->{"operation"};
            $filtdb_h->{"$op $mac $vlan $swname"} = 1;
         }
         while (my($x,$y) = each(%$filtdb_h))  {
            my ($op,$mac,$vlan,$swname) = split " ", $x;
            if ($db)  {                 ## put data into swmacfilterslog, remove from swmacfilters; clear entry from Queue if needed
               $insert_h = $dbh->prepare('INSERT IGNORE into network.swmacfilterlog (datefilt,operation,mac,vlan,swname,netid,comment) VALUES (?,?,?,?,?,?,?)');
               $insert_h->execute($filt_h->{$mac}->{"datefilt"},$op,$mac,$vlan,$swname,$filt_h->{$mac}->{"netid"},$filt_h->{$mac}->{"comment"});
               $delete_h = $dbh->prepare("DELETE FROM network.swmacfilters WHERE mac = \"$mac\"; ");
               $delete_h->execute();
               if ($parm eq "Q")  {
                  $delete_h = $dbh->prepare("DELETE FROM network.swmacfilterQ WHERE mac = \"$mac\" and operation = \"unfilter\"; ");
                  $delete_h->execute();
               }
            }
         }  ## while x,y
      }  ## if $ex
   }  ## foreach my $swname

return;

}  ## unfilter_mac

###################################

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

###################################


sub help  {

print<<EOF;

swmacfilter.pl - filtering/unfiltering macs directly on switches; also, process the swmacfilterQ 

syntax:  ./swmacfilter.pl  f <mac address> <opt>  Process filter from console
         ./swmacfilter.pl  u <mac address> <opt>  Process unfilter from console
         ./swmacfilter.pl  Q <opt>                Process the filter queue
         ./swmacfilter.pl  s                 Show the existing filters on the switch 

options:
p0    print only
-ex0  do not connect to switches
-db0  do not update databases
-pr0  do not print

EOF

}

#!/usr/bin/perl
## jackg@uic.edu
##
#  Does mac based filtering and unfiltering, either by using the network.macfilterQ 
#  table or by manually entering parameters in a situation that warrants manual action. 
#  Normally the filterQ table version will run on a cron and take 
#  care of all filter/unfilter needs.
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

require "$installpath/lib/servers.pl";
my $ipprefix1 = ipprefix1(); 
my $ipprefix2 = ipprefix2(); 
my $ipprefix3 = ipprefix3(); 
use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});
my ($insert_h,$update_h,$select_h);

## THIS FILE
my @fn = split /\//, $0;
my $thisfile = @fn[$#fn];
my ($thisfn,undef) = split /\./, $thisfile;

## control switches
my $ex = 1;      ## switch to turn on/off execution of config line processing (37/47)
my $db = 1;      ## switch to turn on/off writing to database (.filter)
my $pr = 1;      ## switch to turn on/off informational printing
##

my ($date,$time) = date_time();
my $datefilt = "$date $time";
my $dQ;  ## save this "incident time" entered in ARGV to replace $dateQ later 

if ($pr) { print "===== macfilter run: $datefilt\n"; }

## Deal with parms:
if (!@ARGV)  {  help();  exit;  }
if ( grep /-h/ , @ARGV )  {  help();  exit;  }
my $args;
@$args = @ARGV;
my $parm = $args->[0];
if ($parm eq "f")  { $parm = "filter";   }
if ($parm eq "u")  { $parm = "unfilter"; }
if ($parm eq "Q")  { $parm = "filterQ";  }
my $flags;                        ## array of args control flags
## check for incident timestamp override, i.e. manually set  dateQ
for (my $i = 0; $i <= $#$args; $i++ )  {
    if ($args->[$i] =~ /-dQ/)  {
       my $incident_time = $args->[$i];      
       $incident_time =~ s/-dQ//;
       if ($incident_time =~ /\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}/)  {  $dQ = $incident_time;  }  ## $dQ global from above
       if ($pr)  { print "incident time/dateQ override: $dQ\n"; } 
       push @$flags, $args->[$i];
       splice @$args, $i, 1;      ## remove from @args
    }
}
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
   print "macfilter.pl ";
   foreach my $arg (@$args)    {  print "$arg ";   }   print "\n";
   foreach my $flag (@$flags)  {  print "$flag ";  }   print "\n";
   print "\$ex = $ex ::  \$db = $db :: \$pr = $pr \n";
}

######################
######################

my $macathash;       ## macathash->{$mac}->{"dateQ"} = dateQ
                     ## macathash->{$mac}->{"fQln"}  = filterQln
                     ## macathash->{$mac}->{"atlns"}  = mac address-table line 
my $contexthash;     ## hash of mac -> context   as in: $contexthash{$mac}
my $macvlanhash;     ## key is "mac vlan";  value is "pub_ip priv_ip";
## these two are used to save filter process information for network.macfilterlog insert
my $filtermachash;   ## hash of mac address => "dateQ" to be filtered on 37 and 47
my $unfiltermachash; ## hash of mac address => "dateQ" to be unfiltered on 37 and 47
my $duplicate_addr;  ## hash of duplicates in network.macfilterQ - this is used to delete those entries at the end
## this one is used informationally, not processed:
my $filterlnhash;    ## hash of filter command strings keyed by mac addr --  $filterlnhash->{$mac} = $ln

my $wirelessvlanhash;  ## all the vlans in the wireless cloud
$select_h  = $dbh->prepare("SELECT vlan FROM network.vlanmap WHERE description = \"wireless\"; ");
$select_h->execute();
if ($select_h->rows != 0) {
   my $sel_ary = $select_h->fetchall_arrayref;
   foreach my $ln (@$sel_ary)  {
      my $vl = $ln->[0];
      ###push @{$filterlnhash->{$mac}}, "mac address-table static $mac vlan $vl drop";
      $wirelessvlanhash->{$vl} = 1;
   }
}


## macrover-generated filters - REVIEW AND EDIT
#
### End macrover direct filters

my ($of,$ofh);    ## output forensic file
## network.macfilterQ  processing:  address operation  user  number  comment 
if ($parm eq "filterQ")  {
   $of  = "/$installpath/forensic/$thisfn.fQ.out";   ## special file for Q runs
   $ofh = IO::File->new(">$of");
   my $select_h  = $dbh->prepare("SELECT * from network.macfilterQ");
   $select_h->execute();
   my $sel_ary = $select_h->fetchall_arrayref;
   if ($args->[1] eq "-s" || $args->[1] =~ /^sum/)  {
      ## display the filterQ and exit the program
      print "summary of network.macfilterQ lines:\n";     
      foreach my $rec (@$sel_ary)  {
         my ($addr,$oper,$dateQ,$who,$number,$comment) = @$rec;  
         print "$addr  $oper  $dateQ  $who  $number  $comment\n";  
      }
      exit;
   } 
   else  {
      foreach my $rec (@$sel_ary)  {
         my ($addr,$oper,$dateQ,$who,$number,$comment) = @$rec;  
         if ($pr)  { print "$addr  $oper  $dateQ  $who  $number  $comment\n";  }
         if ($dQ ne "")  { $dateQ = $dQ;  }
         my $sift = sift_address($addr);
         if ($sift)   {  my $proc_emsg = process($addr,$oper,$dateQ,$datefilt,$number,$who,$comment);  }
      }
   }
}
else  {
   $of  = "/$installpath/forensic/$thisfn.out";      ## generic file for all non-Q runs
   $ofh = IO::File->new(">$of");
}

if ($parm eq "filter")  {
   my $addr    = $args->[1];
   my $sift = sift_address($addr);
   if ($sift)  {
      my $argstr = join " ", @$args;
      my (undef,undef,$comment) = split " ", $argstr, 3;
      my $dateQ;
      if ($dQ ne "")  { $dateQ = $dQ;  }
      else   {   $dateQ = $datefilt; }
      my $oper = $parm;
      my $proc_emsg = process($addr,$oper,$dateQ,$datefilt,"0","manual",$comment);
   }
}

if ($parm eq "unfilter")  {
   my $addr    = $args->[1];
   my $sift = sift_address($addr);
   if ($sift)  {
      my $argstr = join " ", @$args;
      my (undef,undef,$comment) = split " ", $argstr, 3;
      my $dateQ;
      if ($dQ ne "")  { $dateQ = $dQ;  }
      else   {   $dateQ = $datefilt; }
      my $oper = $parm;
      my $proc_emsg = process($addr,$oper,$dateQ,$datefilt,"0","manual",$comment);
   }
}

if ($parm eq "query")  {
   my $addr = $args->[1];
   query_addr($addr);  
}



###### RESULTS ######

my $filterlines;     ## array of the filter command strings going to 37/47
foreach my $mac (sort keys %$filterlnhash)  {
   foreach my $ln ( @{$filterlnhash->{$mac}} )  {
      ## check for wireless and add all related filter lines
      print $ofh "$ln\n";
      my (undef,undef,undef,$m,undef,$v,undef) = split " ", $ln;
      print $ofh "mac >$m<   vlan  >$v<\n";
      if ($wirelessvlanhash->{$v} == 1)  {
         foreach my $vlkey (keys %$wirelessvlanhash)  {
            push @$filterlines, "mac address-table static $m vlan $vlkey drop"; 
         }
      }
      else  {  push @$filterlines, $ln;  }
   }
}

foreach my $ln (@$filterlines)  {  print $ofh "fl: $ln\n";  } 

require "$installpath/lib/filter_routers.pl";
my $router37 = router37();
my $router47 = router47();
my ($session47,$session37);
my ($lntot,$n);
if (!@$filterlines)    { $n = 0; }
else  { $n = scalar(@$filterlines); }
$lntot = $lntot + $n;
if (!$unfiltermachash)  {  $n = 0;  }
else  {  $n = keys %$unfiltermachash  }
$lntot = $lntot + $n;
if ($lntot > 0)  {
   $session37 = Sshcon->new("$router37");
   $session47 = Sshcon->new("$router47");
}

my $unfilterlines;   ## array of unfilter command strings going to 37/47
if ($unfiltermachash)  {                  ## if there's anything in the hash
   my $currentfilters;  ## hash, the key is a (unique-ified) filter line from 37/47 router configs, value = $mac
   my $ret37 = get_current_filters($session37);
   %$currentfilters = (%$ret37);
   my $ret47 = get_current_filters($session47);
   if (%$currentfilters)  {  %$currentfilters = (%$currentfilters,%$ret47);  }
   else   {  %$currentfilters = (%$ret47);  } 
   ## if (%$currentfilters)  {  foreach my $ln (sort keys %$currentfilters)  {  print "current_uf:  $ln\n"; }  }
   foreach my $mac (keys %$unfiltermachash)  {
      my $mf_found;      # flag
      while ( my($k,$v) = each(%$currentfilters) )  {        ## got them from the router address-table lines
         if ($v eq $mac)  {
            push @$unfilterlines, "no $k";
            $mf_found = 1;      ## found at least one existing filter for *this mac*
         }
      }
      ## if there are no %$currentfilters, this mac is either already unfiltered or was never filtered.
      ## we will create a placeholder @$unfilterlines entry for process futher below
      if ($mf_found == 0)  {
         push @$unfilterlines, "no mac address-table static $mac vlan 1 drop";  
         ## this does create a meaningless command on the router which will result in: "% No such MAC address entry exists"
         ## that will be ignored below while processing @$unfilterlines and the removal from network.macfilters will proceed 
      }
   }
}

#if ($pr)  {
#  foreach my $k (sort keys %$macvlanhash)     { print $ofh "macvlanhash:     $k => ", $macvlanhash->{$k}, "\n";     } 
#  foreach my $k (sort keys %$filtermachash)   { print $ofh "filtermachash:   $k => ", $filtermachash->{$k}, "\n";   } 
#  foreach my $k (sort keys %$unfiltermachash) { print $ofh "unfiltermachash: $k => ", $unfiltermachash->{$k}, "\n"; } 
#}

my $dbqueryhash;        ## hash ref where db query lines are the keys (for uniqueness) 
my $macfilters;         ## hash of filters to go in network.macfilters:  $macfilters->{"mac router vlan"}
my $wirelessflaghash;   ## have we seen an filterline for a wireless vlan yet?1
if ($lntot)  {
   ## process filter and unfilter lines into 37 and 47 configs and insert into database
   my @sessions = ($session47,$session37);
   foreach my $session (@sessions)  {
      if ($ex) {
         my $state = $session->connect;
         if ($state eq "connected")  { $session->enable(); }
         $session->command("conf t",1);
      }
      foreach my $ln (@$filterlines)  {
         if ($ex) {
            $session->command("$ln",1);
         }
         my(undef,undef,undef,$mac,undef,$vlan,undef) = split " ", $ln;
         my $context = $contexthash->{$mac} || "none" ;
         my($pub_ip,$priv_ip) = split " ", $macvlanhash->{"$mac $vlan"};
         if ($priv_ip eq "")  {  $priv_ip = "none";  }
         if ($pub_ip eq "")   {  $pub_ip = "none";  }
         my $addr    = $macathash->{$mac}->{"address"} || $mac;
         my $dateQ   = $macathash->{$mac}->{"dateQ"}   || $datefilt;
         my $num     = 0;
         my $who     = $macathash->{$mac}->{"who"}     || "none";
         my $comment = $macathash->{$mac}->{"comment"} || "misc filter";
         my $q; 
         if ($wirelessvlanhash->{$vlan} == 1)  {
            if (!exists $wirelessflaghash->{$mac})  {
               $wirelessflaghash->{$mac} = 1;   ## we found one - insert only one record
               $q = "INSERT into network.macfilterlog VALUES(\"$dateQ\",\"$datefilt\",\"filter\",\"mac\",\"$mac\",\"$pub_ip\",\"$priv_ip\",
                               \"wireless\",\"wireless\",\"$num\",\"$who\",\"$comment\"); ";
            }  ## else we do nothing, as only one record need be inserted
         }  
         else  {
            $q = "INSERT into network.macfilterlog VALUES(\"$dateQ\",\"$datefilt\",\"filter\",\"mac\",\"$mac\",\"$pub_ip\",\"$priv_ip\",
                            \"$vlan\",\"$context\",\"$num\",\"$who\",\"$comment\"); ";
         }                         
         $dbqueryhash->{$q} = 1;
         $q = "DELETE from network.macfilterQ where address = \"$addr\";  "; 
         $dbqueryhash->{$q} = 1;
         if ($pr) { print $ofh "Filter $dateQ,$datefilt,filter,mac,$mac,$pub_ip,$priv_ip,$vlan,$context,$num,$who,$comment\n"; }
         $macfilters->{"$mac 47 $vlan"} = "filter";
         $macfilters->{"$mac 37 $vlan"} = "filter";
      }
      foreach my $ln (@$unfilterlines)  {
         if ($ex) {
            $session->command("$ln",1);
         }
         my(undef,undef,undef,undef,$mac,undef,$vlan,undef) = split " ", $ln;
         my $context = $contexthash->{$mac} || "none";
         my($pub_ip,$priv_ip) = split " ", $macvlanhash->{"$mac $vlan"};
         if ($priv_ip eq "")  {  $priv_ip = "none";  }
         if ($pub_ip eq "")   {  $pub_ip = "none";  }
         my $addr    = $macathash->{$mac}->{"address"} || $mac;
         my $dateQ   = $macathash->{$mac}->{"dateQ"}   || $datefilt;
         my $num     = 0;
         my $who     = $macathash->{$mac}->{"who"}     || "none";
         my $comment = $macathash->{$mac}->{"comment"} || "misc unfilter";
         my $q; 
         ############ if ($contexthash->{$mac} eq "wireless")  {
         if ($wirelessvlanhash->{$vlan} == 1)  {
            if (!exists $wirelessflaghash->{$mac})  {
               $wirelessflaghash->{$mac} = 1;   ## we found one - insert only one record
               $q = "INSERT into network.macfilterlog VALUES(\"$dateQ\",\"$datefilt\",\"unfilter\",\"mac\",\"$mac\",\"$pub_ip\",\"$priv_ip\",
                               \"wireless\",\"$context\",\"$num\",\"$who\",\"$comment\"); ";
            }  ## else we do nothing, as only one record need be inserted
         }
         else  {
            $q = "INSERT into network.macfilterlog VALUES(\"$dateQ\",\"$datefilt\",\"unfilter\",\"mac\",\"$mac\",\"$pub_ip\",\"$priv_ip\",
                            \"$vlan\",\"$context\",\"$num\",\"$who\",\"$comment\"); ";
         }
         $dbqueryhash->{$q} = 1;
         $q = "DELETE from network.macfilterQ where address = \"$addr\";  "; 
         $dbqueryhash->{$q} = 1;
         ##if ($pr) { print $ofh "UNfilter $dateQ,$datefilt,unfilter,mac,$mac,$pub_ip,$priv_ip,$vlan,$context,$num,$who,$comment\n"; }
         $macfilters->{"$mac 47 $vlan"} = "unfilter";
         $macfilters->{"$mac 37 $vlan"} = "unfilter";
      }
      if ($ex) {
         $session->command("end",1);
         $session->command("wr mem",1);
         $session->close;
         $session37->close;
         $session47->close;
      }
   }
   ## process db queries - these are really inserts and deletes for network.macfilterQ and network.macfilter
   foreach my $query (keys %$dbqueryhash)  {
      ## if ($pr) { print $ofh "DB query: $query\n"; }
      if ($query eq "")  {  next; } 
      if ($db) {
         $insert_h  = $dbh->prepare($query);
         $insert_h->execute();
      }
   }
   ## process network.macfilters entries
   undef %$wirelessflaghash;    ## zero out the hash
   while (my($k,$v) = each(%$macfilters))  {
      my($mac,$router,$vlan) = split " ", $k;
      if ($v eq "filter")  {
         if ($wirelessvlanhash->{$vlan} == 1)  {
            if (!exists $wirelessflaghash->{"$mac $router"})  {
               $wirelessflaghash->{"$mac $router"} = 1;   ## we found one - insert only one record
               if ($db)  {
                  $insert_h = $dbh->prepare("INSERT IGNORE INTO network.macfilters VALUES (?,?,?);");
                  $insert_h->execute($mac,$router,"wireless"); 
               }
               if ($pr) { print $ofh "network.macfilters Insert $mac $router wireless\n"; }
            }  ## else we do nothing, as only one record need be inserted
         }
         else  {
            if ($db)  {
               $insert_h = $dbh->prepare("INSERT IGNORE INTO network.macfilters VALUES (?,?,?);");
               $insert_h->execute($mac,$router,$vlan); 
            }
            if ($pr) { print $ofh "network.macfilters Insert $mac $router $vlan\n"; }
         }
      }
      if ($v eq "unfilter")  {
         if ($db)  {
            my $delete_h = $dbh->prepare("DELETE FROM network.macfilters WHERE mac = ?;");
            $delete_h->execute($mac)  or print  "Something broke: " . $delete_h->errstr;
         }
         if ($pr) { print $ofh "network.macfilters Delete $mac $router $vlan\n"; }
      }
   }
}
###foreach my $mac (sort keys %$contexthash)  { print "$mac - ", $contexthash->{$mac}, "\n"; }

exit;

#####################################

sub process   {

   ## process *one* filter event

   use vars qw($operation $filttype $mac $pub_ip $priv_ip );

   my $addr     = shift;
   my $oper     = shift;
   my $dateQ    = shift;
   my $datefilt = shift;
   my $number   = shift;
   my $who      = shift;
   my $comment  = shift;
 
   if ($pr) { print "{process}: $addr,$oper,$dateQ,$datefilt,$number,$who,$comment\n"; }
 
   my $type;  ## mac or ip
   ## MAC ADDRESS process - mac is sent to sub process_mac_filter  (IPs processed inline below)
   if ($addr !~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)  {    ## not an ip
      $addr = fix_mac_address_format($addr);
   }
   if ($addr =~ /^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$/)  {
      ## it's a mac, so if it's a newer dateQ, we can log the unfilter $mac and move on
      my $mac = $addr;
      if ($macathash->{$mac}->{"dateQ"} gt $dateQ)  {
         $duplicate_addr->{$addr} = 1;  ## for deleting extra network.macfilterQ entry at the end
         return;  ## we already have a filterQ line with a newer dateQ, so do not process this older line
      } 
      if ($oper eq "unfilter")  {  
         $unfiltermachash->{$mac} = "$dateQ";
         my $query = "SELECT context FROM fw.arp WHERE mac = \"$mac\" ORDER BY recent DESC";
         $select_h  = $dbh->prepare($query);
         $select_h->execute();
         if ($select_h->rows != 0) {
            my $sel_ary = $select_h->fetchall_arrayref;
            my $context    = $sel_ary->[0]->[0];
            $contexthash->{$mac} = $context;
         }
         $macathash->{$mac}->{"dateQ"}    = $dateQ;
         $macathash->{$mac}->{"address"}  = $addr;
         $macathash->{$mac}->{"oper"}     = "unfilter";
         $macathash->{$mac}->{"who"}      = $who;
         $macathash->{$mac}->{"comment"}  = $comment;
         @{$macathash->{$mac}->{"fQln"}}  = ($mac,$oper,$dateQ,$number,$who,$comment);
         return;
      }
      ## process filter $mac normally
      if ($oper eq "filter")  {  
         process_mac_filter($mac,$oper,$dateQ,$datefilt,$number,$who,$comment);
         return;
      }
   }
   ## IP ADDRESS -- LAST FAIL CHECK
   if ($addr !~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)  {
      print "ATTENTION - NOT a MAC, NOT an IP - exiting...";
      exit;
   }
   ## END MAC ADDRESS Process

   ## IP ADDRESS processed here
   $type = "ip";
   if ($addr =~ /\A$ipprefix1|\A$ipprefix2|\A$ipprefix3/)  {  $pub_ip = $addr;  }
   else  {  $priv_ip = $addr;  }
   ## a Stubnet check on hospital, other Stubnets??   ## if $Stub...  ip filter on border??  

   ## VLAN - get all possible vlans for this ip address - push into @$vlan_ary
   my $vlan_ary;  
   my $query = "SELECT vlan from network.ipvlanmap where ip = \"$addr\"; ";
   ## this query can give multiple networks in a context. We will filter on all these networks
   $select_h  = $dbh->prepare($query);
   $select_h->execute();
   ## all rows as one array each:
   my $sel_ary = $select_h->fetchall_arrayref;
   foreach my $rec (@$sel_ary)  {  push @$vlan_ary, $rec->[0];  }      

   my $vlan_found;  ## in case we need a switchport check

   ## FW XLATE
   my ($xlbirth,$xlrecent,$context,$vlan);       ## global $priv_ip, $pub_ip                                                        
   $query = "SELECT * FROM fw.xlate where pub_ip=\"$addr\" OR priv_ip=\"$addr\"  AND birth < \"$dateQ\" ORDER BY recent desc;" ; 
   $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      ($xlbirth,$xlrecent,$priv_ip,$pub_ip,$context) = @{$sel_ary->[0]};  
   }  ## if select_h->rows
   if ($pr) { print "Post FW.XLATE:  pub_ip($pub_ip)  priv_ip($priv_ip)  context($context)  lease($xlbirth/$xlrecent)\n";  }

   ## FW.ARP  
   my ($abirth,$arecent,$arpip,$vlan);
   $query = "SELECT * from fw.arp  WHERE arpip=\"$priv_ip\" OR arpip = \"$addr\"  AND birth < \"$dateQ\" ORDER by recent desc; ";
   $select_h = $dbh->prepare($query);                                                                      
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      foreach my $row (@$sel_ary)  {    ## array of arrays
         ($abirth,$arecent,$arpip,$mac,$vlan,$context,undef) = @$row;
         $vlan_found = 1;
         ## check for record on same mac w/newer dateQ already processed
         if ($macathash->{$mac}->{"dateQ"} gt $dateQ)  {
            $duplicate_addr->{$addr} = 1;  ## for deleting extra network.macfilterQ entry at the end
            return;  ## we already have a filterQ line with a newer dateQ, so do not process this older line
         }
         if ( $dateQ gt $macathash->{$mac}->{"dateQ"} )  {
            $macathash->{$mac}->{"atlns"} = ();  ## clear older-dateQ-related lines, overwrite all else below
         }
         $contexthash->{$mac} = $context;
         foreach my $vlan (@$vlan_ary)  {
            if ($priv_ip ne "")  {   $macvlanhash->{"$mac $vlan"} = "$addr $priv_ip";  }
            else  {  $macvlanhash->{"$mac $vlan"} = "$addr $addr";  }
            $macathash->{$mac}->{"dateQ"}   = $dateQ;
            $macathash->{$mac}->{"address"}  = $addr;
            $macathash->{$mac}->{"who"}     = $who;
            $macathash->{$mac}->{"comment"} = $comment;
            @{$macathash->{$mac}->{"fQln"}} = ($addr,$oper,$dateQ,$number,$who,$comment);
            if ($oper eq "filter")  {
               push @{$filterlnhash->{$mac}}, "mac address-table static $mac vlan $vlan drop";
               push @{$macathash->{$mac}->{"atlns"}}, "mac address-table static $mac vlan $vlan drop";
               $filtermachash->{$mac} = "$dateQ";
               $macathash->{$mac}->{"oper"}  = "filter";
            }
            if ($oper eq "unfilter")  {
               $unfiltermachash->{$mac} = "$dateQ";
               $macathash->{$mac}->{"oper"}  = "unfilter";
            }
         }  ## foreach vlan
      }  ## foreach row
   }  ## if select_h->rows fw.arp         
   if ($pr) { print "Post FW.ARP:  priv_ip($priv_ip)  mac($mac)\n";  }

   ## RTR.ARP  (birth,recent,mac,ip,rtr,vlan,active)
   $query = "SELECT * from rtr.arp WHERE ip=\"$priv_ip\" AND birth < \"$dateQ\" ORDER BY recent desc; ";
   $select_h = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      my ($abirth,$arecent,$arpmac,$ip,$context,$vlan,undef) = @{$sel_ary->[0]};
      $vlan_found = 1;
      $mac = $arpmac;     ## global $mac
      ## check for record on same mac w/newer dateQ already processed
      if ($macathash->{$mac}->{"dateQ"} gt $dateQ)  {
         $duplicate_addr->{$addr} = 1;  ## for deleting extra network.macfilterQ entry at the end
         return;  ## we already have a filterQ line with a newer dateQ, so do not process this older line
      }
      if ( $dateQ gt $macathash->{$mac}->{"dateQ"} )  {
         $macathash->{$mac}->{"atlns"} = ();  ## clear older-dateQ-related lines, overwrite all else below
      }
      $contexthash->{$arpmac} = $context;
      ## we're not NATting on this box, so no need to scan grouped vlans
      $macvlanhash->{"$mac $vlan"}    = "$ip $ip"; 
      $macathash->{$mac}->{"dateQ"}   = $dateQ;
      $macathash->{$mac}->{"address"} = $addr;
      $macathash->{$mac}->{"who"}     = $who;
      $macathash->{$mac}->{"comment"} = $comment;
      @{$macathash->{$mac}->{"fQln"}} = ($addr,$oper,$dateQ,$number,$who,$comment);
      if ($oper eq "filter")  {
         push @{$filterlnhash->{$mac}}, "mac address-table static $mac vlan $vlan drop";
         push @{$macathash->{$mac}->{"atlns"}}, "mac address-table static $mac vlan $vlan drop";
         $filtermachash->{$mac} = "$dateQ";
         $macathash->{$mac}->{"oper"}  = "filter";
      }
      if ($oper eq "unfilter")  {
         $unfiltermachash->{$mac} = "$dateQ";
         $macathash->{$mac}->{"oper"}  = "unfilter";
      }
   }  ## if select_h->rows 
   if ($pr) { print "Post RTR.ARP:  priv_ip($priv_ip)   mac($mac)\n";  }
   
   ## ROUTER.ARP   
   my ($birth,$recent);
   ### if ($priv_ip eq "")  {
      my ($ip,$arpmac,$router,$vlan);
      my ($day,undef) = split " ", $dateQ;
      ## 2020-08-29 change - if recent has to be bigger, we lose filters where the client dropped 
      ## my $query = "SELECT * FROM router.arp WHERE ip = \"$addr\" AND (birth < \"$dateQ\" AND recent > \"$dateQ\");" ; 
      my $query = "SELECT * FROM router.arp WHERE ip = \"$addr\" AND birth < \"$dateQ\" ORDER BY recent desc; " ; 
      my $select_h  = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0) {
         my $sel_ary = $select_h->fetchall_arrayref;
         ($birth,$recent,$arpmac,$ip,$router,$vlan,undef) = @{$sel_ary->[0]};   
         $vlan_found = 1;
         $mac = $arpmac;    ## global $mac
         $priv_ip = $addr;  ## global $priv_ip
         if ($macathash->{$mac}->{"dateQ"} gt $dateQ)  {
            $duplicate_addr->{$addr} = 1;  ## for deleting extra network.macfilterQ entry at the end
            return;  ## we already have a filterQ line with a newer dateQ, so do not process this older line
         }
         if ($dateQ gt $macathash->{$mac}->{"dateQ"})  {
            $macathash->{$mac}->{"atlns"} = ();  ## clear older-dateQ-related lines, overwrite all else below
         }
         $macvlanhash->{"$mac $vlan"} = "$addr $addr";  ## no nat
         $contexthash->{$mac} = $router;
         $macathash->{$mac}->{"dateQ"} = $dateQ;
         $macathash->{$mac}->{"address"}  = $addr;
         $macathash->{$mac}->{"who"}     = $who;
         $macathash->{$mac}->{"comment"} = $comment;
         @{$macathash->{$mac}->{"fQln"}} = ($addr,$oper,$dateQ,$number,$who,$comment);
         if ($oper eq "filter")  {
            $macathash->{$mac}->{"oper"}  = "filter";
            push @{$filterlnhash->{$mac}}, "mac address-table static $mac vlan $vlan drop";
            push @{$macathash->{$mac}->{"atlns"}}, "mac address-table static $mac vlan $vlan drop";
            $filtermachash->{$mac} = "$dateQ";
         }
         if ($oper eq "unfilter")  {
            $macathash->{$mac}->{"oper"}  = "unfilter";
            $unfiltermachash->{$mac} = "$dateQ";
         }
      }  ## if $select_h->rows
      if ($pr) { print "Post ROUTER.ARP:  priv_ip($priv_ip)  mac($mac)  vlan($vlan)  time($birth/$recent)\n"; }

   ## NETWORK.STATICMAP info - find privip -- this spelling is only used here: that's what the table uses!!  8-}   D'oH!
   if ($priv_ip eq "")  {
      $query = "SELECT * from network.staticmap WHERE privip = \"$addr\" OR pubip = \"$addr\";" ;
      $select_h  = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0) {
         $vlan_found = 1;
         my $sel_ary  = $select_h->fetchall_arrayref;
         $priv_ip     = $sel_ary->[0]->[0];    ## global priv_ip
         $pub_ip      = $sel_ary->[0]->[1];    ## global pub_ip 
         my $vlan     = $sel_ary->[0]->[2];     
         my $context  = $sel_ary->[0]->[3];     
         if ($pr)  {  print "     staticNAT: $priv_ip = $pub_ip on vlan $vlan in $context\n"; }  
      }  ## if select_h->rows
      if ($pr) { print "Post NETWORK.STATICNAT:  addr($addr)  pub_ip($pub_ip)  priv_ip($priv_ip)  mac($mac) \n";  }
   }  ## if priv_ip
   else  {  if ($pr)  { print "     NETWORK.STATICNAT process not invoked\n"; }  } 

   ## NETWORK.FIXIES info - find mac from priv_ip
   ## If you made it here w/no info, also check original $addr
   my $assoc;
   if (($priv_ip ne "") && ($mac eq ""))  {      
      $select_h  = $dbh->prepare("SELECT mac from network.fixies WHERE ip = \"$priv_ip\" OR ip = \"$addr\";" );
      $select_h->execute();
      if ($select_h->rows != 0) {
         my $sel_ary = $select_h->fetchall_arrayref;
         $mac = $sel_ary->[0]->[0];      ## $mac is global
         ## check to see if the pub_ip of the moment matches the staticNAT
         $query = "SELECT pub_ip from fw.xlate WHERE priv_ip = \"$priv_ip\" AND birth <= \"$dateQ\" ORDER BY recent desc; ";
         $select_h  = $dbh->prepare($query);
         $select_h->execute();
         if ($select_h->rows != 0) {
            my $sel_ary = $select_h->fetchall_arrayref;
            my $xl_pub_ip  = $sel_ary->[0]->[0];
            if ($pr) { print "   xlate: $xl_pub_ip/$priv_ip   pub_ip/addr = $pub_ip\n"; }
            if ($xl_pub_ip eq $pub_ip)  {     ## you only want to process this if you're sill working the right pub_ip
               if ($macathash->{$mac}->{"dateQ"} gt $dateQ)  {
                  $duplicate_addr->{$addr} = 1;  ## for deleting extra network.macfilterQ entry at the end
                  return;  ## we already have a filterQ line with a newer dateQ, so do not process this older line
               }
               if ( $dateQ gt $macathash->{$mac}->{"dateQ"} )  {
                  $macathash->{$mac}->{"atlns"} = ();  ## clear older-dateQ-related lines, overwrite all else below
               }
               $macvlanhash->{"$mac $vlan"} = "$addr $priv_ip";
               $contexthash->{$mac} = $context;
               $macathash->{$mac}->{"dateQ"}   = $dateQ;
               $macathash->{$mac}->{"address"} = $addr;
               $macathash->{$mac}->{"who"}     = $who;
               $macathash->{$mac}->{"comment"} = $comment;
               @{$macathash->{$mac}->{"fQln"}} = ($addr,$oper,$dateQ,$number,$who,$comment);
               if ($oper eq "filter")  {
                  push @{$filterlnhash->{$mac}}, "mac address-table static $mac vlan $vlan drop";
                  $filtermachash->{$mac} = "$dateQ";
                  $macathash->{$mac}->{"oper"}    = "filter";
                  push @{$macathash->{$mac}->{"atlns"}}, "mac address-table static $mac vlan $vlan drop";
               }
               if ($oper eq "unfilter")  {
                  $unfiltermachash->{$mac} = "$dateQ";
                  $macathash->{$mac}->{"oper"} = "unfilter";
               }
            }  ## if xl_pub_ip
            else {           ## $xl_pub_ip NOT equal to $pub_ip/$addr
               if ($pr) {  print "   priv_ip is xlated to a different ip than the search target. Do not associate priv_ip mac for filter.\n";}
               $assoc = "***mac does not associate to \$pub_ip/\$addr";
               $priv_ip = "";
               $mac = "";
            }
         }  ## if slecet->rows
      }  ## if select_h->rows
      if ($pr) { print "Post NETWORK.FIXIES: priv_ip($priv_ip)  mac($mac) $assoc\n";  }
   }  ## if mac eq ""
   else  {  if ($pr)  { print "     NETWORK.FIXIES process not invoked\n"; }  } 

   ## DHCP 
   ## network.last_dhcp  
   if (($priv_ip ne "") && ($mac eq ""))  {     
      $query = "SELECT mac from network.last_dhcp WHERE ip=\"$priv_ip\" AND tstamp <= \"$dateQ\" ORDER BY recent desc; ";
   }
   elsif ($priv_ip eq "")  {  
      $query = "SELECT mac,ip from network.last_dhcp WHERE ip=\"$addr\" AND tstamp <= \"$dateQ\" ORDER BY recent desc; ";
   }
   else  {  return;  }   ## you got nuthin', bub...
   $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      $mac        = $sel_ary->[0]->[0];
      my $dhcp_ip = $sel_ary->[0]->[1];
      ## check to see if the pub_ip of the moment matches the staticNAT
      $query = "SELECT pub_ip from fw.xlate WHERE priv_ip = \"$dhcp_ip\" AND birth <= \"$dateQ\" ORDER BY recent desc; ";
      $select_h  = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0) {
         my $sel_ary = $select_h->fetchall_arrayref;
         my $xl_pub_ip = $sel_ary->[0]->[0];  
         if ($pr) { print "   xlate: $xl_pub_ip/$dhcp_ip   pub_ip/addr = $pub_ip\n"; }
         if ($xl_pub_ip eq $pub_ip)  {     ## you only want to process this if you're sill working the right pub_ip
            if ($priv_ip eq "")  {  $priv_ip = $dhcp_ip;  }
            if ($macathash->{$mac}->{"dateQ"} gt $dateQ)  {   ## we have *something*  ;)
               $duplicate_addr->{$addr} = 1;  ## for deleting extra network.macfilterQ entry at the end
               return;  ## we already have a filterQ line with a newer dateQ, so do not process this older line
            }
            if ( $dateQ gt $macathash->{$mac}->{"dateQ"} )  {
               $macathash->{$mac}->{"atlns"} = ();  ## clear older-dateQ-related lines, overwrite all else below
            }
            $select_h  = $dbh->prepare("SELECT vlan from network.ipvlanmap where ip = \"$addr\"; ");
            $select_h->execute();
            if ($select_h->rows != 0) {
               my $sel_ary = $select_h->fetchall_arrayref;
               my $vlan = $sel_ary->[0]->[0];
               $vlan_found = 1;
            }
            if ($pr)  { print "dhcp lease check: $mac $vlan = $pub_ip $addr\n"; } 
            $macvlanhash->{"$mac $vlan"} = "$pub_ip $addr";
            $contexthash->{$mac} = $context;
            $macathash->{$mac}->{"dateQ"}   = $dateQ;
            $macathash->{$mac}->{"address"} = $addr;
            $macathash->{$mac}->{"who"}     = $who;
            $macathash->{$mac}->{"comment"} = $comment;
            @{$macathash->{$mac}->{"fQln"}} = ($addr,$oper,$dateQ,$number,$who,$comment);
            if ($oper eq "filter")  {
               push @{$filterlnhash->{$mac}}, "mac address-table static $mac vlan $vlan drop";
               #if ($pr)  { print "   fw.dhcp bottom:  filterlnhash->{mac} = >", @{$filterlnhash->{$mac}} , "<\n";  }
               $filtermachash->{$mac} = "$dateQ";
               $macathash->{$mac}->{"oper"}    = "filter";
               push @{$macathash->{$mac}->{"atlns"}}, "mac address-table static $mac vlan $vlan drop";
            }
            if ($oper eq "unfilter")  {
               $unfiltermachash->{$mac} = "$dateQ";
               $macathash->{$mac}->{"oper"} = "unfilter";
               #if ($pr)  { print "   fw.dhcp bottom: unfilter $mac $dateQ\n";  }
            }
         }  ## if xl_pub_ip
         else {           ## $xl_pub_ip NOT equal to $pub_ip/$addr
            if ($pr) {  print "   priv_ip is xlated to a different ip than the search target. Do not associate priv_ip mac for filter.\n";}
            $assoc = "***mac does not associate to \$pub_ip/\$addr";
            $priv_ip = "";
            $mac = "";
         }
      }  ## if select_h->rows
      if ($pr) { print "Post Second FW.DHCP: priv_ip($priv_ip)  mac($mac) $assoc\n";  }
   }  ## if select_h->rows
   else  {  if ($pr)  { print "     Second FW.DHCP process not invoked\n"; }  } 

   if ($priv_ip eq "")     { if ($pr) { print "priv_ip for $addr not found\n"; } }
   if ($mac     eq "")     { if ($pr) { print "mac     for $addr not found\n"; } }
   if ($vlan_found eq "")  { if ($pr) { print "NO vlan_found for $addr - check switch.mac\n"; } }

   return;
} ## process

#####################################

sub process_mac_filter  {

   my $mac      = shift;
   my $oper     = shift;
   my $dateQ    = shift;
   my $datefilt = shift;
   my $number   = shift;
   my $who      = shift;
   my $comment  = shift;

   print $ofh "{process_mac_filter}: $mac,$oper,$dateQ,$number,$who,$comment\n";

   ## We'll make a filter line for the most recent vlan from any of the standard sources
   ## and add that line to mac address table on 37/47 - saves work for macrover later  
   if ($macathash->{$mac}->{"dateQ"} gt $dateQ)  {
      $duplicate_addr->{$mac} = 1;  ## for deleting extra network.macfilterQ entry at the end, here $mac = $addr from start
      return;  ## we already have a filterQ line with a newer dateQ, so do not process this older line
   } 
   if ( $dateQ gt $macathash->{$mac}->{"dateQ"} )  {
      $macathash->{$mac}->{"atlns"} = ();  ## clear older-dateQ-related lines, overwrite all else below
   }
   my ($ip,$vlan,$context,$pub_ip);

   ## FW/ASA - fw.arp
   my $query = "SELECT arpip,context from fw.arp WHERE mac = \"$mac\" AND birth <= \"$dateQ\" ORDER by recent desc; ";
   $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      $ip         = $sel_ary->[0]->[0];
      $context    = $sel_ary->[0]->[1];
      $select_h  = $dbh->prepare("SELECT vlan FROM network.ipvlanmap WHERE ip = \"$ip\"; ");
      $select_h->execute();
      if ($select_h->rows != 0) {
         $sel_ary = $select_h->fetchall_arrayref;
         $vlan = $sel_ary->[0]->[0];
      } 
      push @{$filterlnhash->{$mac}}, "mac address-table static $mac vlan $vlan drop";
      $query = "SELECT pub_ip FROM fw.xlate WHERE priv_ip = \"$ip\" AND birth <= \"$dateQ\" AND recent >= \"$dateQ\"; ";
      $select_h  = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0) {
         $sel_ary = $select_h->fetchall_arrayref;
         $pub_ip = $sel_ary->[0]->[0];
      }
      else  { $pub_ip = $ip; }  ## not really needed, but fills gap
      $macvlanhash->{"$mac $vlan"} = "$pub_ip $ip";
      $contexthash->{$mac} = $context;
      $filtermachash->{$mac} = "$dateQ";
      $macathash->{$mac}->{"dateQ"} = $dateQ;
      $macathash->{$mac}->{"address"}  = $mac;
      $macathash->{$mac}->{"oper"}  = "filter";
      $macathash->{$mac}->{"who"}     = $who;
      $macathash->{$mac}->{"comment"} = $comment;
      @{$macathash->{$mac}->{"fQln"}} = ($mac,$oper,$dateQ,$number,$who,$comment);
      push @{$macathash->{$mac}->{"atlns"}}, "mac address-table static $mac vlan $vlan drop";
   }
   if ($pr) { print "Post FW.ARP: mac($mac)  arpip($ip)  pub_ip($pub_ip)  vlan($vlan)\n"; }

   ## ROUTER.ARP - new table 2020-03-05 or so
   if (($ip eq "") && ($vlan eq ""))  {
      $query = "SELECT ip,vlan,router from router.arp where mac = \"$mac\" AND birth <= \"$dateQ\" ORDER BY recent desc ; ";
      $select_h  = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0) {
         my $sel_ary = $select_h->fetchall_arrayref;
         $ip      = $sel_ary->[0]->[0];
         $vlan    = $sel_ary->[0]->[1];
         $context = $sel_ary->[0]->[2];  ## it's 'router' in this table, but it's 'context' in this code
         $macvlanhash->{"$mac $vlan"} = "$ip $ip";   ## routers don't NAT
         $contexthash->{$mac} = $context;
         push @{$filterlnhash->{$mac}}, "mac address-table static $mac vlan $vlan drop";
         $filtermachash->{$mac} = "$dateQ";
         $macathash->{$mac}->{"dateQ"} = $dateQ;
         $macathash->{$mac}->{"address"}  = $mac;
         $macathash->{$mac}->{"oper"}  = "filter";
         $macathash->{$mac}->{"who"}     = $who;
         $macathash->{$mac}->{"comment"} = $comment;
         @{$macathash->{$mac}->{"fQln"}} = ($mac,$oper,$dateQ,$number,$who,$comment);
         push @{$macathash->{$mac}->{"atlns"}}, "mac address-table static $mac vlan $vlan drop";
      }
      if ($pr) { print "Post ROUTER.ARP: mac($mac)  ip($ip)  vlan($vlan)\n"; }
   }
   else  {  if ($pr)  { print "     ROUTER.ARP process not invoked\n"; }  }

   ## RTR.ARP  (birth,recent,mac,ip,rtr,vlan,active)
   if (($ip eq "") && ($vlan eq ""))  {
      $query = "SELECT * from rtr.arp WHERE mac=\"$mac\" AND birth < \"$dateQ\" ORDER BY recent desc; ";
      $select_h = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0) {
         my $sel_ary = $select_h->fetchall_arrayref;
         my ($abirth,$arecent,$arpmac,$arpip,$context,$Rvlan,undef) = @{$sel_ary->[0]};
         $ip   = $arpip;
         $vlan = $Rvlan;
         $macvlanhash->{"$mac $vlan"}    = "$ip $ip";
         $contexthash->{$mac} = $context;
         $macathash->{$mac}->{"dateQ"}   = $dateQ;
         $macathash->{$mac}->{"address"} = $mac;
         $macathash->{$mac}->{"who"}     = $who;
         $macathash->{$mac}->{"comment"} = $comment;
         @{$macathash->{$mac}->{"fQln"}} = ($mac,$oper,$dateQ,$number,$who,$comment);
         if ($oper eq "filter")  {
            push @{$filterlnhash->{$mac}}, "mac address-table static $mac vlan $vlan drop";
            push @{$macathash->{$mac}->{"atlns"}}, "mac address-table static $mac vlan $vlan drop";
            $filtermachash->{$mac} = "$dateQ";
            $macathash->{$mac}->{"oper"}  = "filter";
         }
         if ($oper eq "unfilter")  {
            $unfiltermachash->{$mac} = "$dateQ";
            $macathash->{$mac}->{"oper"}  = "unfilter";
         }
      }  ## if select_h->rows
      if ($pr) { print "Post RTR.ARP:  mac($mac)  ip($ip)  vlan($vlan)\n";  }
   }  ## if $ip eq "" &&            ## RTR.ARP
   else  {  if ($pr)  { print "     RTR.ARP process not invoked\n"; }  }


   ## DHCP table check - network.last_dhcp 
   if (($ip eq "") && ($vlan eq ""))  {
      $query = "SELECT ip FROM network.last_dhcp WHERE mac = \"$mac\" AND tstamp <= \"$dateQ\" ORDER BY tstamp desc; ";
      $select_h  = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0) {
         my $sel_ary = $select_h->fetchall_arrayref;
         my $ip = $sel_ary->[0]->[1];
         $query = "SELECT pub_ip from fw.xlate WHERE priv_ip = \"$ip\" and birth <= \"$dateQ\" and recent >= \"$dateQ\"; ";
         $select_h  = $dbh->prepare($query);
         $select_h->execute();
         my $sel_ary = $select_h->fetchall_arrayref; 
         $pub_ip  = $sel_ary->[0]->[0]; 
         if ($pub_ip eq "")  {  $pub_ip = $ip;  }
         $macvlanhash->{"$mac $vlan"} = "$pub_ip $ip";
         $contexthash->{$mac} = $context;
         $filtermachash->{$mac} = "$dateQ";
         $macathash->{$mac}->{"dateQ"} = $dateQ;
         $macathash->{$mac}->{"address"}  = $mac;
         $macathash->{$mac}->{"oper"}  = "filter";
         $macathash->{$mac}->{"who"}     = $who;
         $macathash->{$mac}->{"comment"} = $comment;
         @{$macathash->{$mac}->{"fQln"}} = ($mac,$oper,$dateQ,$number,$who,$comment);
         $query = "SELECT vlan from network.ipvlanmap where ip = \"$ip\"; ";
         $select_h  = $dbh->prepare($query); 
         $select_h->execute();
         if ($select_h->rows != 0) {
            my $sel_ary = $select_h->fetchall_arrayref;
            $vlan = $sel_ary->[0]->[0];
            push @{$filterlnhash->{$mac}}, "mac address-table static $mac vlan $vlan drop";
            push @{$macathash->{$mac}->{"atlns"}}, "mac address-table static $mac vlan $vlan drop";
         }
      }
      if ($pr) { print "Post FW.DHCP: mac($mac)  ip($ip)  pub_ip($pub_ip)  vlan($vlan)\n"; }
   }
   else  {  if ($pr)  { print "     FW.DHCP process not invoked\n"; }  }

   if ($vlan eq "")  {
   #if (($ip eq "") && ($vlan eq ""))  {
      $query = "SELECT vlan from switch.mac WHERE mac=\"$mac\" order by recent desc; ";
      $select_h = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0) {
         my $sel_ary = $select_h->fetchall_arrayref;
         $vlan = $sel_ary->[0]->[0];
         push @{$filterlnhash->{$mac}}, "mac address-table static $mac vlan $vlan drop";
         push @{$macathash->{$mac}->{"atlns"}}, "mac address-table static $mac vlan $vlan drop";
      }
   }

   if ($vlan eq "")  { if ($pr) { print "vlan    for $mac not found\n"; } }

   ## If we can't find data on this mac, we force filter it on vlan 1 and let rover work other vlans
   if (not exists $filterlnhash->{$mac})  {
      if ($pr)  {  print "Force Filter on vlan 1 mac $mac\n";  }
      push @{$filterlnhash->{$mac}}, "mac address-table static $mac vlan 1 drop";
      $filtermachash->{$mac} = "$dateQ";
      $macathash->{$mac}->{"dateQ"} = $dateQ;
      $macathash->{$mac}->{"address"}  = $mac;
      $macathash->{$mac}->{"oper"}  = "filter";
      $macathash->{$mac}->{"who"}     = $who;
      $macathash->{$mac}->{"comment"} = $comment;
      @{$macathash->{$mac}->{"fQln"}} = ($mac,$oper,$dateQ,$number,$who,$comment);
      push @{$macathash->{$mac}->{"atlns"}}, "mac address-table static $mac vlan 1 drop";
   }
   if ($pr) {     ## TEST
      foreach my $c (keys %$contexthash) { print "$c >", $contexthash->{$c}, "< \n"; }
   }

   return;
}  ## process_mac_filter

#####################################

sub get_current_filters  {

   my $session = shift;
    
   my $retlns;  ## hash where the keys are returned mac filter lines
   my $state = $session->connect;
   if ($state eq "connected")  { $session->enable(); }
   $session->command("term len 0",2);
   my $cmd_ret = $session->command("sh conf | i mac address-table static");
   foreach my $ln (@$cmd_ret)  {
      chomp($ln);
      if ($ln =~ /^mac address-table static/)  {  
         my(undef,undef,undef,$mac,undef) = split " ", $ln, 5;   ## it's possible in future to check if last var eq "drop"
         $retlns->{$ln} = $mac;
      }
   } 
   $session->close();
   return($retlns);

}  ## get_current_filters

#####################################

sub query_addr   {

   my $addr = shift;

   require "$installpath/lib/filter_routers.pl";
   my $router37 = router37();
   my $router47 = router47();
   my ($session47,$session37,$state,$cmd_ret);
   $session47 = Sshcon->new("$router47");
   $state = $session47->connect;
   if ($state eq "connected")  { $session47->enable(); }
   $session47->command("term len 0",1);
   $cmd_ret = $session47->command("sh conf | inc mac address-table static $addr",5);

   $session37 = Sshcon->new("$router37");
   $state = $session37->connect;
   if ($state eq "connected")  { $session37->enable(); }
   $session37->command("term len 0",1);
   $cmd_ret = $session37->command("sh conf | inc mac address-table static $addr",5);

   $session47->close;
   $session37->close;
   print "\n";  
 
   return;   

}  ## query_addr

#####################################

sub sift_address  {

   my $addr = shift;

   if ($addr =~ /0008\.a4/i || $addr eq "")  {
      print "Cisco internal, bad or blank address: >$addr<\n";
      ## cisco internal or blank
      my $delete_h  = $dbh->prepare("DELETE * from network.macfilterQ where address = \"$addr\"; ");
      $delete_h->execute();
      return(0);
   }
   return(1);
}

#####################################

sub fix_mac_address_format  {

  my $addr  = shift;

  $addr = lc($addr);   ## in case Dave typed in a mac addr  ;->
  $addr =~ s/\.//g;
  $addr =~ s/\://g;
  $addr =~ s/\-//g;
  my $aa = substr($addr,0,4);
  my $bb = substr($addr,4,4);
  my $cc = substr($addr,8,4);
  $addr = "$aa.$bb.$cc";
  return($addr);

} ## fix_mac_address_format

#####################################

sub date_time  {

   ## Returns string with Date and Time as mm/dd/yy hh/mm/ss"
   my ($sec,$min,$hour,$mday,$mon,$year,undef,undef,undef) = localtime(time);
   $mon += 1;
   if ($mon  < 10) { $mon  = "0"."$mon"; }
   if ($mday < 10) { $mday = "0"."$mday"; }
   # Y2K fix:
   my $yr=1900+$year;
   my $date = "$yr-$mon-$mday";
   if ( $hour < 10 )  { $hour = "0"."$hour"; }
   if ( $min  < 10 )  { $min  = "0"."$min"; }
   if ( $sec  < 10 )  { $sec  = "0"."$sec"; }
   my $time = "$hour:$min:$sec";

   return($date,$time);

}  ## date_time

###################################################

sub help {

  print <<EOF;

  macfilter.pl

  Does mac based filtering and unfiltering, either by using the network.macfilterQ 
  table or by manually entering parameters in a situation that warrants manual action.  
  Normally the filterQ table version will run on a cron and take care of all filter/unfilter needs.

  === Syntax ===

  Process filterQ table:                        macfilter.pl filterQ

  Print only a summary of table process data:   macfilter.pl filterQ -s
                                          or:   macfilter.pl filterQ summary

  Manual filter:   sudo macfilter.pl <operation> <address>    [<comment> optional]

  * must be run as sudo
  address can be mac, public ip or private ip
  operation shorthand:
     f = filter
     u = unfilter
     Q = filterQ
  example: macfilter.pl u 1234.4567.9876
           macfilter.pl f 131.193.178.43
           macfilter.pl Q    

  Processing Overrides - any of these manual run control signals can be used to test or selectively process:

     -dQ<timestamp formatted incident time>   This is the most important of the overrides.
        This override sets the incident time, processed and recorded as the \$dateQ which controls all searches
        related to birth/recent restrictions, which is pretty much all of them.
        Timestamp must be connected to '-dQ' with no spaces between.

        example: ./macfilter.pl f  131.193.82.24 -dQ2020-03-22_12:12:12 p0 


     p0   = Print Only - overrides all below: will not process network device execution or database execution
            example:  ./macfilter.pl u 131.193.177.100 -dQ2020-03-22_12:12:12 p0

     -ex0 = turn off all processing of network devices (routers, FWs, ASAs, etc.)

     -db0 = turn off all database processing

     -pr0 = turn off printing of process progress

        example: ./macfilter.pl u 1234.2345.abcd -dQ2020-03-22_12:12:12 -ex0 -db0      this is the same as:  ./macfilter.pl u 1234.2345.abcd p0 

        example: ./macfilter.pl u 1234.2345.abcd -dQ2020-03-22_12:12:12 -pr0    process devices and database, but don't print on screen (very rare) 


EOF
  print "\n";

#}  ## else
}  ## help

####################################################


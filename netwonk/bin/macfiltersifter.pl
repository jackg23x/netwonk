#!/usr/bin/perl
## jackg@uic.edu
##
## macfiltersifter.pl
## script to sync macfilter lists on routers (37 and 47 as of 2020-12-11)
## part of the whole rover suite
## world database tables:
## - network.macfilters 
##
##

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use lib "$installpath/lib";
use Sshcon;
use strict;

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});
my ($insert_h,$update_h,$select_h,$delete_h);

## THIS FILE
my @fn = split /\//, $0;
my $thisfile = @fn[$#fn];
my ($thisfn,undef) = split /\./, $thisfile;

##my $of  = "/$installpath/forensic/$thisfn.out";      
##my $ofh = IO::File->new(">$of");

## control switches
my $ex = 1;      ## switch to turn on/off execution of config line processing (37/47)
my $db = 1;      ## switch to turn on/off writing to database (network.macfilter)
my $pr = 1;      ## switch to turn on/off informational printing
##

my ($date,$time) = date_time();
my $dateQ = "$date $time";

##if ($pr) { print $ofh "===== running siftmacfilters on filtering routers: \$dateQ\n"; }

## Deal with parms:
if ( grep /-h|help/ , @ARGV )  {  help();  exit;  }
my $args;
@$args = @ARGV;

my $flags;                   ## array of args control flags
## check for print-only override
my $p0;
for (my $i = 0; $i <= $#$args; $i++ )  {
    if ($args->[$i] =~ /p0/)  {
       $p0 = 1; $pr = 1; $ex = 1; $db = 0;  ## print Only Override - you still need to connect to get list
       push @$flags, $args->[$i];
       splice @$args, $i, 1;      ## remove from @args
    }
}
if ($pr) {
   print "siftmacfilters.pl ";
   foreach my $arg (@$args)    {  print "$arg ";   }   print "\n";
   foreach my $flag (@$flags)  {  print "$flag ";  }   print "\n";
   print "\$ex = $ex ::  \$db = $db :: \$pr = $pr \n";
}

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

my $session;
require "$installpath/lib/filter_routers.pl";
use vars qw(%filter_routers);
## set up router hash w/key=rname
my $router_h; 
while (my($rip,$rname) = each(%filter_routers))   {  $router_h->{$rname} = $rip;  }
## filters currently on the routers
my $all_filts_h;  ## filters by mac; value is an array of "$rname $vlan" elements
my $filt_h;       ## filters sub-grouped by router 
while (my($rip,$rname) = each(%filter_routers))  {
   ## Connect
   $session = Sshcon->new($rip);
   my $state = $session->connect();
   if ($state eq "notconnected")  {
      print "CONNECT ERROR: $rname $rip - Session state = $state\n";
      exit;
   }
   my $ena_ret;
   if ($state ne "enabled")   {  $ena_ret = $session->enable();  }
   $session->command("terminal length 0");
   my @ret = $session->command("sh conf  | inc mac address-table static");
   foreach my $r (@ret)  {
      foreach my $filt (@$r)  {
         if ($filt =~ /^\s*!/)  {  next;  }   ## dump comments
         if ($filt =~ /[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}/)  {
            ## mac address-table static 000e.8e88.6a29 vlan 1 drop
            my (undef,undef,undef,$mac,undef,$vlan,undef) = split " ", $filt;
            $filt_h->{$rname}->{"$mac $vlan"} = 1;
            push @{$all_filts_h->{$mac}}, "$rname $vlan";
         }
      }
   }
}

## for every filter in all_filts_h, make sure it's on *each* of the routers via $filt->{$rname}
my $add_filters_to_routers_h;     ## key is $rname, value is array of command lines applying mac address filters
foreach my $mac (keys %$all_filts_h)  {
   foreach my $rv (@{$all_filts_h->{$mac}})  {
      my (undef,$vlan) = split " ", $rv;        ## grab the vlan for the existing entry, to check for a missing an entry
      foreach my $rname (keys %$filt_h)  {
         if (!exists $filt_h->{$rname}->{"$mac $vlan"})  {                    ## filter is missing on one of the routers
            push @{$add_filters_to_routers_h->{$rname}}, "mac address-table static $mac vlan $vlan drop";
            ##print $ofh "filter >mac address-table static $mac vlan $vlan drop< missing on router $rname\n";
         }
      }
   }
}
## add these filter fixes to the routers 
foreach my $rname (keys %$add_filters_to_routers_h)  {
   my $rip = $router_h->{$rname};
   $session = Sshcon->new($rip);
   my $state = $session->connect();
   if ($state eq "notconnected")  {
      print "CONNECT ERROR: $rname $rip - Session state = $state\n";
      exit;
   }
   ### Don't need to enable -- these come up enabled
   $session->command("terminal length 0");
   $session->command("conf t");
   foreach my $cmd ( @{$add_filters_to_routers_h->{$rname}} )  {
      $session->command("$cmd");
      my (undef,undef,undef,$mac,undef,$vlan,undef) = split " ", $cmd;
      push @{$all_filts_h->{$mac}}, "$rname $vlan";
   }    
   $session->command("end");
   $session->command("write mem");
   $session->command("exit");
}

## network.macfilters
my $macfilts_h;   ## array ref - form of data in network.macfilters, including "wireless" notation
foreach my $mac (keys %$all_filts_h)  {
   foreach my $rnvl (@{$all_filts_h->{$mac}})  {
      if ($mac =~ /[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}/)  {
         my ($rname,$vlan) = split " ", $rnvl;
         if ($wirelessvlanhash->{$vlan} == 1)  {  $macfilts_h->{"$mac $rname wireless"} = 1;  }     
         else                                  {  $macfilts_h->{"$mac $rname $vlan"} = 1;     }
      }
   }
}
if ($db)  {
   my $delete_h = $dbh->prepare("DELETE FROM network.macfilters;");
   $delete_h->execute() or print "Something broke on network.macfilters delete: " . $delete_h->errstr;
}
foreach my $mfilt (sort keys %$macfilts_h)  {
   my ($mac,$rname,$vlan) = split " ", $mfilt;
   ## if ($pr)  {  print $ofh "network.macfilters:  $mac  $rname  $vlan\n";  }
   if ($db)  {
      $insert_h = $dbh->prepare('INSERT IGNORE INTO network.macfilters (mac,router,vlan) VALUES (?,?,?)');
      $insert_h->execute($mac,$rname,$vlan);
   }   
}

##foreach my $rname (keys %$filt_h)  {
##   print $ofh "Router: $rname\n";
##   foreach my $filt ( keys %{$filt_h->{$rname}} )  {  print $ofh "$filt\n";  }
##}

$dbh->disconnect();
$session->close();

exit;

##################

sub help  {

print<<EOF;

macfiltersifter.pl - check, compare and sync rover info with router info and network.macfilters, update world db table network.macfilters

syntax:  ./macfiltersifter.pl  
option:  ./macfiltersifter.pl -p0   Print only, do not affect database


EOF

}

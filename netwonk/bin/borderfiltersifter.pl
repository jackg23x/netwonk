#!/usr/bin/perl
## jackg@uic.edu
##
## script to sync border-host-filter lists on border routers (51 and 61 as of 2020-12-11)
## world database tables:
## - network.borderfilters 
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

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});
my ($insert_h,$update_h,$select_h,$delete_h);

## control switches
my $ex = 1;      ## switch to turn on/off execution of config line processing (37/47)
my $db = 1;      ## switch to turn on/off writing to database (network.borderfilter)
my $pr = 1;      ## switch to turn on/off informational printing
##

my ($date,$time) = date_time();
my $dateQ = "$date $time";

if ($pr) { print "===== running bsift on border routers: \$dateQ\n"; }

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
   print "bsift.pl ";
   foreach my $arg (@$args)    {  print "$arg ";   }   print "\n";
   foreach my $flag (@$flags)  {  print "$flag ";  }   print "\n";
   print "\$ex = $ex ::  \$db = $db :: \$pr = $pr \n";
}

require "$installpath/lib/border_routers.pl";
use vars qw(%border_routers);
my $session;
my $all_filts_h;  ## filts by ip
my $filt_h;       ## filts sub-grouped by router 
while (my($rip,$rname) = each(%border_routers)) {
   ## Connect
   $session = Sshcon->new($rip);
   my $state = $session->connect();
   if ($state eq "notconnected")  {
      print "CONNECT ERROR: $rname $rip - Session state = $state\n";
      exit;
   }
   $session->command("terminal length 0");
   my @ret = $session->command("sh conf running-config object-group network ipv4 border-host-filter");
   foreach my $r (@ret)  {
      foreach my $filt (@$r)  {
         if ($filt =~ /^\s*!/)  {  next;  }   ## dump comments
         if ($filt =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)  {
            $filt =~ s/host //;
            $filt =~ s/\s+//g;
            $filt_h->{$rname}->{$filt} = 1;
            $all_filts_h->{$filt} = 1;
         }
      }
   }
}

print "#####\n #####\n #####\n #####\n\n\n";

my $guardlist;  ## array
print "Guardlist:\n";
foreach my $ip (keys %$all_filts_h)  {
   foreach my $rn (keys %$filt_h)  {
      if (!exists $filt_h->{$rn}->{$ip})  {
         if ($db)  { 
            $insert_h = $dbh->prepare('INSERT IGNORE INTO network.borderfilterQ (address,operation,dateQ,netid,comment ) VALUES (?,?,?,?,?)');
            $insert_h->execute($ip,"filter",$dateQ,"borderguard","synching lists");
         }
         print "$ip  $rn\n";
         ##push @$guardlist, "$ip $rn";
      }
   }
}
##print "Guardlist:\n";
##foreach my $ipr (@$guardlist)  {  print "$ipr\n";  }

## fix inserts into network.borderfilters
my $current_filter_h;   ## elements of network.borderfilters
$select_h = $dbh->prepare('SELECT address FROM network.borderfilters;');
$select_h->execute();
if ($select_h->rows != 0) {
   my $sel_ary = $select_h->fetchall_arrayref;
   foreach my $row (@$sel_ary)   {
      my $addr = $row->[0];
      $current_filter_h->{$addr} = 1;
   }
}
print "Missing from network.borderfilters:\n";
foreach my $ip (keys %$all_filts_h)  {
   if (!exists $current_filter_h->{$ip})  {      ## i.e., ip not in borderfilters table, so put it in there
      if ($db)  {
         $insert_h = $dbh->prepare('INSERT IGNORE INTO network.borderfilters (tstamp,address) VALUES (?,?)');
         $insert_h->execute($dateQ,$ip);
      }
      print "$ip\n"; 
   } 
}

my $test == 0;
if ($test) {
  foreach my $rn (keys %$filt_h)  {
     print "Router: $rn\n";
     foreach my $filt ( keys %{$filt_h->{$rn}} )  {
        print "$filt\n";
     }
  }
}

$dbh->disconnect();
$session->close();

exit;

##################

sub help  {

print<<EOF;

bsift.pl - check, compare and sync border-host-filter; update world db table network.borderfilters

syntax:  ./borderfiltersifter.pl  
option:  ./borderfiltersifter.pl -p0   Print only, do not affect database


EOF

}

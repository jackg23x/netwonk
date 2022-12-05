#!/usr/bin/perl
## jackg@uic.edu 
## 
## fw-asaconfig.pl
## 
## ASA config grabber
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
use Net::DNS;

#if (!@ARGV)  {  help();  exit;  }
#if ( grep / -h/ , @ARGV )  {  help();  exit;  }
#if ( grep /help/ , @ARGV )  {  help();  exit;  }

## timestamp of this run
my($date,$time) = Sshcon::date_time();
my $tstamp = "$date"."_"."$time";

my $asas;
$asas = get_DNS_switches("asa");   ## local subroutine
## while ( my($x,$y) = each(%$asas))  { print "$x => $y\n"; }

require "$installpath/lib/servers.pl";
my $mntpath = mntpath();
my $scriptserver = scriptserver();
($scriptserver,undef) = split /\./, $scriptserver;
my $mntdir  = "$mntpath/$scriptserver/netwonk/configs/asa";
my $dir     = "$installpath/configs/asa";

my ($aip,$aname);
while ( ($aname,$aip) = each(%$asas) )  {
   print "=== processing $aname => $aip \n";
   get_config($aname,$aip);
}

print "exiting...\n";

exit;  ## th-th-th-th-that's all folks!

#########################################################

sub get_config  {

   my $aname = shift;
   my $aip   = shift;
   
   ## It originates in the admin context, do a 'changeto sys' for complete list (includes 'admin')
   ## From sys you can see the other contexts, which are under that one.  So get those.
   my $session = Sshcon->new($aip);
   my $state = $session->connect;
   my $ena_ret;
   if ($state ne "enabled")  {
      $session->enable();
   }
   $session->command("term pager 0");
   $session->command("changeto sys");
   my $contexts; ## array ref
   ## get all contexts
   my $ctxt_list = $session->command("show context");
   foreach my $c (@$ctxt_list)  {
      ## pull the "default" contexts
      #my($ctxt,$default,undef) = split " ", $c;
      #if ($default eq "default")  {  push @$contexts, $ctxt;  }
      if ($c =~ /Routed/)  {
         my($ctxt,undef) = split " ", $c;
         push @$contexts, $ctxt;
      }
   } 
   push @$contexts, "system";
   my $temp_cfg;
   foreach my $ctxt (@$contexts)  {
      $ctxt =~ s/\*//;
      print "context = $ctxt\n";  ## TEST  TEST  TEST
      if ($ctxt != /secure/)  { next; }  ### TEST  TEST  TEST  TEST
      my $cf  = "$dir/$aname.$ctxt.cfg";  ## each config as it will be written
      my $cfh = IO::File->new(">$cf");     
      $session->command("changeto sys");
      if ($ctxt ne "system")  {
         $session->command("changeto context $ctxt");
      }
      $session->command("term pager 0");
      $temp_cfg = $session->command("show config");

      if ( scalar(@$temp_cfg) > 33 )  {      ## if new file has enough lines to not be junk, replace old
         foreach my $tc (@$temp_cfg) {
            if ($tc =~ /show conf/)     {  next;  }
            if ($tc =~ /password/)      {  next;  }
            if ($tc =~ /^\s*passwd/)    {  next;  }
            print $cfh "$tc\n";
            if ($tc =~ /:\send/)        {  last;  }
         }
      }
      system ("cp", "$cf", "$mntdir/$aname.$ctxt.cfg");
   }
 
}  ## get_config

##############################################################################

sub get_DNS_switches  {

   my $zone = shift;

   require "$installpath/lib/servers.pl";
   my $dns1 = dns1();
   my $dns2 = dns2();
   my $dns3 = dns3();
   my $dnssuffix = dnssuffix();
   if ($zone !~ /$dnssuffix/)  {  $zone = "$zone.$dnssuffix";  }
 
   my $switches;
   ## get all switch entries from DNS
   my ($sw_ip,$sw_name);
   my $res  = Net::DNS::Resolver->new;
   $res->nameservers($dns1,$dns2,$dns3);
   my @zone = $res->axfr("$zone");
   foreach my $rr (@zone) {
     unless ($rr->type eq "A")  { next; }
     $sw_ip   = $rr->address;
     my $full_name = $rr->name;
     ($sw_name) = split /\./, $full_name, 2;
     #print "$sw_name  $sw_ip\n";
     ### This version swaps the aip and aname
     $switches->{$sw_name} = $sw_ip;
   }
 
   #foreach my $swname (keys %$switches)  { print "sh: $swname => ", $switches->{$swname}, "\n"; }
 
   return($switches);
}

#########################################################

sub help  {

print " \n";
print " asaconfig.pl - get all ASA configs \n\n";
 

}

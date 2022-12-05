#!/usr/bin/perl
# jackg@uic.edu 
#
# swcdp.pl
# collect cdp info off switches and RTRs
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
use strict;
use vars qw( $sql_err_lines  $sql_all_err_lines $tstamp );

my $args;
@$args  = @ARGV;
my $swip   = $args->[0];
my $swname = $args->[1];

## Change this to 1 if you need to print run testing:
my $prt = 1;
my ($of,$ofh);
if ($prt == 1)  {
   $of   = "$installpath/forensic/switches/$swname.swcdp";
   $ofh  = IO::File->new(">>$of");
}

if ($swip !~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {
   if ($prt)  {  print $ofh "\nBad input - first argument must switch IP, second switch name.\nExiting...\n\n";  }
   print "\nBad input - first argument must switch IP, second switch name.\nExiting...\n\n";
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

my ($date,$time)=SshSwcon::date_time();
my $start_time = "$date $time";
my $tstamp = $start_time;

my $pmf  = "$installpath/data/swcdpPhoneMoves.out";
my $pmfh = IO::File->new(">$pmf");

## Collect existing phone locations
my $SEPs;     ## hash ref of phone locations
my $query = "SELECT * from switch.cdp where remoteDeviceID like 'SEP%';";
my $select_h  = $dbh->prepare($query);
$select_h->execute();
my $sel_ary = $select_h->fetchall_arrayref;
foreach my $rec (@$sel_ary)  {
   my ($swip,$swname,$localPort,$remoteDeviceID,undef) = @$rec;
   $SEPs->{"$remoteDeviceID"} = "$swip $swname $localPort";
}

## Connect to switch
my $session = SshSwcon->new($swip);
my $state = $session->connect();
my $ena_ret;
if ($state ne "enabled")   {  $ena_ret = $session->enable();  }
$session->command("term len 0");
my $rets = $session->command("show cdp entry *");  ##  "*" = "all"

## DELETE/CLEAR the old switch.cdp entries for this $swname 
## - devices will either be replaced where they are, put in their new locations, or removed as reflects current network state
$query    = "DELETE from switch.cdp WHERE swname = \"$swname\" ";
my $delete_h = $dbh->prepare($query);
$delete_h->execute();

## Get all entries for this switch
if ($prt)  { print $ofh "##################\n$tstamp:  $swname    $swip\n"; }
my $lines;
for (my $i=0; $i<= $#$rets; $i++)  {
    if ($rets->[$i] =~ /\AVersion/)  {    # multiline entry
       my $a = $rets->[$i];
       my $b = $rets->[$i+1];
       if ($b =~ /Cisco Internetwork Operating System Software/)  {
          $b = $rets->[$i+2];
          $i++;
       } 
       push @$lines, "$a $b";
       $i++;
    } 
    else  {  push @$lines, $rets->[$i];  }
}

my ($localPort,$remoteDeviceID,$remoteIP,$remotePort,$platform,$capabilities);
my ($version,$VTPdomain,$powerDrawn,$powerRequest);
foreach my $ln (@$lines)  {
  ## Deal with the cdp previous entry you have already found and put into the field variables
  if ($ln =~ /\ADevice ID/i)  {
     if ($remoteDeviceID ne "")  {  ## it's not the first virgin run, so you have data in the field variables
        if ($VTPdomain eq "")    {  $VTPdomain =  "n/a"; }   ## not in all configs
        if ($powerDrawn eq "")   {  $powerDrawn = "n/a"; }   ## not in all configs
        if ($powerRequest eq "") {  $powerRequest = "n/a"; } ## not in all configs
        my $query = "INSERT into switch.cdp (swip,swname,localPort,remoteDeviceID,remoteIP,remotePort,platform,version,capabilities,VTPdomain,powerDrawn,powerRequest,tstamp)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";
        my $insert_h = $dbh->prepare($query);
        $insert_h->execute($swip,$swname,$localPort,$remoteDeviceID,$remoteIP,$remotePort,$platform,$version,$capabilities,$VTPdomain,$powerDrawn,$powerRequest,$tstamp);
        if ($prt) {print $ofh "$swip,$swname,$localPort,$remoteDeviceID,$remoteIP,$remotePort,$platform,$version,$capabilities,$VTPdomain,$powerDrawn,$powerRequest,$tstamp\n";}
        ## clear all persistent field variables
        $localPort=$remoteDeviceID=$remoteIP=$remotePort=$platform=$capabilities="";
        $version=$VTPdomain=$powerDrawn=$powerRequest="";
     }
     ## Now deal with the current cdp entry - start filling the field variables as we go on through the "ifs"
     (undef,undef,$remoteDeviceID) = split " ", $ln;
  }
  if ($ln =~ /\A\s*IP address/i)  {
     #if ($prt)  {  print $ofh "$ln\n";  }
     (undef,undef,$remoteIP) = split " ", $ln;
  }
  if ($ln =~ /\A\s*Platform/i)  {
     my ($plat,$cap) = split /\,/, $ln;
     (undef,$platform) = split /\:/, $plat, 2;
     $platform =~ s/Cisco//i;
     $platform =~ s/\A\s+//g;
     $platform =~ s/\s+\z//g;
     $platform =~ s/ /_/g;
     (undef,$capabilities) = split /\:/, $cap, 2;
     $capabilities =~ s/\A\s+//g;
     $capabilities =~ s/\s+\z//g;
     if ($capabilities eq "")  {  $capabilities =  "n/a"; }
     $capabilities =~ s/ /_/g;
  }
  if ($ln =~ /\A\s*Interface/i)  {
     my ($int,$port) = split /\,/, $ln;
     (undef,$localPort) = split /\:/, $int;
     $localPort =~ s/\A\s+//g;
     $localPort =~ s/\s+\z//g;
     $localPort =~ s/ /_/g; 
     (undef,$remotePort)  = split /\:/, $port;
     $remotePort =~ s/\A\s+//g;
     $remotePort =~ s/\s+\z//g;
     $remotePort =~ s/ /_/g; 

     ## Check for phone move:
     if ($remoteDeviceID =~ /SEP/)  {
        if (exists $SEPs->{$remoteDeviceID})  {
           if ($SEPs->{$remoteDeviceID} ne "$swip $swname $localPort")  {
              print $pmfh "Move: $tstamp $remoteDeviceID ", $SEPs->{$remoteDeviceID}, " $swip $swname $localPort\n";
           }
        }
        else  {  print $pmfh "New: $tstamp $remoteDeviceID none none install $swip $swname $localPort\n";  }
     }
  }
  if ($ln =~ /\A\s*Version/i)  {
     my (undef,$verstring) = split /\:/, $ln;
     my @vers = split /\,/, $verstring;
     if ($#vers == 0)  {
        $version = $vers[0];
        $version =~ s/Version//g;
        $version =~ s/\A\s+//g;
        $version =~ s/\s+\z//g;
        $version =~ s/ /_/g;
     }
     else  {
        foreach my $v (@vers)  {
           if ($v =~ /Version/)  {
              (undef,$version) = split / /, $v, 2;
              $version =~ s/Version//g;
              $version =~ s/\A\s+//g;
              $version =~ s/\s+\z//g;
              $version =~ s/ /_/g;
           }
        }
     }
  }
  if ($ln =~ /\A\s*Power drawn/i)  {
     (undef,$powerDrawn) = split /\:/, $ln, 2;
     $powerDrawn =~ s/Watts//i;
     $powerDrawn =~ s/\A\s+//g;
     $powerDrawn =~ s/\s+\z//g;
     if ($powerDrawn eq "")    {  $powerDrawn = "n/a"; }
  }
  if ($ln =~ /\A\s*Power request levels are/i)  {
     (undef,$powerRequest) = split /\:/, $ln, 2;
     $powerRequest =~ s/\A\s+//g;
     $powerRequest =~ s/\s+\z//g;
     $powerRequest =~ s/ /_/g;
     if ($powerRequest eq "")    {  $powerRequest = "n/a"; }
  }
  if ($ln =~ /\A\s*VTP Management/i)  {
     (undef,$VTPdomain) = split /\:/, $ln, 2;
     $VTPdomain =~ s/\A\s+//g;
     $VTPdomain =~ s/\s+\z//g;
     $VTPdomain =~ s/\'//g;
     if ($VTPdomain eq "")    {  $VTPdomain =  "n/a"; }
  }
} ## foreach my $ln

## process that last line from above, and you're done
if ($VTPdomain eq "")        { $VTPdomain =  "n/a"; }     ## not in all configs
if ($powerDrawn eq "")       { $powerDrawn = "n/a"; }     ## not in all configs
if ($powerRequest eq "")     { $powerRequest = "n/a"; }   ## not in all configs
if ($localPort eq "")        { $localPort = "unknown";  } 
if ($remotePort =~ /^\s*$/)  { $remotePort = "unknown"; } 
my $query = "INSERT into switch.cdp (swip,swname,localPort,remoteDeviceID,remoteIP,remotePort,platform,version,capabilities,VTPdomain,powerDrawn,powerRequest,tstamp)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";
my $insert_h = $dbh->prepare($query);
$insert_h->execute($swip,$swname,$localPort,$remoteDeviceID,$remoteIP,$remotePort,$platform,$version,$capabilities,$VTPdomain,$powerDrawn,$powerRequest,$tstamp);
if ($prt) {print $ofh "$swip,$swname,$localPort,$remoteDeviceID,$remoteIP,$remotePort,$platform,$version,$capabilities,$VTPdomain,$powerDrawn,$powerRequest,$tstamp\n";}

$session->close();
$dbh->disconnect(); 

exit;

#######################


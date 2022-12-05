#!/usr/bin/perl
#jackg@uic.edu 
#
# rtrcfgsav.pl  
# child process -- collects a rtr config from a single device
#

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use lib "$installpath/lib";
use SshSwcon;
use IO::File;
use strict;

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

my ($date,$time)=SshSwcon::date_time();
my $tstamp = "$date $time";

my $args;
@$args  = @ARGV;
my $swip   = $args->[0];
my $swname = $args->[1];

require "$installpath/lib/servers.pl";
my $mntpath = mntpath();
my $scriptserver = scriptserver();
($scriptserver,undef) = split /\./, $scriptserver;
my $mntdir  = "$mntpath/$scriptserver/netwonk/configs/rtr";
my $dir     = "$installpath/configs/rtr";

my $session = SshSwcon->new($swip);
my $state = $session->connect();
if ($state eq "notconnected")  {
   ## print $errfh "$tstamp $rname $rip - Session state = $state\n"; ## from rtrarp.pl
   exit;
}
my $ena_ret;
if ($state ne "enabled")  {  $ena_ret = $session->enable();  }
$session->command("term len 0");
my $cfglns = $session->command("show start");

### If the result file is big enough
if ( scalar(@$cfglns) > 52 )  {
   my $cf  = "$dir/$swname.cfg";  ## each config as it will be written
   my $cfh = IO::File->new(">$cf");
   foreach my $ln (@$cfglns)  {
      if ($ln =~ /show start/)              {  next;  }
      if ($ln =~ /Building configuration/)  {  next;  }
      if ($ln =~ /enable secret/)           {  next;  }
      if ($ln =~ /password/)                {  next;  }
      if ($ln =~ /^\s*passwd/)              {  next;  }
      print $cfh "$ln\n";
      if ($ln =~ /\A$swname/)               {  next;  }   ## last return line
      ## not needed -- if ($ln =~ /:\send/)                  {  last;  }
   }
   system ("cp", "$cf", "$mntdir/$swname.cfg");
}

$session->close();
exit;

#######################


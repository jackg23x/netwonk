#!/usr/bin/perl
#jackg@uic.edu 
#
# switchconfig 
# child process of swseeker.pl -- collects switch config from a single switch
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

my ($date,$time)=SshSwcon::date_time();
my $tstamp = "$date $time";

my $args;
@$args  = @ARGV;
my $swip   = $args->[0];
my $swname = $args->[1];

if ($swip !~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {
   print "\nBad input - first argument must switch IP, second switch name.\nExiting...\n\n";
   exit;
}
require "$installpath/lib/servers.pl";
my $domain = dnssuffix();
$swname =~ s/\.rtr\.$domain//;
$swname =~ s/\.switch\.$domain//;

require "$installpath/lib/servers.pl";
my $mntpath = mntpath();
my $scriptserver = scriptserver();
($scriptserver,undef) = split /\./, $scriptserver;
my $mntdir  = "$mntpath/$scriptserver/netwonk/configs/switches";
my $dir     = "$installpath/configs/switches";

my $session = SshSwcon->new($swip);
my $state = $session->connect();
if ($state eq "notconnected")  {
   ## print $errfh "$tstamp $swname $swip - Session state = $state\n"; # from swmisc.pl, output: ./forensic-swmisc/ZXerr.out
   exit;
}
my $ena_ret;
if ($state ne "enabled")  {  $ena_ret = $session->enable();  }
$session->command("term len 0",1);
my $cfglns = $session->command("show start");

### If the result file is big enough
 
if ( scalar(@$cfglns) > 52 )  {
   my $cf  = "$dir/$swname.cfg";  ## each config as it will be written
   my $cfh = IO::File->new(">$cf");
   foreach my $ln (@$cfglns)  {
      if ($ln =~ /show start/)                {  next;  }
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
print "\n";
exit;

#######################


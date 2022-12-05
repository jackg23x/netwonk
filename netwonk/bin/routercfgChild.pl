#!/usr/bin/perl
## jackg@uic.edu
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

my($date,$time) = Sshcon::date_time();

require "$installpath/lib/servers.pl";
my $mntpath = mntpath();
my $scriptserver = scriptserver();
($scriptserver,undef) = split /\./, $scriptserver;
my $mntdir  = "$mntpath/$scriptserver/netwonk/configs/routers";
my $dir     = "$installpath/configs/routers";

my $args;
@$args = @ARGV;
my $routerip   = $args->[0];
my $routername = $args->[1];

print "routername = $routername  ::  routerip = $routerip\n";
my $cf     = "$dir/$routername.cfg";  ## each config as it will be written
my $cfh    = IO::File->new(">$cf");
my $mntcf  = "$mntdir/$routername.cfg";  ## each config as it will be written
my $mntcfh = IO::File->new(">$mntcf");

my $session = Sshcon->new($routerip);
my $state = $session->connect();
my $ena_ret;
if ($state ne "enabled")  {
   $ena_ret = $session->enable();
}
$session->command("term length 0",1);
my $temp_cfg; 
if    ($routername eq "30") { $temp_cfg = $session->command("show config ",120); }  
elsif ($routername eq "40") { $temp_cfg = $session->command("show config ",120); }  
else                        { $temp_cfg = $session->command("show run ",42);     }
if ( scalar(@$temp_cfg) > 33 )  {      ## if new file is big enough to not be junk, replace
   foreach my $tc (@$temp_cfg)  {
      if ($tc =~ /show conf/)        {  next;  }
      if ($tc =~ /enable password/)  {  next;  }
      if ($tc =~ /^\s*passwd/)       {  next;  }
      print $cfh "$tc\n";
      print $mntcfh "$tc\n";
      if ($tc =~ /\Aend\z/)    {  last;  }
   } 
} 
$session->close();
print "\n";

exit;

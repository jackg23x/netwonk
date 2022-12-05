#!/usr/bin/perl
#jackg@uic.edu 
#
# showversion.pl 
#

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/util//;

use lib "$installpath/lib";
use SshSwcon;

my ($date,$time)=SshSwcon::date_time();
my $tstamp = "$date $time";

my $args;
@$args  = @ARGV;
my $swip   = $args->[0];
# my $swname = $args->[1];

my $session = SshSwcon->new($swip);
my $state = $session->connect();
if ($state eq "notconnected")  {
   exit;
}
my $ena_ret;
if ($state ne "enabled")  {  $ena_ret = $session->enable();  }
$session->command("term len 0");
$session->command("show version");
sleep(1);
$session->close();
print "\n";
exit;

#######################


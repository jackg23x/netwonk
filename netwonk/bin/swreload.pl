#!/usr/bin/perl
#jackg@uic.edu 
#
# swreload.pl 
# child process of swseeker.pl -- reloads a switch, supports 'AT'
# supports vgreload functionality
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

my ($date,$time)=SshSwcon::date_time();
my $tstamp = "$date $time";

my $args;
@$args  = @ARGV;
my $swip   = $args->[0];
my $swname = $args->[1];
my $at     = $args->[2];

my $of  = "$installpath/forensic/switches/$swname.swreload";
my $ofh = IO::File->new(">>$of");

print $ofh "$tstamp swreload.pl $swname $swip -"; # 

my $session = SshSwcon->new($swip);
my $state = $session->connect();
if ($state eq "notconnected")  {
   exit;
}
my $ena_ret;
if ($state ne "enabled")  {  $ena_ret = $session->enable();  }
## 'AT' support:
#if ($at ne "")  {
#   $session->command("reload at $at");
#}
#else {
   $session->command("reload");
#}
sleep(1);
$session->close();
print $ofh "- Session state = $state\n";
print "\n";
exit;

#######################


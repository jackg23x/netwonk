#!/usr/bin/perl
## jackg@uic.edu 
##

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/util//;

use lib "$installpath/lib";
use SshSwcon;

#use IO::File;
#my $jf  = "$installpath/util/fixswntp.out";
#my $jfh = IO::File->new(">$jf");

my $args;
@$args = @ARGV;
my $swname = $args->[0];

require "$installpath/lib/servers.pl";
my $ntpserver1 = ntpserver1();
my $ntpserver2 = ntpserver2();

my $session;
$session = SshSwcon->new($swname);
my $conret = $session->connect;
## $session->enable(); # not needed
$session->command("conf t",1);
$session->command("ntp server $ntpserver1",1);
$session->command("ntp server $ntpserver2",1);
$session->command("end",1);
$session->command("write mem",5);
$session->command("exit",1);
$session->close;

exit;

######
######

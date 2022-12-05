#!/usr/bin/perl
#jackg
use strict;
use warnings;

my $process = $ARGV[0];
if (! $process) { print "must enter scrit name as parameter, i.e.:  \./world_manager.pl world_ack.pl\n"; exit;   }

my $call = "/etc/syslog-ng/scripts/$process";

my $chip = `ps waux | grep world_nofree.pl | grep -v grep`;
#print "chip >$chip<\n";

if(`ps waux | grep $process | grep -v grep | grep -v world_manager`) {
   #print "$process is running...\n";
}
else {
   print "$process is NOT running...let's run it!\n";
   print "calling $call\n";
   exec "sudo $call &";
   exit;
   ## `$call &`;
}


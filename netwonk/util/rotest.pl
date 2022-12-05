#!/usr/bin/perl
## jackg@uic.edu
##
##

use Time::Local;
use strict;


#my $epoch = timelocal($sec, $min, $hour, $mday, $mon, $year)

my $epoch = timelocal(0,0,0,5,0,2022);                     
my $now = timelocal(localtime());

print "epoch    = $epoch\n";
print "local    = $now\n";
print $now-$epoch, "\n";


my $datefilt = "2021-12-31 12:12:12";

my $now = timelocal(localtime());
my ($dt,undef) = split " ", $datefilt;
my ($y,$m,$d)  = split "-", $dt;
print "$y,$m,$d\n";
my $dflt = timelocal(0,0,0,$d,$m-1,$y);
my $diff = $now - $dflt;
print "now      = $now\n";
print "datefilt = $dflt\n";
print "diff     = $diff\n";
if ($diff < 600000)  {  next;  print "bailing on short date $diff\n";  }


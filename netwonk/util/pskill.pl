#!/usr/bin/perl
## jackg@uic.edu
##

use IO::File;
use strict;

my $psfile = "./pskill.list";
my $psfh   = IO::File->new("$psfile");

while (my $ln = <$psfh>)  {
   $ln =~ s/\s+/ /;
#   print "$ln\n";
   my ($a,$ps,$b,$c,$d,undef) = split / /, $ln;
#   print "$a $ps $b $c $d\n";
#   print "ps:$ps\n";
   print "kill -9 $ps\n";
   `kill -9 $ps`;
   ## `sudo kill -9 $ps`;
}

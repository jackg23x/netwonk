#!/usr/bin/perl
#jackg@uic.edu

use strict;

use FindBin qw($Bin);
#use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
print "### install path: $installpath  ###\n";
$installpath =~ s/\/$//;
print "### install path: $installpath  ###\n";
$installpath =~ s/\/util//;
print "### install path: $installpath  ###\n";

foreach my $inc (@INC) {  print "$inc\n";  }


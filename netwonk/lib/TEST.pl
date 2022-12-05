#!/usr/bin/perl
# Jack Gallagher 

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

#use lib "$installpath/lib";

print "### install path: $installpath  ###\n";


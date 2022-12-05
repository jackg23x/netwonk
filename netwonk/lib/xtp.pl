#!/usr/bin/perl
## Jack Gallagher
##
##

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/lib//;

require "$installpath/lib/PWtest.pl";
my $exe1 = rtexe1();
my $ena1 = rtena1();
my $exe2 = rtexe2();
my $ena2 = rtena2();
print "\n";
print "$exe1\n$ena1\n$exe2\n$ena2\n";

$exe1 = swexe1();
$ena1 = swena1();
$exe2 = swexe2();
$ena2 = swena2();
print "\n";
print "$exe1\n$ena1\n$exe2\n$ena2\n";

print "\n";

exit;

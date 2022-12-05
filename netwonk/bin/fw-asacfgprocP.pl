#!/usr/bin/perl
# jackg@uic.edu
#
# Reads all asa configs.
#

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

my $contexthash;
my $cfg_path = "$installpath/configs/asa";
opendir(DIR, $cfg_path) || die "can't opendir $cfg_path: $!";
my $dirlist;
@$dirlist = readdir(DIR);
foreach my $f (@$dirlist)  {
   if ( $f =~ /\.system\.cfg\z/ )  { next; }
   if ( $f =~ /\.admin\.cfg\z/ )  { next; }
   if ( $f =~ /\.temp\.cfg\z/ )  { next; }
   if ( $f !~ /cfg$/ )  { next; }
   my $fwn = $f;
   $fwn =~ tr/\./ /;
   my ($asa,$context) = split " ", $fwn;
   $contexthash->{$context} = $f;  ## only one file saved/processed per context
}

foreach my $context (sort keys %$contexthash)  { 
   print "$context => ",$contexthash->{$context}, "\n";
   my $cfgfile = $contexthash->{$context};
   $SIG{CHLD} = 'IGNORE';
   unless ( fork() )  {
      exec ("$installpath/bin/fw-asacfgprocC.pl", "$cfgfile", "&");
      exit (0);
   }
}
exit;
###########################################


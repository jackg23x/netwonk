#!/usr/bin/perl 
#jackg@uic.edu 
#
# swntpcheck.pl - check for ntp servers on switches
#

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/util//;

#use vars qw( $ping_switch_hash $smdmf $smdmfh );
use vars qw( $ping_switch_hash $missingboth $missing1 $missing2 );

if (@ARGV[0] ne "-p" && @ARGV[0] ne "")  { 
   help();  
   exit;
}

my $args;
@$args = @ARGV;
my $prefix;       # switchname prefix

for (my $i=0; $i< scalar(@$args); $i++)  {
   if ($args->[$i] eq "-p")  {
      $i++;
      while (($args->[$i] !~ /\A-/) && ($i< scalar(@$args)))  {
         $prefix .= "$args->[$i]";
         $i++;
      }
   }
}

use IO::File;
my $of  = "$installpath/util/swntpcheck.out";
my $ofh = IO::File->new(">$of");

require "$installpath/lib/servers.pl";
my $ntpserver1 = ntpserver1();
my $ntpserver2 = ntpserver2();

my $cfg_path = "$installpath/configs/switches";
opendir(DIR, $cfg_path) || die "can't opendir $cfg_path: $!";
my @dirlist = grep /\.cfg\z/ , readdir(DIR);
my $i;
if ($prefix)  {
   foreach my $cfgfile (@dirlist)  {
      if ($cfgfile =~ /^$prefix/)  { check_one_switch($cfgfile); }
   }
}
else  {
   foreach my $cfgfile (@dirlist)  { check_one_switch($cfgfile); }
}

if ($missingboth) {
   #print $ofh "Missing both $ntpserver1 and $ntpserver2:\n";
   foreach my $fn (@$missingboth)  { print $ofh "./fixswntp.pl $fn\n"; }
   #print $ofh "\n";
}
if ($missing1) {
   #print $ofh "Missing $ntpserver1 only:\n";
   foreach my $fn (@$missing1)     { print $ofh "./fixswntp.pl $fn\n"; }
   #print $ofh "\n";
}
if ($missing2) {
   #print $ofh "Missing $ntpserver2 only:\n";
   foreach my $fn (@$missing2)     { print $ofh "./fixswntp.pl $fn\n"; }
   #print $ofh "\n";
}

exit;

###############

sub check_one_switch  {
 
   my $cfgfile = shift;

   my ($has1,$has2);
   my $ret;
   @$ret = `grep "ntp server" $cfg_path/$cfgfile`;
   foreach my $ln (@$ret)  {
      chomp($ln);
      if ($ln =~ /$ntpserver1/)  { $has1 = 1; }
      if ($ln =~ /$ntpserver2/)  { $has2 = 1; }
   }
   if ($has1 && $has2)   { return; }
   my ($fn,undef) = split /\./, $cfgfile; 
   if (!$has1 && !$has2) { push @$missingboth, $fn; }
   if ($has1 && !$has2)  { push @$missing2, $fn; }
   if (!$has1 && $has2)  { push @$missing1, $fn; }
   
   return;

}

###############

sub help  {

print<<EOF;

swntpcheck.pl

Syntax: swcheckntp.pl  [ options ]

options:
  -p <prefix>   front-end of a switch name, which starts with a building,
                but you're not limited to that. You can add more.
                *** This allows PARTIAL RUNS for quick data. ***   

   -h or help   You get to this help printout
EOF

}

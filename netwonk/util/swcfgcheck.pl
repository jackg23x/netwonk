#!/usr/bin/perl 
#jackg@uic.edu 
#
# swcfgcheck.pl - in ./netwonk/switches/configs checks for likes that match the given search string
# mainly used for finding switches that haven't saved a config in a while and poking them
# creates a file of ready to go calls to  ./swconfig.pl <swip> <swname>
#

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/util//;

require "$installpath/lib/servers.pl";
my $domain = dnssuffix();
print "domain = $domain\n";

use Net::DNS;
use IO::File;
my $of  = "$installpath/util/swcfgcheck.out";
my $ofh = IO::File->new(">$of");

my $search = $ARGV[0];
print "search = $search\n";

my $swname;
my @lines = `ls -l $installpath/configs/*`;
foreach my $ln (@lines)  {
   chomp $ln;
   if ($ln =~ /$search/)  {
      my(undef,undef,undef,undef,undef,undef,undef,undef,$swname) = split " ", $ln;
      ($swname,undef) = split /\./, $swname;
      print "$swname.switch.$domain\n";
      my $res   = Net::DNS::Resolver->new;
      my $query = $res->query("$swname.switch.$domain");
      my $swip;
      if ($query) {
          foreach my $rr ($query->answer) {
             $swip = $rr->address, "\n";
             print $ofh "./swconfig.pl $swip $swname\n";
          }
      }
   } 
}
exit;

###########


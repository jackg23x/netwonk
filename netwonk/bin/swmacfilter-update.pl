#!/usr/bin/perl

# jackg@uic.edu
#
# grabs all switch macfilters from saved configs and puts them
# in table network.swmacfilters                    
#
#

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use vars qw($ints );

my $time = `date`;
print "start: $time\n";

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

#use IO::File;
#my $of  = "$installpath/forensic/swmacfilter-update.out";
#my $ofh = IO::File->new(">$of");

my $swmacfilt_lns;
my $cfgpath = "$installpath/configs/switches";
@$swmacfilt_lns = `grep static $cfgpath/* | grep drop`;

my $swmacfilts;  ## array ref
foreach my $mfl (@$swmacfilt_lns)  {
   chomp($mfl);
   ##print "$mfl\n";
   if ($mfl !~ /$cfgpath/)  {  next;  }
   chomp $mfl;
   my($swname,undef) = split ":", $mfl;
   #print $ofh "swname = $swname\n";
   $swname =~ s/\// /g;
   (undef,undef,undef,undef,$swname) = split " ", $swname;
   ($swname,undef) = split /\./, $swname;
   my(undef,$stuff) = split "static", $mfl;
   my($mac,undef,$vlan,undef) = split " ", $stuff;
   push @$swmacfilts, "$swname $mac $vlan";
}

my $query    = "DELETE from network.swmacfilters;";
my $delete_h = $dbh->prepare($query);
$delete_h->execute();
foreach my $mfl (@$swmacfilts)  {
   my($swname,$mac,$vlan) = split " ", $mfl;
   #print $ofh "$swname - $mac - $vlan\n";
   my $query    = "INSERT into network.swmacfilters (swname,mac,vlan) VALUES (?,?,?)";
   my $insert_h = $dbh->prepare($query);
   $insert_h->execute($swname,$mac,$vlan);
}


exit;


$time = `date`;
print "end: $time\n";

exit;

################################################

sub help  {

print<<EOF;

swmacfilter.pl

Syntax: swmacfilter.pl               

grabs all switch macfilters and throws them into network.swmacfilters on world.cc

EOF

}


#!/usr/bin/perl
## jackg@uic.edu
##
## backup for the scripts

use strict;
use warnings;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/util//;

require "$installpath/lib/servers.pl";
my $mntpath      = mntpath();
my $scriptserver = scriptserver();
my $crontab      = crontab();
($scriptserver,undef) = split /\./, $scriptserver;

my $dirs;
@$dirs = (
           "bin",
           "configs",
           #"data",
           #"forensic",
           "lib",
           "util",
);

foreach my $dir (@$dirs)  {
   my $src = "$installpath/$dir";
   my $dest = "$mntpath/$scriptserver/netwonk";
   print "rsync -ar $src to $dest\n";
   system("/usr/bin/rsync -ar $src $dest");
}

#`cat $crontab > ./crontab.list`;
print "rsync -av the crontab to $mntpath/$scriptserver/netwonk/crontab.list\n";
system("/usr/bin/rsync -av  $crontab  $mntpath/$scriptserver/netwonk/crontab.list");
#system("/usr/bin/rsync -av  ./crontab.list $/crontab.list");

exit;


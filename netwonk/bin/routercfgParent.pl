#!/usr/bin/perl
## jackg@uic.edu
##

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use lib "$installpath/lib";
use Sshcon;  

require "/$installpath/lib/core_routers.pl";
use vars qw(%core_routers);

my($date,$time) = Sshcon::date_time();
##print "routercfgParent.pl running $date $time\n";

foreach my $routerip (keys %core_routers)  {
   my $routername = $core_routers{$routerip};
   print "   invoking routercfgChild.pl $routerip $routername\n";

   $SIG{CHLD} = 'IGNORE';
   unless ( fork() )  {
     exec ("/$installpath/bin/routercfgChild.pl", "$routerip", "$routername",  "&");
     exit (0);
   }
}  ## foreach routerip

print "\n";
exit;

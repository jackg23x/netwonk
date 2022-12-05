#!/usr/bin/perl
# by jackg - Jack Gallagher
#
# switch_lastconnect.cgi
#
 
use strict;

print "Content-type: text/html\n\n<html><body>";
print "<title> lastconnect: Switches listed by inverse order of the last time connected by swmisc.pl script </title>";
print "<body bgcolor=\"bbbbbb\">";

use FindBin qw($Bin);
my $installpath = $Bin;
$installpath =~ s/\/$//;

use CGI;
my $in = CGI->new;

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit("server1");
#my ($h,$u,$p) = dbigrabit();
print "$h<br>";

my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

require "$installpath/lib/servers.pl";
my $nuser  = network();
my $domain = dnssuffix();

########## LOCAL AUTH CODE ############################################
require "$installpath/lib/auth.pl";
use vars qw(%network_staff %noc_staff %security_staff %systems_staff);
my $host = $ENV{REMOTE_ADDR} || "host unknown";
my %auth = (%network_staff , %noc_staff , %security_staff, %systems_staff);
my $netid = $ENV{REMOTE_USER} || "no user specified";
$netid =~ s/\/tacacs//;
if (exists $auth{$netid})  {  print "netid '$netid' connecting from $host <br><br>\n";  }
else {
  print "<body bgcolor=red><br><br><h2><b><font color=green>User Authorization Failure</font></b><br><br>";
  print "<b> Use of this page by $netid not authorized. <br><br>";
  print "Please contact <a href=\"mailto:$nuser\@$domain\">$nuser\@$domain</a></b>\n";
  exit;
}
#######################################################################

print "<h3> Last time a switch connected by script ssh (swmisc.pl) oldest first </h3>";

my $s4 = "&nbsp&nbsp&nbsp&nbsp";
my $th = "<th rowspan=1 align=left>";

#my $query  = "SELECT * FROM switch.lastconnect ORDER BY recent DESC ";
my $query  = "SELECT * FROM switch.lastconnect ORDER BY swname ";
my $select_h = $dbh->prepare($query);
my $lastconnects = $select_h->execute();
print "<b>Total switches registered: $lastconnects </b><br><br>"; 
if ($lastconnects != 0) {
   print "<table border=5>";
   print "$th swname </th> $th swip </th> $th tstamp </th> </tr>  </b> \n";
   while ( my $row = $select_h->fetchrow_arrayref ) {
       my ($swname,$swip,$tstamp) = @$row;
       print "<td> $swname $s4 </td>  <td> $swip $s4 </td>  <td> $tstamp $s4 </td> </tr>";
   }
   print "</table>";
}
else  {  print "<font color=red> *** No switches found in table *** <br><br>\n";  }
print "<br>";

exit;

################

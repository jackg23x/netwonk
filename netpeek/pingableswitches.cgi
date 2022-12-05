#!/usr/bin/perl
# by jackg - Jack Gallagher
#
# pingableswitches.cgi
#
 
use strict;

print "Content-type: text/html\n\n<html><body>";
print "<title> pingableswitches: Switches that responded to ping in the previous run </title>";
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
## while ( my($x,$y) = each(%auth) )  {  print "$x<br>\n"; }
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

  my (@swpings,@nopings);
  my $query = "SELECT * FROM switch.ping";
  my $select_h  = $dbh->prepare($query);
  my $recs = $select_h->execute();
  if ($recs != 0) {
     while ( my $row = $select_h->fetchrow_arrayref ) {
        my ($swname,$swip,$ping) = @$row;
        if ($ping) { push @swpings, "$swname $swip"; }
        else       { push @nopings, "$swname $swip"; }
     }
  }
  @swpings = sort(@swpings);
  @nopings = sort(@nopings);

  my $blank  = "target = \"_blank\"";
  my $s2 = "&nbsp&nbsp";
  my $s4 = "&nbsp&nbsp&nbsp&nbsp";
  print "<a href=\"#ping\"><b> Pingable Switches </b></a><br><br>\n";
  print "$s4 Note: Some switches are merely pingable, and may not answer in any other way. <br><br>\n";
  print "<a href=\"#non\"><b> NON-Pingable Switches </b></a><br><br>\n";
  print "$s4 Note: Some of these may exist only as DNS entries. <br><br>\n";

  print "<hr><br>";
  print "<a name=\"ping\"><b> Current pingable switches on UIC networks </b></a><br><br>\n";
  print "<table border = 5>";
  print " <th> switch name </th> <th> switch ip </th>"; 
  foreach my $sw (@swpings)  { 
     my ($swname,$swip) = split " ", $sw;
     print "<tr> <td> <a href=\"netpeek/netpeek.cgi?submit=Submit&oper=query_ip&ip=$swip\" $blank > $swname </a> </td>"; 
     print "<td> $swip </td>";
  }
  print "</table> <br>";

  print "<hr><br>";
  print "<a name=\"non\" ><b>Current NON-pingable switches on UIC networks </b></a><br><br>\n";
  print "<table border=5> ";
  print "<th> switch IP  </th> <th> switch name </th>";
  foreach my $sw (@nopings)  {
     my ($swname,$swip) = split " ", $sw;
     print "<tr> <td> <a href=\"netpeek/netpeek.cgi?submit=Submit&oper=query_ip&ip=$swip\" $blank > $swname </a> </td>"; 
     print "<td> $swip </td>";
  }
  print "</table> <br> ";

exit;

##################


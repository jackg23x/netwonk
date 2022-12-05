#!/usr/bin/perl
# by jackg - Jack Gallagher
#
# reapmac.cgi
#
 
use strict;

print "Content-type: text/html\n\n<html><body>";
print "<title> reapmac totals - reapmac data by day </title>";
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
my $webcgi = webcgi();

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

print "<h3> reapmac data by day </h3>";
print "<b> How many mac addresses were last updated as seen on the day shown</b><br>";

my $s4 = "&nbsp&nbsp&nbsp&nbsp";
my $th = "<th rowspan=1 align=left>";
my $query    = "SELECT * FROM arp.reapmac ORDER by recent desc";
my $select_h = $dbh->prepare($query);
my $reaprets = $select_h->execute();
my $reaphash;
my $reapary;
if ($reaprets != 0) {
   while ( my $row = $select_h->fetchrow_arrayref ) {
      my ($mac,$recent,undef,undef,undef) = @$row;
      if (!exists $reaphash->{$recent})  {  push @$reapary,$recent;  }
      $reaphash->{$recent} += 1;  
   }
}
else  {  print "<font color=red> *** No data found in <b>arp.reapmac</b> <br><br>\n";  }
print "<table border=5>";
print "$th date </th> $th count </th> </tr> </b> \n";
foreach my $rec (@$reapary)  { 
    print "<td> $rec $s4 </td>  <td> ", $reaphash->{$rec} ,  " $s4 </td> </tr>\n";
}
print "</table>";
print "<br>";

exit;





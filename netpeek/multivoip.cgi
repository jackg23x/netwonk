#!/usr/bin/perl
#
# by jackg - Jack Gallagher
#

use strict;

print "Content-type: text/html\n\n<html><body>";
print "<title> multivoip - show ports with multiple voip phones </title>";
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
#######################################################################

my ($phoneh,$phary);
my $select_h = $dbh->prepare("SELECT swname,localPort,platform FROM switch.cdp;");
my $filtQrecs = $select_h->execute();
if ($select_h->rows != 0) {
   my $sel_ary = $select_h->fetchall_arrayref;
   foreach my $row (@$sel_ary)  {
      my ($swname,$lport,$plat) = @$row;
      if ($plat =~ /phone/i)  { $phoneh->{"$swname $lport"} += 1; }
   }
}

#foreach my $swp (keys %$phoneh)  {  print "$swp ", $phoneh->{$swp}, "<br>"; }
foreach my $k (keys %$phoneh)  {
   if ($phoneh->{$k} > 1) { push @$phary,$k; }
}

print "<br>\n";
print "<b> Switchports found with more than one VoIP phone in *today's* swseeker cdp run: </b><br>";
print "<br>\n";
print "<table border=5>";
print "<tr> <td><b> switch &nbsp&nbsp </b></td> 
       <td><b> port &nbsp&nbsp&nbsp </b></td> 
       <td><b> phones  &nbsp&nbsp&nbsp </b></td></tr>\n";
@$phary = sort @$phary;
foreach my $ph (@$phary)  {
  my ($swname,$lport) = split " ", $ph;
  my $phones = $phoneh->{$ph};
  print "<tr>\n";
  # print "<td> $swname </td>\n";
  my $href = "<a href=\"https://$webcgi/netpeek/sw.cgi?submit=Submit&oper=swlist&swnames=$swname\"> ";
  print "<td> $href $swname </a> </td> \n";
  print "<td> $lport  </td>\n";
  print "<td> $phones </td>\n";
  print "</tr>\n";
}

exit;

###################################################



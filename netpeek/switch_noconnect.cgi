#!/usr/bin/perl
# by jackg - Jack Gallagher
#
# switch_noconnect.cgi
#
 
use strict;

print "Content-type: text/html\n\n<html><body>";
print "<title> noconnect: Switches that have failed to connect in the past seven days by date </title>";
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

print "Switches that have failed to connect via script ssh (swmisc.pl) by date </h3>";

my $s4 = "&nbsp&nbsp&nbsp&nbsp";
my $th = "<th rowspan=1 align=left>";

my $query  = "SELECT * FROM switch.noconnect ORDER BY tstamp DESC";
my $select_h = $dbh->prepare($query);
my $noconnects = $select_h->execute();
if ($noconnects != 0) {
   my $days_h;
   while ( my $row = $select_h->fetchrow_arrayref ) {
      my ($swname,$swip,$tstamp) = @$row;
      if ($swname =~ /^\d\d/)  {  next;  }
      if ($swname =~ /^\d\d-\d/)  {  next;  }
      if ($swname =~ /ex\d\d00/) {  next;  }
      if ($swname =~ /qfx5110/)  {  next;  }
      my ($day,undef) = split " ", $tstamp;
      push @{$days_h->{$day}}, "$swname $swip $tstamp";
   }
   my $day_ary;
   while (my($x,$y) = each(%$days_h))  { push @$day_ary, $x; }
   @$day_ary = reverse(sort(@$day_ary));
   foreach my $day (@$day_ary)  {
      #print "<b> = $day $s4 ", scalar(@{$days_h->{$day}}), " switches </b> <br>";
      print "<h3> = $day $s4 ", scalar(@{$days_h->{$day}}), " switches </h3>";
      my $daysws;       ## array of switches in a day 
      foreach my $sw (@{$days_h->{$day}})  { push @$daysws, $sw; }
      print "<table border=5>";
      @$daysws = sort(@$daysws);
      foreach my $daysw (@$daysws)  {
         my ($swname,$swip,$tstamp) = split " ", $daysw, 3;
         print "<tr><td>$swname $s4</td> <td>$swip $s4</td> <td>$tstamp $s4</td</tr>";
      }
      print "</table>";
   }
}
else  {  print "<font color=red> *** No switches found that have failed to connect in the past seven days *** <br><br>\n";  }
print "<br>";

exit;

#!/usr/bin/perl
# by jackg - Jack Gallagher
#
# iproutes.cgi - show all routes in the routing talbe plus any custom static 
# routes added by edit withing this code -- that should be fixed so it's not a
# local edit, but it won't be by me -- maybe Mason or Paul
#
###  ATTENTION - DO NOT Edit in unusual routes here  *** 
###  Do that in lib/exroutes.pl                      *** 
#
 
use strict;

print "Content-type: text/html\n\n<html><body>";
print "<title> iproutes: Routes Internal and Connected</title>";
print "<body bgcolor=\"cccccc\">";

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

push @INC,"$installpath/lib";
require "exroutes.pl";
require "servers.pl";
my $nuser     = network();
my $domain    = dnssuffix();

use vars qw(%network_staff %noc_staff %security_staff %systems_staff);
require "$installpath/lib/auth.pl";
##########
my $host = $ENV{REMOTE_ADDR} || "host unknown";
my %auth = (%network_staff , %noc_staff , %security_staff, %systems_staff); 
my $netid = $ENV{REMOTE_USER} || "no user specified";
$netid =~ s/\/tacacs//;
if (exists $auth{$netid})  { print "netid '$netid' connecting from $host <br><br>\n"; }
else {
   print "<body bgcolor=red><br><br><h2><b><font color=green>User Authorization Failure</font></b><br><br>";
   print "<b> Use of this page by $netid not authorized. <br><br>";
   print "Please contact <a href=\"mailto:$nuser\@$domain\">$nuser\@$domain</a></b>\n";
   exit;
}
##########

my $iproute;  ## hash ref - all the routes
my $query  = "SELECT * FROM network.routes"; 
my $select_h  = $dbh->prepare($query);
my $recs = $select_h->execute();
if ($recs != 0) {
   while ( my $row = $select_h->fetchrow_arrayref ) {
      my ($route,$mask,$first,$last,$rtr,$vlan,$code) = @$row;
      $mask = "/"."$mask";
      if ($route eq "0.0.0.0")  { $route = "0.0.0.0:$rtr"; }
      my $rcolor = "#BBBBBB";
      my ($a,$b,$c,$d) = split /\./, $route;
      if ($d eq "0")  { 
         my $m = $c % 4;
         if ($m == 0)  { $rcolor = "#CCCCFF"; } 
         if ($m == 2)  { $rcolor = "#BBFFCC"; } 
      } 
      $iproute->{"$route $rtr $vlan"} = "$rcolor $route $mask $rtr $first $last $vlan $code";
   } 
}

my $exroute = exroutes();  ## hash ref for external routes - from lib/exroutes.pl
%$iproute = (%$iproute, %$exroute);  ## merge routes

my $gateways;  ## array ref
foreach my $gate (keys %$iproute)  {  push @$gateways, $gate;  }
$gateways = sort_by_ip($gateways);

my $exmessages = exmessages();  ## hash ref for messages about external routes - from lib/exroutes.pl
print "<hr>";
print "<b>Routing table entries for all connected networks</b> <br><br>\n";
print "<table>\n";
foreach my $msg (@$exmessages)  {  print "$msg";  }
print "<tr><td><b>S* </b></td><td> default route </td></tr>\n";
print "<tr><td><b>C </b></td><td> directly connected </td></tr>\n";
print "<tr><td><b>S </b></td><td> static routes, including those to internal networks. <br></td></tr>\n";
print "<tr><td><b>D </b></td><td> EIGRP routes from privately managed routers within local AS </td></tr>\n";     
print "<tr><td><b>D EX</td><td> EIGRP routes from external routers outside AS </td></tr>\n";
print "<tr><td><b>R </b></td><td> RIP routes from privately managed routers within local AS </td></tr>\n";
print "<tr bgcolor=#CCCCFF><td><b>Blue bars </b></td><td> /22 boundries </td></tr>\n";
print "<tr bgcolor=#BBFFCC><td><b>Green bars </b></td><td> /23 boundries </td></tr>\n";
print "</table><BR />\n";

print "<table> ";
print "<th align=left> IP Route   </th>";
print "<th align=left> Mask   </th>";
print "<th align=left> Router </th> ";
print "<th align=left> First Host </th>";
print "<th align=left> Last Host  </th>";
print "<th align=left> Vlan/Target </th> ";
print "<th align=left> Route Code </th>";

my $t = "<td align=left>";
foreach my $gate (@$gateways)  { 
   my($rcolor,$route,$mask,$rtr,$first,$last,$vlan,$code) = split " ", $iproute->{$gate}, 8;  ## 8th is code/comment - multi-word
   print "<tr bgcolor=$rcolor>$t $route</td>$t $mask</td>$t $rtr</td>$t $first</td>$t $last</td>$t $vlan</td>$t $code</td></tr>";
}
print "</table> ";

exit;

#################################################

sub sort_by_ip  {

my $iplist = shift;   ## array ref

@$iplist =
    map {$_->[0]}
    sort { ($a->[1] <=>$b->[1])
                || ($a->[2] <=>$b->[2])
                || ($a->[3] <=>$b->[3])
                || ($a->[4] <=>$b->[4]) }
    map {[$_, split( '[ \.]', $_) ]} @$iplist;
return ($iplist);
}  ## sort_by_ip
##################################################

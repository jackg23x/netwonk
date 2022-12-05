#!/usr/bin/perl 
# by jackg - Jack Gallagher  
#
# show all macfilters
#

use strict;

print "Content-type: text/html\n\n<html><body>";
print "<title> allmacfilters - current macfilters - 10 minute interval </title>";
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

my $oper = "main";
my %oper = ( main   => \&Front_Page,);
unless (exists $oper{$oper}) {
    print "Content-type: text/html\n\n<html><body>Bad action $oper \n</body></html>\n";
    exit;
}
$oper{$oper}->();
unless ($oper eq "main")  { Front_Page(); }
exit;

###################################################

sub Front_Page  {

  show_all();

  return;
}

###################################################

sub show_all  {

   my $s2 = "&nbsp&nbsp";
   my $blank  = "target = \"_blank\"";

   print "<b> Current macfilters: </b><br>";
   print "<table border=5>";
   print "<tr> <td><b> $s2 mac address $s2 $s2 </b></td> 
          <td><b> $s2 router $s2 $s2 </b></td> 
          <td><b> $s2 vlan   $s2 $s2 </b></td></tr>\n";
 
   my $query = "SELECT * FROM network.macfilters";
   my $select_h  = $dbh->prepare($query);
   my $recs = $select_h->execute();
   if ($recs != 0) {
      while ( my $row = $select_h->fetchrow_arrayref ) {
         my ($mac,$router,$vlan) = @$row;
         if ($mac eq "0000.0000.0000")  { next; }
         print "<tr>";
         print "<td> <a href=\"https://$webcgi/netpeek/netpeek.cgi?submit=Submit&oper=query_mac&mac=$mac\" $blank > $mac </a> $s2 </td>";
         print "<td> $s2 $router </td>";
         print "<td> $s2 $vlan   </td>";
         print "</tr>";
      }
   }
   print "</table>\n";

   return;

}

###################################################


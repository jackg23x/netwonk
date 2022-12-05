#!/usr/bin/perl 
# by jackg - Jack Gallagher
#
# show all switch macfilters
#

use strict;

print "Content-type: text/html\n\n<html><body>";
print "<title> allswmacfilters - current switch macfilters </title>";
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
### while ( my($x,$y) = each(%auth) )  {  print "$x<br>\n"; }
my $netid = $ENV{REMOTE_USER} || "no user specified";
$netid =~ s/\/tacacs//;
if (exists $auth{$netid})  {  print "netid '$netid' connecting from $host <br><br>\n";  }
else {
  print "<body bgcolor=red><br><br><h2><b><font color=green>User Authorization Failure</font></b><br><br>";
  print "<b> Use of this page by $netid not authorized. <br><br>";
  print "Please contact <a href=\"mailto:$nuser\@$domain\">$nuser\@$domain</a></b>\n";
  exit;
}
########################################################################

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

   my $select_h  = $dbh->prepare("SELECT * FROM network.swmacfilters;");
   my $filtrecs = $select_h->execute();
   if ($filtrecs != 0) {
      my $mac_h;
      while ( (my @row) = $select_h->fetchrow_array ) {
         my ($mac,$swname,$vlan,$datefilt) = @row;
         $mac_h->{$mac} = "$swname $vlan $datefilt";
      }
      my $macs;  ## array ref
      foreach my $mac (sort keys %$mac_h)  {  push @$macs, $mac;  }
      my $ct = scalar(@$macs);
      print "<h3> Current swmacfilters: </h3>\n";
      print "<b> $ct filters</b><br>\n";
      print "<table border = 5>\n";
      print "<tr> <td><b> mac <br></td> <td><b> swname <br></td> <td><b> vlan <br></td> <td><b> tstamp <br></td>  </tr>";
      my $s4 = "&nbsp;&nbsp;&nbsp;&nbsp;";
      foreach my $mac (@$macs)  {
         my ($swname,$vlan,$datefilt) = split " ", $mac_h->{$mac}, 3;   # 3 keeps the datefilt together
         print "<tr> <td> $mac $s4 </td> <td> $swname $s4 </td> <td> $vlan $s4 </td> <td> $datefilt $s4 </td>  </tr>";
      }
      print "</table>\n";
      print "<hr> <b> Just the macs, only the macs (good for cut-n-paste): </b> <br><br>\n";
      foreach my $mac (@$macs)  {  print "$mac <br>";  }
   }
   else { print "No swmacfilters in force at this time<br><br>\n"; }

   return;

}

###################################################


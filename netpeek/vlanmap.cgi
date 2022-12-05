#!/usr/bin/perl 
# by jackg - Jack Gallagher
#

use strict;

print "Content-type: text/html\n\n<html><body>";
print "<title> vlanmap - vlan data, dhcpservers, descriptions - for routers and firewalls </title>";
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

   print "<br>";
   print "<a href=\"#border\"><b> Jump to Border Vlan Listing </b></a><br><br>\n";
   print "<hr>";
   
   print "<br><b> CORE VTP domain Vlans with related network and dhcpserver info: </b><br><br>\n";
   print "<table border=\"5\" cellpadding=\"2\">";
   print "<tr> <td><b> vlan   &nbsp&nbsp </b></td> 
          <td><b> router </b></td> 
          <td><b> network </b></td> 
          <td><b> gateway level </b></td> 
          <td><b> dhcp server </b></td> 
          <td><b> state &nbsp&nbsp&nbsp </b></td> 
          <td><b> description &nbsp&nbsp&nbsp </b></td></tr>\n"; 
   my @vlans;
   my $query = "SELECT * FROM network.vlanmap";
   my $select_h  = $dbh->prepare($query);
   my $recs = $select_h->execute();
   if ($recs != 0) {
      while ( my $row = $select_h->fetchrow_arrayref ) {
         my $ln = join " ",@$row;
         push @vlans, $ln;
      }
   }
   ################# Overrides ############
   # reserved vlans -jlm 2021-11-19
   push @vlans, "685 reserved 0.0.0.0 reserved AITS layer2 reserved for AITS";
   push @vlans, "686 reserved 0.0.0.0 reserved AITS layer2 reserved for AITS";
   push @vlans, "711 reserved 172.29.11.0/24 reserved UIH layer2 UIH desktops East of Wood";
   push @vlans, "712 reserved 172.29.12.0/24 reserved UIH layer2 UIH desktops West of Wood";
   # research vlans -jlm 2021-11-19
   for (my $rvlan = 1600; $rvlan <= 1699; $rvlan++) {
      my $rvln = "$rvlan research 0.0.0.0 reserved none reserved for research network";
      push @vlans, $rvln;
   }
   push @vlans, "4094 reserved 172.26.94.0/24 reserved startel airgap startel voip in nodes";
   ########################################
   my $border_vlans;
   @vlans = sort {$a <=> $b} @vlans;  
   foreach my $v (@vlans)  {
      my ($vlan,$router,$subnet,$status,$dhcpserver,$state,$desc) = split / /, $v, 7; ## 7 to get whole description!
      if ($router =~ /\A31|41\z/)  {
         push @$border_vlans, "$vlan $router $subnet $status $dhcpserver $state $desc";
         next;
      }
      print "<tr>\n";
      my $blank  = "target = \"_blank\"";
      my $href = "<a href=\"https://$webcgi/netpeek/netpeek.cgi?submit=Submit&oper=query_vlan&vlan=$vlan\"  $blank > ";
      print "<td> $href $vlan </td>\n";
  
      if ($router !~ '\.') {  print "<td><font color=\"red\"> $router </font></td>\n";  } 
      elsif ($router =~ /\.$/)  {
         $router =~ s/\.$//;
         print "<td> <font color=purple> $router </font> </td>\n";
      }
      else  {
         $router =~ s/\.$//;
         print "<td> $router </td>\n";
      }
  
      if ($subnet !~ '^10\.' ) {  print "<td> $subnet </td>\n";   } 
      else  {  print "<td><font color=\"green\"> $subnet </font></td>\n"; }
  
      if ($status eq "secondary") {  print "<td><font color=\"red\"> $status </font></td>\n";   } 
      else  {  print "<td> $status </td>\n"; }
  
      if ($dhcpserver eq "128.248.155.124")   {  print "<td><font color=\"green\"> $dhcpserver </font></td>\n";  } 
      elsif ($dhcpserver eq "192.43.252.231") {  print "<td><font color=\"blue\"> $dhcpserver </font></td>\n";  } 
      elsif ($dhcpserver eq "none")           {  print "<td><font color=\"red\"> $dhcpserver </font></td>\n";  } 
      else  {  print "<td> $dhcpserver </td>\n"; }
  
      if ($state eq "shutdown") {  print "<td><font color=\"red\"> $state </font></td>\n";  }
      else  {  print "<td> $state </td>\n"; }
      print "<td> $desc </td>\n";
      print "</tr>\n";
  }
  
  print "</table>\n";    
            
  ## OK, let's do the @$border_vlans now:

  print "<br> <hr> <br>\n";
  print "<a name=\"border\"><b> Vlans defined on the network border, not part of router CORE (may exist independently in both environs): </b></a><br><br>\n";

  print "<table border=\"5\" cellpadding=\"2\">";
  print "<tr> <td><b> vlan   &nbsp&nbsp </b></td> 
         <td><b> router </b></td> 
         <td><b> network </b></td> 
         <td><b> gateway level </b></td> 
         <td><b> dhcp server </b></td> 
         <td><b> state &nbsp&nbsp&nbsp </b></td> 
         <td><b> description &nbsp&nbsp&nbsp </b></td></tr>\n";
  foreach my $bv (@$border_vlans)  {
     my ($vlan,$router,$subnet,$status,$dhcpserver,$state,$desc) = split / /, $bv, 7; ## 7 to get whole description!
     print "<tr>\n";
     print "<td> $vlan </td>\n";
 
     if ($router !~ '\.') { print "<td><font color=\"red\"> $router </font></td>\n";  }
     else                 { print "<td> $router </td>\n"; }
 
     if ($subnet !~ '^10\.' ) { print "<td> $subnet </td>\n";   }
     else                     { print "<td><font color=\"green\"> $subnet </font></td>\n"; }
 
     if ($status eq "secondary") { print "<td><font color=\"red\"> $status </font></td>\n";   }
     else                        { print "<td> $status </td>\n"; }
 
     if ($dhcpserver eq "128.248.155.124")   { print "<td><font color=\"green\"> $dhcpserver </font></td>\n";  }
     elsif ($dhcpserver eq "192.43.252.231") { print "<td><font color=\"blue\"> $dhcpserver </font></td>\n";  }
     elsif ($dhcpserver eq "none")           { print "<td><font color=\"red\"> $dhcpserver </font></td>\n";  }
     else                                    { print "<td> $dhcpserver </td>\n"; }
 
     if ($state eq "shutdown") { print "<td><font color=\"red\"> $state </font></td>\n";  }
     else                      { print "<td> $state </td>\n"; }
     print "<td> $desc </td>\n";
     print "</tr>\n";
  }
  print "</table>\n";
   
  return;
}

###################################################

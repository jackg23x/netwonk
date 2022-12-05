#!/usr/bin/perl
# by jackg - Jack Gallagher
#

use strict;

print "Content-type: text/html\n\n<html><body>";
print "<title> errdis - error-disabled switch ports </title>";
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
########################################################################

my $oper;
my $msg;   ## for passing error mes to Front_Page
   $oper       = $in->param('oper');
my $switchname = $in->param('switchname');
my $portname   = $in->param('portname');
my $submit     = $in->param('submit');

if ($submit eq "")  {
   print "<br>\n";
   Front_Page();
   exit;
   ##exit;  ## ???
}

my %oper    = (
    'main'     => sub{ Front_Page($msg)   },
    'queue_port_reset'  => sub{ queue_port_reset($switchname,$portname,$netid) },
    );
unless ($oper{$oper}) {
    print "Content-type: text/html\n\n<html><body>Bad query: $oper\n</body></html>\n";
    exit;
}
$oper{$oper}->();

exit;

#######################################

sub Front_Page  {

   my $msg = shift || "";

   print "<font color=red> $msg </font> \n";
   print "<form method=\"post\" action=\"$ENV{'SCRIPT_NAME'}\">";

   my $s2 = "&nbsp&nbsp";
   my $s3 = "&nbsp&nbsp&nbsp";
   my $blank  = "target = \"_blank\"";
   print "<br><b> Current err-disabled ports on reachable switches: </b><br><br>";
   print "<table border=5>";
   print "<tr> <td><b> switch name $s2 </b></td>
          <td><b> switch ip  </b></td>
          <td><b> port   $s3 </b></td>
             <td><b> tstamp $s3 </b></td>
          <td><b> reason $s3 </b></td></tr>\n";
   my $query = "SELECT * FROM switch.errdis ORDER BY swname;";
   my $select_h  = $dbh->prepare($query);
   my $recs = $select_h->execute();
   if ($recs != 0) {
      while ( my $row = $select_h->fetchrow_arrayref ) {
         my ($swip,$swname,$port,$tstamp,$reason) = @$row;
         if ($port eq "")  { $port = "unknown"; }
         print "<tr>\n";
         my $href = "<a href=\"https://$webcgi/netpeek/sw.cgi?submit=Submit&oper=swlist&swnames=$swname\" $blank > $swname </a> ";
         print "<td> $href $s2 </td>\n";
         print "<td> $swip $s2 </td>\n";
         print "<td> $port $s2 </td>\n";
         print "<td> $tstamp $s2 </td>\n";
         print "<td> $reason $s2 </td>\n";
         my $np    = "https://$webcgi/netpeek/errdis.cgi";
         my $parms = "?submit=Submit&oper=queue_port_reset&switchname=$swname&portname=$port";
         print "<td> <a href=\"$np$parms\" $blank > queue for reset $s2";
         print "</tr>\n";
      }
      print "</table>\n";
   }
   else  {
      print "</table> <br> <font color=red> No entries found in switch.errdis database table. <br>";
   }
   print "<br><br>";

   ## Print the current swportresetQ
   print_swportresetQ();
   print "<br>";
   print25_swportresetlog();
   print "<br>";
   print25_swportresetfail();
   print "<br>";

   return;
}  ## Front_Page

##############################

sub queue_port_reset  {

   ## parameters reference a switchport we're trying to process

   my $switchname = shift;
   my $portname   = shift;
   my $netid      = shift;

   print "queueing port $portname on switch $switchname for reset... <br><br>\n";

   my $query = "SELECT * FROM network.swportresetQ WHERE swname = \"$switchname\" AND port = \"$portname\";  ";
   my $select_h  = $dbh->prepare($query);
   my $recs = $select_h->execute();
   if ($recs != 0) {
      ## we found an existing entry in the queue for this port - good enough
      print " = port previously queued = <br><br>\n";
   }
   else  {
      my $insert_h  = $dbh->prepare("INSERT into network.swportresetQ (swname,port,netid) VALUES (?,?,?)");
      $insert_h->execute($switchname,$portname,$netid);
      print " = port $switchname:$portname queued = <br><br>\n";
   }

   print_swportresetQ();

   return;
}  ## queue_port_reset

#####################################################################

sub print_swportresetQ  {

   ## print the current swportresetQ
   print "<b>Current port reset queue (network.swportresetQ): </b> <br><br>\n";
   my $query = "SELECT * FROM network.swportresetQ;";
   my $select_h  = $dbh->prepare($query);
   my $recs = $select_h->execute();
   my $Qlines;
   if ($recs != 0) {
      while ( my $row = $select_h->fetchrow_arrayref ) {
         my ($swname,$port,$netid) = @$row;
         push @$Qlines, "$swname $port $netid";
      }
   }
   else  {
      print "&nbsp&nbsp * No ports currently scheduled for reset in network.swportresetQ <br><br>";
      return;
   }

   print "<table border=5>";
   print "<th> switchname </th> <th> port </port> <th> netid </th>";
   @$Qlines = sort @$Qlines;
   foreach my $qln (@$Qlines) {
      my($sw,$po,$ne) = split " ", $qln;
      print "<tr> <td> $sw </td> <td> $po </td> <td> $ne </td> </tr>";
   }
   print "</table>";

   return;
}  ## print_swportresetQ

##########################################################################

sub print25_swportresetlog  {

   print "<b>25 most recent resets from port reset log (network.swportresetlog): </b> <br><br>\n";
   my $query = "SELECT * FROM network.swportresetlog ORDER BY tstamp DESC LIMIT 25";
   my $select_h  = $dbh->prepare($query);
   my $recs = $select_h->execute();
   my $loglines;
   if ($recs != 0) {
      while ( my $row = $select_h->fetchrow_arrayref ) {
         my ($swname,$port,$netid,$tstamp) = @$row;
         push @$loglines, "$swname $port $netid $tstamp";
      }
   }

   print "<table border=5>";
   print "<th> switchname </th> <th> port </th> <th> netid </th> <th> tstamp </th>  ";
   foreach my $ln (@$loglines) {
      my($sw,$po,$ne,$ts) = split " ", $ln;
      print "<tr> <td> $sw </td> <td> $po </td> <td> $ne </td> <td> $ts </td>  </tr>";
   }
   print "</table>";

   return;

}   ## print25_swportresetlog

##########################################################################

sub print25_swportresetfail  {

   print "<b>25 most recent resets from port reset log (network.swportresetfail): </b> <br><br>\n";
   my $query = "SELECT * FROM network.swportresetfail ORDER BY tstamp DESC LIMIT 25";
   my $select_h  = $dbh->prepare($query);
   my $recs = $select_h->execute();
   my $loglines;
   if ($recs != 0) {
      while ( my $row = $select_h->fetchrow_arrayref ) {
         my ($swname,$port,$netid,$tstamp,$comment) = @$row;
         push @$loglines, "$swname $port $netid $tstamp $comment";
      }
   }

   print "<table border=5>";
   print "<th> switchname </th> <th> port </th> <th> netid </th> <th> tstamp </th> <th> comment </th> ";
   foreach my $ln (@$loglines) {
      my($sw,$po,$ne,$dt,$tm,$cm) = split " ", $ln, 6;
      my $ts = "$dt $tm";
      print "<tr> <td> $sw </td> <td> $po </td> <td> $ne </td> <td> $ts </td> <td> $cm </td>  </tr>";
   }
   print "</table>";

   return;

}   ## print25_swportresetfail

##########################################################################

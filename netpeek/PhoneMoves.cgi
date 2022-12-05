#!/usr/bin/perl
# by jackg - Jack Gallagher
#
# PhoneMoves.cgi - tracks movement of IP phones
#

use strict;

print "Content-type: text/html\n\n<html><body>";
print "<title> PhoneMoves - installs and moves of VoIP phones </title>";
print "<body bgcolor=\"bbbbbb\">";

use Net::DNS;
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
require "servers.pl";
my $admin     = admin();
my $netmgr    = netmgr();
my $neteng    = neteng();
my $nuser     = network();
my $domain    = dnssuffix();
my $webcgi    = webcgi();

########## LOCAL AUTH CODE ############################################
require "$installpath/lib/auth.pl";
use vars qw(%network_staff %noc_staff %security_staff %systems_staff %auth $datethresh);
my $host = $ENV{REMOTE_ADDR} || "host unknown";
my %auth_hash = (%network_staff,%noc_staff,%systems_staff,%auth);
## while ( my($x,$y) = each(%auth_hash) )  {  print "$x<br>\n"; }
my $netid = $ENV{REMOTE_USER} || "no user specified";
$netid =~ s/\/tacacs//;
if (exists $auth_hash{$netid})  {
   print "netid '$netid' connecting from $host <br> <hr> \n";
}
else {
   print "<body bgcolor=red><br><br><h2><b><font color=green>User Authorization Failure</font></b><br><br>";
   print "<b> Use of this page by $netid not authorized. <br><br>";
   print "Please contact <a href=\"mailto:$nuser\@$domain\">$nuser\@$domain</a></b>\n";
   exit;
}
########################################################################

my $oper         = $in->param('oper');
my $submit       = $in->param('submit');
my $phonemovesdb = $in->param('phonemovesdb');
my $records      = $in->param('records');
my $datesearch   = $in->param('datesearch');
my $date1        = $in->param('date1');
my $date2        = $in->param('date2');
my $s2 = "&nbsp&nbsp";
my $s4 = "&nbsp&nbsp&nbsp&nbsp";


if ($submit eq "Submit")  {
   unless ($oper)  {
      my $msg = "Please enter a search query.<br><br>\n";
      $oper = "main";
      Front_Page($msg);
      exit;
   }
}
else  {  $oper = "main";  }  ## All the action starts here

print "<a name=\"TOP\"> </a><br>\n";

my %oper    = (
    'main'         => sub{ Front_Page()   },
    'phonemovesdb' => sub{ phonemovesdb_query($records) },
    'datesearch'   => sub{ datesearch_query($date1,$date2) },
    );

unless ($oper{$oper}) {
    print "Content-type: text/html\n\n<html><body>Bad query: $oper\n</body></html>\n";
    exit;
}
$oper{$oper}->();
exit;

##################

sub Front_Page  {

my $msg = shift || "";
print "<font color=red> $msg </font> \n";

print <<EOF;
<form method=\"post\" action=\"$ENV{'SCRIPT_NAME'}\">
<h3> PhoneMoves.cgi - installs and moves of VoIP phones </h3>
<input type=\"submit\" value=\"Submit\" name=\"submit\" >
<br><br>
EOF

print <<EOF;
<input type=radio name="oper" value="phonemovesdb" checked>
<select name="records">
  <option value="50">   show the last 50 records in the   </option>
  <option value="100">  show the last 100 records in the  </option>
  <option value="250">  show the last 250 records in the  </option>
  <option value="all">  show all records in the </option>
</select>
<b> switch.phone_moves database </b> (log table of all VoIP phone move and install activity)
<br><br><br>

<table>
<tr>
<td> <input type=radio name="oper" value="datesearch">
     <b> Search for date (Optional - use as start date): </b> </td>
<td> <input type=\"text\" size=12 name=\"date1\" value=\"\" > </td> 
     <td> <b> &nbsp&nbsp (Optional - end date: </b> </td>
     <td> <input type=\"text\" size=12 name=\"date2\" value=\"\" > <b> ) </b> </td>
     <td> <b> &nbsp&nbsp date format yyyy-mm-dd </b> </td> </tr>
</table>
<br><br>
EOF

print <<EOF;
<input type=\"submit\" value=\"Submit\" name=\"submit\" >   <br> <br>
<hr>
In case of problems with this page, send email to
<em> <a HREF=\"mailto:$nuser\@$domain\"> the ACCC Network Group </a> </em> <br><hr>
EOF

return;

}  ## Front_Page

###################################

sub phonemovesdb_query {

my $records = shift;

#print "{phonemovesdb_query}: >$records< <br>";

  print "<a HREF=\"https://$webcgi/netpeek/PhoneMoves.cgi\"> ";
  print "Back to PhoneMoves home page </a> <br><br>";

  my $query;
  if ($records eq "all")  {
    print "Current contents of the entire switch.phone_moves database:<br><br>\n";
    $query = "SELECT * FROM switch.phone_moves ORDER BY tstamp DESC;";
  }
  else   {
    print "<b> $records most recent entries </b> from the switch.phone_moves database:<br><br>\n";
    $query = "SELECT * FROM switch.phone_moves ORDER BY tstamp DESC LIMIT $records ;";
  }
  my $select_h = $dbh->prepare($query);
  $select_h->execute();
  if ($select_h->rows != 0) {
     print "<table border=5>";
     ## print header
     my $header_h = $dbh->prepare("DESCRIBE switch.phone_moves;");
     my $header_recs = $header_h->execute();
     my $fields;
     while ( (my @row) = $header_h->fetchrow_array ) { push @$fields, $row[0]; }
     foreach my $field (@$fields)  { print "<th align=left> $field </th> "; }
     ## print records
     while ( (my $row) = $select_h->fetchrow_arrayref ) {
        my ($tstamp,$phone,$previp,$prevname,$prevport,$currip,$currname,$currport) = @$row;
        print "<tr> <td>$tstamp</td> <td>$phone</td> <td>$previp</td> <td>$prevname</td> <td>$prevport</td> <td>$currip</td> <td>$currname</td> <td>$currport</td> </tr>";
     }
     print "</table>";
  }
  else  { print "switch.phone_moves database is currently <b>empty!</b> <br>\n"; }

return;

}

###################################

sub datesearch_query {

my $date1 = shift;
my $date2 = shift;

#print "{datesearch_query}: >$date1<  >$date2< <br>";

  print "<a HREF=\"https://$webcgi/netpeek/PhoneMoves.cgi\"> ";
  print "Back to PhoneMoves home page </a> <br><br>";

  my $query;
  if ($date2 eq "")  {
    print "Records in switch.phone_moves database for $date1:<br><br>\n";
    $query = "SELECT * FROM switch.phone_moves WHERE tstamp LIKE \"$date1%\" ORDER BY tstamp DESC;";
  }
  else   {
    print "<b> Records in switch.phone_moves database from $date1 through $date2:<br><br>\n";
    $query = "SELECT * FROM switch.phone_moves WHERE (tstamp >= \"$date1%\" and tstamp <= \"$date2 23:59:59\") ORDER BY tstamp DESC ;";
  }
  my $select_h = $dbh->prepare($query);
  $select_h->execute();
  if ($select_h->rows != 0) {
     print "<table border=5>";
     ## print header
     my $header_h = $dbh->prepare("DESCRIBE switch.phone_moves;");
     my $header_recs = $header_h->execute();
     my $fields;
     while ( (my @row) = $header_h->fetchrow_array ) { push @$fields, $row[0]; }
     foreach my $field (@$fields)  { print "<th align=left> $field </th> "; }
     ## print records
     while ( (my $row) = $select_h->fetchrow_arrayref ) {
        my ($tstamp,$phone,$previp,$prevname,$prevport,$currip,$currname,$currport) = @$row;
        print "<tr> <td>$tstamp</td> <td>$phone</td> <td>$previp</td> <td>$prevname</td> <td>$prevport</td> <td>$currip</td> <td>$currname</td> <td>$currport</td> </tr>";
     }
     print "</table>";
  }
  else  { print "switch.phone_moves database is currently <b>empty!</b> <br>\n"; }

return;

}

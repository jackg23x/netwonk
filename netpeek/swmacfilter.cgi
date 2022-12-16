#!/usr/bin/perl
# by jackg - Jack Gallagher
#
# swmacfilter.cgi -- filter/unfilter mac addresses on switches, query db tables
#
 

use strict;

print "Content-type: text/html\n\n<html><body>";
print "<title> swmacfilter - filter/unfilter mac addresses on switches, query db tables  </title>";
print "<body bgcolor=\"bbbbbb\">\n";

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
my $admin  = admin();
my $nuser  = network();
my $domain = dnssuffix();
my $webcgi = webcgi();
my $webid  = user();
my $webbox = webserver();
my $blank  = "target=\"_blank\"";

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

my $emsg;
my $submit  = $in->param('submit');
my $oper    = $in->param('oper');
my $records = $in->param('records');
my $addr    = $in->param('addr');
   $addr    =~ s/\s+//g;
   $addr    =~ s/,//g;
my $comment = $in->param('comment');
   $comment =~ s/^\s+//g;
   $comment =~ s/\s+$//g;
   $comment =~ s/,/ -/g;  ## commas are used for field separators!! must translate them.
   $comment =~ s/'//g;  
   $comment =~ s/"//g;  

my ($date,$time)=date_time();
my $tstamp = "$date"."_"."$time"; 

if (($submit eq "Submit") && (!$oper))  {
  $emsg = "Please choose an action.<br><br>\n";
  $oper = "main";
  Front_Page($emsg);
  exit;
}   
elsif  (!$submit)  {  $oper = "main";  }

#print "oper = $oper<br>";
#print "addr = $addr<br>";

my %oper = (
            main            => \&Front_Page,
            filter          => sub{insert_filterQ("filter",$addr,$netid,$tstamp,$comment)},
            unfilter        => sub{insert_filterQ("unfilter",$addr,$netid,$tstamp,$comment)},
            query_mac       => sub{query_mac($addr)},
            filterQ         => \&print_filterQ,
            clearfilterQ    => \&clear_filterQ,
            swmacfilters    => \&print_swmacfilters,
            swmacfilterlog => sub{print_swmacfilterlog($records)},
           );

unless (exists $oper{$oper}) {
    print "Content-type: text/html\n\n<html><body>Bad action $oper \n</body></html>\n";
    exit; 
}   
$oper{$oper}->();

print "<br>\n";
print "<a HREF=\"https://$webcgi/netpeek/swmacfilter.cgi\"> ";      
print "back to swmacfilter home page </a> <br><hr>";

exit;


############################

sub no_web_access  {

  my $host = shift;
  print "Sorry to say, your host $host does not have access to this page<br><br>\n";
  print "If you think this is in error, please contact Networking via email: <br><br>\n";
  print "<em> <a HREF=\"mailto:$nuser\@$domain\"> Click to Email the Network Group </a> </em> <br>\n";
  print "Email address: <b> $nuser\@$domain </b> <br><br><hr>\n";
}

############################

sub Front_Page  {

my $msg = shift || "";
if ($msg ne "")  {  print "<br><font color=red><b> $msg </b> </font> \n";  }

print <<EOF;
<form method=\"post\" action=\"$ENV{'SCRIPT_NAME'}\">
<h3> swmacfilter - filter/unfilter mac addresses on switches, query existing filter data </h3>
The swmacfilter queue is processed, at which time filters 
become active and show up under the selection <b>show all current swmacfilters</b>  <br><br>
EOF

print <<EOF;
<table>
<tr> <td><input type=\"text\" size=32 name=\"addr\" value=\"\" ></td> <td> filter/unfilter: host or network address </td> </tr>
<tr> <td><input type=\"text\" size=32 name=\"comment\" value=\"\" ></td> <td> reason or comment for filter/unfilter </td> </tr>
</table>
<br>
<b> Address Actions: </b>  <br>
<input type=radio name="oper" value="filter"> <b> filter </b> this address  <br>
<input type=radio name="oper" value="unfilter"> <b> unfilter </b> this address <br>
<input type=radio name="oper" value="query_mac"> <b> query </b> swmacfilterlog for this address  <br>
<br>
<b> No Address needed: </b>  <br>
<input type=radio name="oper" value="filterQ">  show current     <b> swmacfilter queue </b> <br>
<input type=radio name="oper" value="swmacfilters"> show all current <b> swmacfilters  </b> <br>
<input type=radio name="oper" value="swmacfilterlog">   
<select name="records">
  <option value="20">   show the last 20 records in the   </option>
  <option value="50">   show the last 50 records in the   </option>
  <option value="100">  show the last 100 records in the   </option>
  <option value="full"> show the full </option>
</select>
<b> swmacfilterlog </b> (log table of all swmacfilter activity)
<br><br>
<input type=radio name="oper" value="clearfilterQ">
<font color=red><b>CLEAR swmacfilterQ!</b></font> 
Please be <font color=green><b>Careful</b></font>, this is not reversible 
<br><br>

<input type=\"submit\" value=\"Submit\" name=\"submit\" >   <br> <br>

<hr>
In case of problems with this page, send email to
<em> <a HREF=\"mailto:$nuser\@$domain\"> the Network Group </a> </em> <br><hr>

EOF

return;
}  ## Front_Page

###################################

sub query_mac  {

  my $mac = shift;

  print "<form method=\"post\" action=\"$ENV{'SCRIPT_NAME'}\">";
  print "<a HREF=\"https://$webcgi/netpeek/swmacfilter.cgi\"> ";
  print "back to swmacfilters home page </a> <br><hr>";

  print "<br>";
  if ($mac !~ /[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}/)  {  print "mac $mac is a malformed mac <br>";  }

  my $s2 = "&nbsp&nbsp";
  my $th = "<th rowspan=1 align=left>";
  my $query = "SELECT * FROM network.swmacfilterlog where mac=\"$mac\" ORDER BY datefilt DESC ;";
  my $select_h  = $dbh->prepare($query);
  $select_h->execute();
  if ($select_h->rows != 0) {
     print "&nbsp <b> network.swmacfilterlog </b> entries for <b> $mac:</b> <br>";
     my $sel_ary = $select_h->fetchall_arrayref;
     print "<table border=5> ";
     print "$th datefilt</th> $th operation</th> $th mac</th> $th vlan</th> $th swname</th> $th netid</th> $th comment $s2</th> \n";
     foreach my $row (@$sel_ary)  {
        my ($datefilt,$operation,$mac,$vlan,$swname,$netid,$comment) = @$row;
        my $href = "<a href=\"https://$webcgi/netpeek/netpeek.cgi?submit=Submit&oper=query_mac&mac=$mac\" $blank > ";
        print "<tr><td>$datefilt $s2</td> <td>$operation $s2</td> <td>$href $mac $s2 </a></td> <td>$vlan $s2</td> <td>$swname $s2</td> <td>$netid $s2</td> <td>$comment $s2</td></tr>";
     }
     print "</table>";
  }
  else  {  print "No <b>network.swmacfilterlog</b> entries found for <b>$mac</b> <br><br>\n";  }
  print "<br><br>";

  ## Check network.swmacfilterQ to see if activity has been queued
  my $select_h  = $dbh->prepare("SELECT * from network.swmacfilterQ where mac = \"$mac\";");
  $select_h->execute();
  if ($select_h->rows != 0) {
     my $sel_ary = $select_h->fetchall_arrayref;

     print "<b> $mac </b> is currently queued for activity as follows: <br>";
     print "<table>";
     foreach my $row (@$sel_ary)  {
        print "<tr>";
        foreach my $r (@$row)  {   print "<td> $r $s2 </td>";   }
        print "</tr>";
     }
     print "</table>  <br>\n";
  }
  else  {  print "No filter/unfilter actions in <b>network.swmacfilterQ</b> for <b> $mac </b>  <br><br>";  }
  print "<br>";

  ## Check current filter status
  my $select_h  = $dbh->prepare("SELECT * from network.swmacfilters where mac = \"$mac\";");
  $select_h->execute();
  if ($select_h->rows != 0) {
     print "<b> $mac </b> currently shows as filtered in the <b>network.swmacfilters</b> database:<br>";
     print "<table border=5>\n";
     print "<tr> <td><b>mac</td> <td><b>swname</td> <td><b>vlan</td> <td><b>datefilt</b></td> </tr>";
     my $sel_ary = $select_h->fetchall_arrayref;
     foreach my $row (@$sel_ary)  {
        ##foreach my $r (@$row)  {   print "$r <br>";   }
        my (undef,$swname,$vlan,$datefilt) = @$row;
	print "<tr> <td>$mac</td> <td>$swname</td> <td>$vlan</td> <td>$datefilt</td> </tr>";
     }
     print "</table>";
  }
  else  { print  "<b> $mac </b> shows as not filtered in the network.swmacfilters database <br>";  }

  print "<br><br><hr><br>";
  Front_Page($emsg);
  return;
 
} ## query_mac 

###################################

sub insert_filterQ  {

  my $oper    = shift;
  my $mac     = shift;
  my $netid   = shift;
  my $tstamp  = shift;
  my $comment = shift;

  # print "{insert_filterQ}: $oper, $mac, $netid, $tstamp, $comment<br>\n";

  if ($mac !~ /\A[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\z/) {
     my $emsg = " *** mac $mac is invalid - please input valid mac\n";
     Front_Page($emsg);
     return;
  }
  print "<br>";
  my $query = "SELECT * from network.swmacfilterQ WHERE mac=\"$mac\" and operation=\"$oper\" ; ";
  my $select_h  = $dbh->prepare($query);
  my $filtQrecs = $select_h->execute();
  if ($filtQrecs != 0) {
     print "mac $mac is already currently queued for <b>$oper</b> processing. <br><br>\n";
     print_filterQ();  ## prints filterQ
     return;
  }
  my $insert_h = $dbh->prepare("INSERT IGNORE INTO network.swmacfilterQ (mac,operation,dateQ,netid,comment) VALUES (?,?,?,?,?)");
  if ($comment eq "")  {  $comment = "none";  }
  $insert_h->execute($mac,$oper,$tstamp,$netid,$comment);
  print "<b> mac $mac processed for $oper", " -- added to network.swmacfilterQ</b> <br><br>";
  print_filterQ();

} ## insert_filterQ

##################################

sub clear_filterQ  {

  my $select_h = $dbh->prepare("SELECT * from network.swmacfilterQ;");
  my $filtQrecs = $select_h->execute();
  if ($select_h->rows != 0) {
     print "<br> Entries deleted from swmacfilterQ: <br>\n";
     print "<table border=5>";
     my $sel_ary = $select_h->fetchall_arrayref;
     foreach my $row (@$sel_ary)  {
        my ($mac,$swname,$vlan,$datefilt) = @$row;
        print "<tr> <td>$mac</td> <td>$swname</td> <td>$vlan</td> <td>$datefilt</td> </tr>";
     }
     print "</table>";
     my $delete_h = $dbh->prepare("DELETE FROM network.swmacfilterQ;");
     my $success;                                   
     eval {  $success = $delete_h->execute()  };
     if ($success)  {
        print  "<br> <font color=red> <b> swmacfilterQ </b> has been cleared.  This action cannot be reversed. </font> <br> \n"; 
     }
     else  {  print "Error: $@ <br>\n";  }
  }
  else  {  print "<br>No entries in <b>network.swmacfilterQ</b> at present<br>"; }

  print "<br><hr>";
  Front_Page($emsg);
  return;

} ## clear_filterQ

###################################

sub print_swmacfilters  {

  print "<br>\n";
  print "<a HREF=\"https://$webcgi/netpeek/swmacfilter.cgi\"> ";
  print "back to swmacfilters home page </a> <br><br>";

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
        my $href = "<a href=\"https://$webcgi/netpeek/netpeek.cgi?submit=Submit&oper=query_mac&mac=$mac\" $blank > ";
        print "<tr> <td> $href $mac $s4 </a></td> <td> $swname $s4 </td> <td> $vlan $s4 </td> <td> $datefilt $s4 </td>  </tr>";
     }
     print "</table>\n";
     print "<hr> <b> Just the macs, only the macs (good for cut-n-paste): </b> <br><br>\n";
     foreach my $mac (@$macs)  {  print "$mac <br>";  }
  }
  else { print "No swmacfilters in force at this time<br><br>\n"; }
  print "<br><hr>";
  Front_Page($emsg);

  return;
} ## print_swmacfilters

###################################

sub print_filterQ  {

  my $select_h = $dbh->prepare("SELECT * from network.swmacfilterQ;");
  my $filtQrecs = $select_h->execute();
  if ($filtQrecs != 0) {
     print "<br><b>Current contents of the swmacfilter queue:</b><br><br>\n";
     print "<table border=5>";
     ## Print Header
     my $header_h = $dbh->prepare("DESCRIBE network.swmacfilterQ;");
     my $header_recs = $header_h->execute();
     my $fields;
     while ( (my @row) = $header_h->fetchrow_array ) { push @$fields, $row[0]; }
     foreach my $field (@$fields)  { print "<th rowspan=1 align=left> $field </th> "; }
     my $s2 = "&nbsp;&nbsp;";
     print "<tr>\n";
     while ( (my @row) = $select_h->fetchrow_array ) {
         my ($mac,$operation,$dateQ,$netid,$comment) = @row;
         if ($comment eq "") { $comment = "web Queue entry"; }
         my $href = "<a href=\"https://$webcgi/netpeek/netpeek.cgi?submit=Submit&oper=query_mac&mac=$mac\" $blank > ";
         print "<tr> <td>$href $mac $s2 </a></td> <td>$operation $s2</td> <td>$dateQ $s2</td> <td>$netid $s2</td> <td>$comment $s2</td> </tr>\n";
     }
     print "</table>"; 
  }
  else  { print "<br> * * * network.swmacfilterQ is currently <b>empty!</b> <br>\n"; }   
  print "<br><hr>";
  Front_Page($emsg);
  return;

} ## print_filterQ

###################################

sub print_swmacfilterlog  {

   my $records = shift;

   print "<br>\n";
   print "<a HREF=\"https://$webcgi/netpeek/swmacfilter.cgi\"> ";
   print "back to swmacfilters home page </a> <br><br>";
 
   my $query;
   if ($records eq "full")  {
     print "Current contents of the <b> full </b> network.swmacfilterlog database:<br><br>\n";
     $query = "SELECT * FROM network.swmacfilterlog order by datefilt desc;";
   }
   else   {
     print "<b> $records most recent entries </b> from the swmacfilterlog database:<br><br>\n";
     $query = "SELECT * FROM network.swmacfilterlog order by datefilt desc LIMIT $records ;";
   }
   my $select_h  = $dbh->prepare($query);
   my $filtrecs = $select_h->execute();
   if ($filtrecs != 0) {
      print "<table border = 3>";
      my $s2 = "&nbsp;&nbsp;";
      ## Print Header
      my $header_h = $dbh->prepare("DESCRIBE network.swmacfilterlog;");
      my $header_recs = $header_h->execute();
      my $fields;
      while ( (my @row) = $header_h->fetchrow_array ) { push @$fields, $row[0]; }
      foreach my $field (@$fields)  { print "<th rowspan=1 align=left> $field </th> "; }
      while ( (my $row) = $select_h->fetchrow_arrayref ) {
         my ($datefilt,$operation,$mac,$vlan,$swname,$netid,$comment) = @$row;      
         unless ($comment) { $comment = "none"; }
         my $href = "<a href=\"https://$webcgi/netpeek/swmacfilter.cgi?submit=Submit&oper=query_mac&addr=$mac\" $blank > ";
         print "<tr><td>$datefilt $s2</td> <td>$operation $s2</td> <td> $href $mac $s2 </a></td> <td>$vlan $s2</td> <td>$swname $s2</td> <td>$netid $s2</td> <td>$comment $s2</td></tr>";
      }
      print "</table>";
   }
   else  { print "swmacfilterlog database is currently <b>empty!</b> <br>\n"; }
   #print "<br><hr>";
   #Front_Page($emsg);

   return;
}  ## print_swmacfilterlog

#################################

sub sort_by_ip  {

my $iplist = shift;   ## array ref

## here's the mapping transform for IP number sorting:
    @$iplist =
        map {$_->[0]}
        sort { ($a->[1] <=>$b->[1])
                    || ($a->[2] <=>$b->[2])
                    || ($a->[3] <=>$b->[3])
                    || ($a->[4] <=>$b->[4]) }
        map {[$_, split( '[ \.]', $_) ]} @$iplist;

return ($iplist);

}  ## sort_by_ip

###################################################

## NOT USED! -- NOT INVOKED  --- MAYBE LATER
sub mail_it  {

  my $rogue_filts= shift;

open (SENDMAIL, "|/usr/lib/sendmail -oi -t -odq")  or die "Can't fork for sendmail: $!\n";

print SENDMAIL <<"EOF";
From: Switch Mac Filter Checker <$webid\@$webbox>
To: network admin <$webid\@$webbox>
Subject: manual mac filter alert

The following lines show filters on the routers that are
on the router, but not in the network.macfilterlog database.

Insert these lines on network.macfilterlog

EOF

foreach (@$rogue_filts)  { print SENDMAIL "$_\n"; }
print SENDMAIL "Fire Chief \n";
close(SENDMAIL)  or warn "sendmail didn't close nicely";

}  ## mail_it

###################################################################

sub date_time  {

   ## Returns string with Date and Time as:
   ##  "mm/dd/yy hh/mm/ss"
   my ($sec,$min,$hour,$mday,$mon,$year,undef,undef,undef) = localtime(time);
   $mon += 1;
   # Y2K fix:
   my $yr=1900+$year;
   my $date = "$yr-$mon-$mday";
   if ( $min < 10 )  { $min = "0"."$min"; }
   if ( $sec < 10 )  { $sec = "0"."$sec"; }
   my $time = "$hour:$min:$sec";

   ## for this script, we split 'em!!
   return($date,$time);
}  ## date_time

##################################
################################## 

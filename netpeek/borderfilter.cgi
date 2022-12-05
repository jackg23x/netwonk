#!/usr/bin/perl
# by jackg - Jack Gallagher
#
# borderfilter.cgi -- filter remote hosts and networks on the border routers
#
 
use strict;

print "Content-type: text/html\n\n<html><body>";
print "<title> borderfilter - filter/unfilter hosts and networks at border routers, query db tables  </title>";
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
#######################################################################
### foreach (keys %ENV)  {  print "ENV: $_ => $ENV{$_} <br> \n"; }

my $emsg;
my $submit  = $in->param('submit');
my $addr    = $in->param('addr');
   $addr    =~ s/\s+//g;
   $addr    =~ s/,//g;
my $comment = $in->param('comment');
   $comment =~ s/^\s+//g;
   $comment =~ s/\s+$//g;
   $comment =~ s/,/ -/g;  ## commas are used for field separators!! must translate them.
   $comment =~ s/'//g;  
   $comment =~ s/"//g;  
my $oper = $in->param('oper');
my $records = $in->param('records');

my ($date,$time)=date_time();
my $tstamp = "$date"."_"."$time"; 
my $blank  = "target = \"_blank\"";

if (($submit eq "Submit") && (!$oper))  {
  $emsg = "Please choose an action.<br><br>\n";
  $oper = "main";
  Front_Page($emsg);
  exit;
}   
elsif  (!$submit)  {  $oper = "main";  }
##print "oper = $oper<br>";

my %oper = (
            main            => \&Front_Page,
            filter          => sub{insert_filterQ("filter",$addr,$netid,$tstamp,$comment)},
            unfilter        => sub{insert_filterQ("unfilter",$addr,$netid,$tstamp,$comment)},
            query_addr      => sub{query_addr($addr)},
            filterQ         => \&print_filterQ,
            clearfilterQ    => \&clear_filterQ,
            borderfilters   => \&print_borderfilters,
            borderfilterlog => sub{print_borderfilterlog($records)},
           );

unless (exists $oper{$oper}) {
    print "Content-type: text/html\n\n<html><body>Bad action $oper \n</body></html>\n";
    exit; 
}   
$oper{$oper}->();

print "<br>\n";
print "<a HREF=\"https://$webcgi/netpeek/borderfilter.cgi\"> ";      
print "back to Border Filters home page </a> <br><hr>";

exit;


############################

sub no_web_access  {

  my $host = shift;
  print "Sorry to say, your host $host does not have access to this page<br><br>\n";
  print "If you think this is in error, please contact ACCC Networking via email: <br><br>\n";
  print "<em> <a HREF=\"mailto:$nuser\@$domain\"> Click to Email the ACCC Network Group </a> </em> <br>\n";
  print "Email address: <b> $nuser\@$domain </b> <br><br><hr>\n";
}

############################

sub Front_Page  {

   my $msg = shift || "";

   if ($msg ne "")  {  print "<br><font color=red><b> $msg </b> </font> \n";  }

print <<EOF;
<form method=\"post\" action=\"$ENV{'SCRIPT_NAME'}\">
<h3> borderfilter - filter/unfilter host or network on border routers, query existing filter data </h3>
The borderfilter queue is processed, at which time filters 
become active and show up under the selection <b>show all current borderfilters</b>  <br><br>
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
<input type=radio name="oper" value="query_addr"> <b> query </b> borderfilterlog for this address  <br>
<br>
<b> No Address needed: </b>  <br>
<input type=radio name="oper" value="filterQ">  show current     <b> borderfilter queue </b> <br>
<input type=radio name="oper" value="borderfilters"> show all current <b> borderfilters  </b> <br>
<input type=radio name="oper" value="borderfilterlog">   
<select name="records">
  <option value="20">   show the last 20 records in the   </option>
  <option value="50">   show the last 50 records in the   </option>
  <option value="100">  show the last 100 records in the   </option>
  <option value="full"> show the full </option>
</select>
<b> borderfilterlog </b> (log table of all borderfilter activity)
<br><br>
<input type=radio name="oper" value="clearfilterQ">
<font color=red><b>CLEAR borderfilterQ!</b></font> 
Please be <font color=green><b>Careful</b></font>, this is not reversible 
<br><br>

<input type=\"submit\" value=\"Submit\" name=\"submit\" >   <br> <br>

<hr>
In case of problems with this page, send email to
<em> <a HREF=\"mailto:$nuser\@$domain\"> the ACCC Network Group </a> </em> <br><hr>

EOF

return;
}  ## Front_Page

###################################

sub query_addr  {

  my $addr    = shift;

print "sub query_addr <br>";

  print "<form method=\"post\" action=\"$ENV{'SCRIPT_NAME'}\">";
  ## select_from_table filter
  print "<a HREF=\"https://$webcgi/borderfilter.cgi\"> ";
  print "back to borderfilters home page </a> <br><hr>";

  print "<br>";
  if ($addr =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/)  {
     print "<b> address $addr </b><br><br>\n";
  }
  else  {  print "address $addr is a malformed address <br>";  }

  print "<input type=radio name=\"oper\" value=\"filter\"> <b> filter </b> this address <br>";
  print "<input type=radio name=\"oper\" value=\"unfilter\"> <b> unfilter </b> this address <br><br>";
  print "reason: <input type=\"text\" size=69 name=\"comment\" value=\"\" > <br><br>";
  print "<input type=hidden name=\"addr\" value=\"$addr\"> <input type=\"submit\" value=\"Submit\" name=\"submit\" > <br>"; 
  print "<br> <hr> <br>";

  my $s2 = "&nbsp&nbsp";
  my $th = "<th rowspan=1 align=left>";
  my $mac;
  my $query = "SELECT * FROM network.borderfilterlog WHERE address=\"$addr\" ORDER BY datefilt DESC ;";
  my $select_h  = $dbh->prepare($query);
  my $filtrecs = $select_h->execute();
  if ($filtrecs != 0) {
     ## print "Recorded $filtrecs log entries for <b>$addr</b>: <br><br>\n";
     print "<table border=3> <b>";
     print "$th address </th> $th operation </th> $th datefilt </th> $th netid </th> $th comment $s2 </th> </tr>  </b> \n";
     while ( my $row = $select_h->fetchrow_arrayref ) {
        my ($address,$operation,$datefilt,$netid,$comment) = @$row;
        print "<td> $address $s2 </td>  <td> $operation $s2 </td>  <td> $datefilt $s2 </td> <td> $netid $s2 </td>  <td> $comment $s2 </td>  </tr>";
     }
     print "</table>";
  }
  else  {  print "No network.borderfilterlog entries found for <b>$addr</b> <br><br>\n";  }
  print "<br>";

  ## Check network.borderfilterQ to see if activity has been queued
  my $select_h  = $dbh->prepare("SELECT * from network.borderfilterQ where address = \"$addr\";");
  my $filtQrecs = $select_h->execute();
  if ($filtQrecs != 0) {
     print "<b> $addr </b> is currently queued for activity as follows: <br>";
     print "<table>";
     while ( (my @row) = $select_h->fetchrow_array ) {
       print "<tr>";
       foreach my $r (@row)  {   print "<td> $r $s2 </td>";   }
       print "</tr>";
     }
     print "</table>  <br>\n";
  }
  else  {  print "No filter/unfilter actions queued for <b> $addr </b>  <br><br>";  }

  ## Check current filter status
  my $select_h  = $dbh->prepare("SELECT * from network.borderfilters where address = \"$addr\" ;");
  my $bfiltrecs = $select_h->execute();
  if ($bfiltrecs != 0) {
     print "<b> $addr </b> currently shows as filtered in the network.borderfilters database:<br>";
     print "<table>\n";
     print "<tr> <td><b> datefilt </td>  <td><b> address $s2 </td>  </tr>";
     my ($datefilt,$address);
     while ( (my @row) = $select_h->fetchrow_array ) {
       ($datefilt,$address) = @row;
       print "<tr> <td> $datefilt </td>  <td> $address </td>  </tr>";
     }
     print "</table>\n";
  }
  else  { print  "<b> $addr </b> shows as not filtered in the network.borderfilters database <br>";  }

} ## query_addr 

###################################

sub insert_filterQ  {

  my $oper    = shift;
  my $addr    = shift;
  my $netid   = shift;
  my $tstamp  = shift;
  my $comment = shift;

  if ($addr =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/)  {
     my ($ip,$mask) = split /\//, $addr;
     my ($a,$b,$c,$d) = split /\./, $ip;
     my ($pre,$num,$sub);
     if (($mask < 31) && ($mask > 24))  {
        $pre = "$a.$b.$c";
        $num = 2**(32-$mask);
        $sub = $d;
     }
     if (($mask < 25) && ($mask > 15))  {
        $pre = "$a.$b";
        $num = 2**(24-$mask);
        $sub = $c
     }
     if ($sub % $num != 0)  {
        my $emsg = " *** Address $addr is an invalid subnet/mask combination - please input valid address\n";
        Front_Page($emsg);
        return;
     }
  }

  print "<br>";
  my $query = "SELECT * from network.borderfilterQ WHERE address=\"$addr\" and operation=\"$oper\" ; ";
  my $select_h  = $dbh->prepare($query);
  my $filtQrecs = $select_h->execute();
  if ($filtQrecs != 0) {
     print "Address $addr is already currently queued for <b>$oper</b> processing. <br><br>\n";
     print_filterQ();  ## prints filterQ
     return;
  }
  my $insert_h = $dbh->prepare("INSERT IGNORE INTO network.borderfilterQ (address,operation,dateQ,netid,comment) VALUES (?,?,?,?,?)");
  if ($comment eq "")  {  $comment = "none";  }
  $insert_h->execute($addr,$oper,$tstamp,$netid,$comment);
  print "<b> address $addr processed for $oper", " -- added to network.borderfilterQ</b> <br><br>";
  print_filterQ();

} ## insert_filterQ

##################################

sub clear_filterQ  {

  my $select_h = $dbh->prepare("SELECT * from network.borderfilterQ;");
  my $filtQrecs = $select_h->execute();
  if ($filtQrecs != 0) {
     print "Entries to be deleted from borderfilterQ: <br>\n";
     while ( (my @row) = $select_h->fetchrow_array ) {
        my $ln = join " ", @row;    
        if ($ln ne "")  {  print "== >$ln< == <br>";  }
     }
     my $delete_h = $dbh->prepare("DELETE FROM network.borderfilterQ;");
     my $success;                                   
     eval {  $success = $delete_h->execute()  };
     if ($success)  {
        print  "<br> <font color=red> <b> borderfilterQ </b> has been cleared.  This action cannot be reversed. </font> <br> \n"; 
     }
     else  {  print "Error: $@ <br>\n";  }
  }
  else  {  print "No entries in network.borderfilterQ at present<br>"; }

} ## clear_filterQ

###################################

sub print_borderfilters  {

  print "<br>\n";
  print "<a HREF=\"https://$webcgi/borderfilter.cgi\"> ";
  print "back to borderfilters home page </a> <br><br>";

  my $select_h  = $dbh->prepare("SELECT * FROM network.borderfilters;");
  my $filtrecs = $select_h->execute();
  if ($filtrecs != 0) {
     my $addr_h;
     while ( (my @row) = $select_h->fetchrow_array ) {
        my ($tstamp,$address) = @row;
        $addr_h->{$address} = $tstamp;
     }
     my $addrs;  ## array ref
     foreach my $address (sort keys %$addr_h)  {  push @$addrs, $address;  }
     $addrs = sort_by_ip($addrs);

     print "<h3> Current <b>borderfilters</b>: </h3>\n";
     print "<table>\n";
     print "<tr> <td><b> tstamp </td>  <td><b> address </td>  </tr>";
     my $s4 = "&nbsp;&nbsp;&nbsp;&nbsp;";
     foreach my $address (@$addrs)  {      
        print "<tr> <td> ", $addr_h->{$address}, " $s4 </td>  <td> $address </td>  </tr>";
     }
     print "</table>\n";
     print "<hr> <b> Just the addresses, only the addresses (good for cut-n-paste): </b> <br><br>\n";
     foreach my $address (@$addrs)  {  print "$address <br>";  }
  }
  else { print "No borderfilters in force at this time<br><br>\n"; }

  return;
} ## print_borderfilters

###################################

sub print_filterQ  {

  my $select_h = $dbh->prepare("SELECT * from network.borderfilterQ;");
  my $filtQrecs = $select_h->execute();
  if ($filtQrecs != 0) {
     print "<br><b>Current contents of the borderfilter queue:</b><br><br>\n";
     print "<table>";
     ## Print Header
     my $header_h = $dbh->prepare("DESCRIBE network.borderfilterQ;");
     my $header_recs = $header_h->execute();
     my $fields;
     while ( (my @row) = $header_h->fetchrow_array ) { push @$fields, $row[0]; }
     foreach my $field (@$fields)  { print "<th rowspan=1 align=left> $field </th> "; }
     my $s2 = "&nbsp;&nbsp;";
     ## my $th = "<th align=left>";
     my $td = "<td align=left>";
     print "<tr>\n";
     while ( (my @row) = $select_h->fetchrow_array ) {
         my ($address,$operation,$dateQ,$netid,$comment) = @row;
         if ($comment eq "") { $comment = "web Queue entry"; }
         print "<tr>  $td $address $s2 </td> $td $operation $s2 </td> $td $dateQ $s2 </td> $td $netid $s2 </td> $td $comment $s2 </td>  </tr>\n";
     }
     print "</table>"; 
  }
  else  { print "network.borderilterQ is currently <b>empty!</b> <br>\n"; }   
  print "<br><hr>";
  Front_Page($emsg);
  return;

} ## print_filterQ

###################################

sub print_borderfilterlog  {

   my $records = shift;

   print "<br>\n";
   print "<a HREF=\"https://$webcgi/borderfilter.cgi\"> ";
   print "back to borderfilters home page </a> <br><br>";
 
   my $s2 = "&nbsp;&nbsp;";
   my $query;
   if ($records eq "full")  {
     print "Current contents of the <b> full </b> network.borderfilterlog database:<br><br>\n";
     $query = "SELECT * FROM network.borderfilterlog order by datefilt desc;";
   }
   else   {
     print "<b> $records most recent entries </b> from the borderfilterlog database:<br><br>\n";
     $query = "SELECT * FROM network.borderfilterlog order by datefilt desc LIMIT $records ;";
   }
   my $select_h  = $dbh->prepare($query);
   my $filtrecs = $select_h->execute();
   if ($filtrecs != 0) {
      print "<table border=5>";
      ## Print Header
      my $header_h = $dbh->prepare("DESCRIBE network.borderfilterlog;");
      my $header_recs = $header_h->execute();
      my $fields;
      while ( (my @row) = $header_h->fetchrow_array ) { push @$fields, $row[0]; }
      foreach my $field (@$fields)  { print "<th rowspan=1 align=left> $field </th> "; }
      print "<tr>\n";
      ## my $th = "<th rowspan=1 align=left>";
      my $td = "<td align=left>";
      while ( (my $row) = $select_h->fetchrow_arrayref ) {
         my ($address,$operation,$datefilt,$netid,$comment) = @$row;      
         unless ($comment) { $comment = "none"; }
         my $href = "<a href=\"./borderfilter.cgi?submit=Submit&oper=query_addr&addr=$address\" $blank > ";
         print "<tr> $td $href $address $s2 </a></td> $td $operation $s2 </td>  $td $datefilt $s2 </td>  $td $netid $s2 </td>  $td $comment $s2 </td> </tr> ";
      }
   }
   else  { print "borderfilterlog database is currently <b>empty!</b> <br>\n"; }
   print "</table>";
   return;
} 

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
From: fire.cc Filter Checker <$nuser\@$domain>
To: Jack Gallagher <$admin\@$domain>
Subject: manual mac filter alert

The following lines show filters on the routers that are
on the router, but not in the network.borderfilter database.

Insert these lines on network.borderfilter

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

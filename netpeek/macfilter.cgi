#!/usr/bin/perl
# by jackg - Jack Gallagher
#
# macfilter.cgi - all web processing related to macfilters
#

use strict;

## THIS FILE
my @fn = split /\//, $0;
my $thisfile = @fn[$#fn];

print "Content-type: text/html\n\n<html><body>";
print "<title> macfilter - filter/unfilter mac addresses, query existing mac filter data  </title>";
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
my $addr    = $in->param('addr');
   $addr    =~ s/\s+//g;
   $addr    =~ s/,//g;
my $comment = $in->param('comment');
   $comment =~ s/^\s+//g;
   $comment =~ s/\s+$//g;
   $comment =~ s/,/ -/g;  ## commas are used for field separators!! must translate them.
   $comment =~ s/'//g;  
   $comment =~ s/"//g;  
my $dateSec = $in->param('dateSec');
my $oper    = $in->param('oper');
my $records = $in->param('records');

my ($date,$time)=date_time();
my $tstamp = "$date"."_"."$time"; 
##if ($dateSec =~ /\d{4}\-\d{2}\-\d{2}\s+\d{2}/)  { 
if ($dateSec =~ /\d{4}\-\d{2}\-\d{2}\s+\d{2}\:\d{2}\:\d{2}/)  { 
   $tstamp = $dateSec;
   print "Using security event timestamp $tstamp <br>";
}
elsif ($dateSec eq "")  {  print "Using default date queued timestamp $tstamp <br>";  }
else  { 
   $emsg = "Improper security event date format entered, please edit -- USE Back Button";
   Front_Page($emsg); 
}

if (($submit eq "Submit") && ($oper !~ /filterQ|macfilts|filtdb/))  {  
   my $addr_save = $addr;
   if ($addr ne /\A\s*\z/)  {
      if ($addr =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)    {    ## IP address
         if ($oper eq "unfilter")  {
            $emsg = "Unfilter operator may use MAC Address only - no unfilter by IP addresses";
            Front_Page($emsg); 
            exit;
         } 
      }
      else  {  ## they must mean it to be a mac -- let's try that
         $addr = lc($addr);   ## I'm case chauvanistic  ;->
         $addr =~ s/\.//g;
         $addr =~ s/\://g;
         $addr =~ s/\-//g;
         my $aa = substr($addr,0,4);
         my $bb = substr($addr,4,4);
         my $cc = substr($addr,8,4);
         $addr = "$aa.$bb.$cc";
         if ($addr !~ /^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$/) {
            $emsg  = " Address format error -- address entered = $addr_save <br>\n";
            $emsg .= " IP format example:  192.168.100.155  <br>\n";
            $emsg .= " MAC format example:  1234.5678.90ab  <br>\n";
            Front_Page($emsg);
            exit;
         }
      }
   }

   if (!$oper)  { 
     $emsg = "Please choose an action.<br><br>\n";
     $oper = "main";
     Front_Page($emsg);
   }   
}
elsif ($oper =~ /filterQ|macfilts|filtdb/)  {         } ## they are what they are, not doing anything now... ;->
else   { $oper = "main";   } 

my $user = $netid;         

#print "oper = $oper<br>";

my %oper = (
            main         => \&Front_Page,
            query_addr   => sub{query_addr($addr)},
            filter       => sub{insert_filterQ("filter",$addr,$user,$tstamp,$comment)},
            unfilter     => sub{insert_filterQ("unfilter",$addr,$user,$tstamp,$comment)},
            filterQ      => \&print_filterQ,
            clearfilterQ => \&clear_filterQ,
            macfilts     => \&print_macfilts,
            filtdb       => sub{print_filtdb($records)},
           );

unless (exists $oper{$oper}) {
    print "Content-type: text/html\n\n<html><body>Bad action $oper \n</body></html>\n";
    exit; 
}   
$oper{$oper}->();

print "<br>\n";
print "<a HREF=\"https://$webcgi/netpeek/$thisfile\"> ";      
print "back to Mac Filters home page </a> <br><hr>";

exit;


############################

sub no_web_access  {

  my $host = shift;
  print "Sorry to say, your host $host does not have access to this page<br><br>\n";
  print "If you think this is in error, please contact Network via email: <br><br>\n";
  print "<em> <a HREF=\"mailto:$nuser\@$domain\"> Click to email the network admin </a> </em> <br>\n";
  print "Email address: <b> $nuser\@$domain </b> <br><br><hr>\n";
}

############################

sub Front_Page  {

 my $msg = shift || "";

 if ($msg ne "")  {
    print "<br><font color=red><b> $msg </b> </font> \n";
 }

print <<EOF;
<form method=\"post\" action=\"$ENV{'SCRIPT_NAME'}\">

<h3> macfilter - filter/unfilter mac addresses, query existing mac filter data </h3>

Filter by ip or mac address <br>
Unfilter by <b> mac address </b> only.  IPs are often dynamic and reused after a filter such that they point at a different mac address. <br>
The macfilter queue is processed, at which time filters 
become active and show up under the selection <b>show all current  mac filters</b>
<br><br>
EOF

print <<EOF;
<table>
<tr> <td><input type=\"text\" size=32 name=\"addr\" value=\"\" ></td> <td> filter: mac or ip -- unfilter: mac only </td> </tr>
<tr> <td><input type=\"text\" size=32 name=\"comment\" value=\"\" ></td> <td> reason for filter/unfilter </td> </tr>
<tr> <td><input type=\"text\" size=32 name=\"dateSec\" value=\"\" ></td> <td> YYYY-MM-DD HH:MM:SS
          timestamp of security event (optional -- if blank, date queued used)</td> </tr>
</table>
<br>
<b> Address Actions: </b>  <br>
<input type=radio name="oper" value="filter"> <b> filter </b> this address  <br>
<input type=radio name="oper" value="unfilter"> <b> unfilter </b> this address - <b> mac address only </b> <br>
<input type=radio name="oper" value="query_addr"> <b> query </b> filter log for this address  <br>
<br>
<b> No Address needed: </b>  <br>
<input type=radio name="oper" value="filterQ">  show current     <b> filter queue </b> <br>
<input type=radio name="oper" value="macfilts"> show all current <b> mac filters  </b> <br>
<input type=radio name="oper" value="filtdb">   
<select name="records">
  <option value="75">   show the last 75 records in the   </option>
  <option value="150">  show the last 150 records in the   </option>
  <option value="250">  show the last 250 records in the  </option>
  <option value="500">  show the last 500 records in the  </option>
  <option value="2000"> show the last 2000 records in the </option>
  <option value="full"> show the full </option>
</select>
<b> macfilter database </b> (log table of all macfilter activity)
<br><br>
<input type=radio name="oper" value="clearfilterQ">
<font color=red><b>CLEAR the macfilterQ!</b></font> 
Please be <font color=green><b>Careful</b></font>, this is not reversible 
<br><br>

<input type=\"submit\" value=\"Submit\" name=\"submit\" >   <br> <br>

<hr>
In case of problems with this page, send email to
<em> <a HREF=\"mailto:$nuser\@$domain\"> the network admin </a> </em> <br><hr>

EOF

return;

}  ## Front_Page

###################################

sub query_addr  {

  my $addr    = shift;

  print "<form method=\"post\" action=\"$ENV{'SCRIPT_NAME'}\">";
  ## select_from_table filter
  print "<a HREF=\"https://$webcgi/netpeek/$thisfile\"> ";
  print "back to Mac Filters home page </a> <br><hr>";

  print "<br>";
  if ($addr =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)  { print "<b> address $addr </b><br><br>\n"; }
  else  { print "<b> mac address $addr </b><br><br>\n"; }  

  print "<input type=radio name=\"oper\" value=\"filter\"> <b> filter </b> this address <br>";
  print "<input type=radio name=\"oper\" value=\"unfilter\"> <b> unfilter </b> this address <br><br>";
  print "reason: <input type=\"text\" size=69 name=\"comment\" value=\"\" > <br><br>";
  print "<input type=hidden name=\"addr\" value=\"$addr\"> <input type=\"submit\" value=\"Submit\" name=\"submit\" > <br>"; 
  print "<br> <hr> <br>";

  my $s2 = "&nbsp&nbsp";
  my $th = "<th rowspan=1 align=left>";
  my $mac;
  my $query = "SELECT * FROM network.macfilterlog where mac=\"$addr\" or pub_ip=\"$addr\" or priv_ip=\"$addr\" order by dateQ desc;";
  my $select_h  = $dbh->prepare($query);
  my $filtrecs = $select_h->execute();
  if ($filtrecs != 0) {
     print "Recorded $filtrecs log entries for <b>$addr</b>: <br><br>\n";
     print "<table> <b>";
     print "$th date time </th> $th operation </th> $th type </th> $th mac </th> $th public ip $s2 </th> $th private ip $s2 </th>
            $th vlan $s2 </th> $th router $s2 </th> $th who </th> $th comment </th> </tr>  </b> \n";
     while ( my $row = $select_h->fetchrow_arrayref ) {
        my (undef,$Fdatetime,$oper,$type,$m,$pub_ip,$priv_ip,$vlan,$router,undef,$who,$comment) = @$row;
        $mac = $m;
        print "<tr>  <td> $Fdatetime $s2 </td>  <td> $oper $s2 </td>  <td> $type $s2 </td>";
        if ($mac =~ /\A[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\z/) {
           print "<td> <a href=\"https://$webcgi/netpeek.cgi?submit=Submit&oper=query_mac&mac=$mac\" $blank > $mac </a> $s2 </td>";
        }
        else  { print "<td> $mac $s2 </td>"; }
        if ($pub_ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)  {
           print "<td> <a href=\"https://$webcgi/netpeek/netpeek.cgi?submit=Submit&oper=query_ip&ip=$pub_ip \" $blank > $pub_ip </a> $s2 </td>";
        }
        else  { print "<td> $pub_ip $s2 </td>"; }
        if ($priv_ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)  {
           print "<td> <a href=\"https://$webcgi/netpeek/netpeek.cgi?submit=Submit&oper=query_ip&ip=$priv_ip\" $blank > $priv_ip </a> $s2 </td>";
        }
        else  { print "<td> $priv_ip $s2 </td>"; }
        print "<td> $vlan $s2 </td>  <td> $router $s2 </td>  <td> $who $s2 </td>  <td> $comment $s2 </td>  </tr>";
     }
     print "</table>";
  }
  else  {  print "No network.macfilterlog entries found for <b>$addr</b> <br><br>\n";  }
  print "<br>";

  ## Check network.macfilterQ to see if activity has been queued
  my $select_h  = $dbh->prepare("SELECT * from network.macfilterQ where address = \"$mac\";");
  my $filtQrecs = $select_h->execute();
  if ($filtQrecs != 0) {
     print "<b> $mac </b> is currently queued for activity as follows: <br>";
     print "<table>";
     while ( (my @row) = $select_h->fetchrow_array ) {
       print "<tr>";
       foreach my $r (@row)  {   print "<td> $r $s2 </td>";   }
       print "</tr>";
     }
     print "</table>  <br>\n";
  }
  else  {  print "No filter/unfilter actions queued for <b> $mac </b>  <br><br>";  }

  ## Check current filter status
  my $select_h  = $dbh->prepare("SELECT * from network.macfilters where mac = \"$mac\";");
  my $macfiltrecs = $select_h->execute();
  if ($macfiltrecs != 0) {
     print "<b> $mac </b> currently shows as filtered in the network.macfilters database:<br>";
     print "<table>\n";
     print "<tr> <td><b> mac </td>  <td><b> router $s2 </td>  <td><b> vlan </td></b> </tr>";
     my ($mac,$router,$vlan);
     while ( (my @row) = $select_h->fetchrow_array ) {
       ($mac,$router,$vlan) = @row;
       print "<tr> <td> $mac </td>  <td> $router </td>  <td> $vlan </td> </tr>";
     }
     print "</table>\n";
  }
  else  { print  "<b> $mac </b> shows as not filtered in the network.macfilters database <br>";  }

} ## query_addr 

###################################

sub insert_filterQ  {

  my $oper    = shift;
  my $addr    = shift;
  my $user    = shift;
  my $tstamp  = shift;
  my $comment = shift;


  print "<br>";
  my $query = "SELECT * from network.macfilterQ WHERE address=\"$addr\" and operation=\"$oper\" ; ";
  my $select_h  = $dbh->prepare($query);
  my $filtQrecs = $select_h->execute();
  if ($filtQrecs != 0) {
     print "Address $addr is already currently queued for <b>$oper</b> processing. <br><br>\n";
     print_filterQ();  ## prints filterQ
     return;
  }
  ## implied else here  
  my $insert_h = $dbh->prepare("INSERT IGNORE INTO network.macfilterQ (address,operation,dateQ,user,number,comment) VALUES (?,?,?,?,?,?)");
  $insert_h->execute($addr,$oper,$tstamp,$user,"0",$comment);
  print "<b> address $addr processed for $oper", "...</b> <br><br>";
  print_filterQ();

} ## insert_filterQ

##################################

sub clear_filterQ  {

  my $select_h = $dbh->prepare("SELECT * from network.macfilterQ;");
  my $filtQrecs = $select_h->execute();
  if ($select_h->rows != 0) {
     print "<br> Entries deleted from macfilterQ: <br>\n";
     print "<table border=5>";
     my $sel_ary = $select_h->fetchall_arrayref;
     foreach my $row (@$sel_ary)  {
        my ($mac,$swname,$vlan,$num,$datefilt) = @$row;
        print "<tr> <td>$mac</td> <td>$swname</td> <td>$vlan</td> <td>$num</td> <td>$datefilt</td> </tr>";
     }
     print "</table>";
     my $delete_h = $dbh->prepare("DELETE FROM network.macfilterQ;");
     my $success;                                   
     eval {  $success = $delete_h->execute()  };
     if ($success)  {
        print  "<br> <font color=red> <b> filterQ </b> has been cleared.  This action cannot be reversed. </font> <br> \n"; 
     }
     else  {  print "Error: $@ <br>\n";  }
  }
  else  {  print "No entries in network.macfilterQ at present<br>"; }
  print "<hr>";
  Front_Page($emsg);

} ## clear_filterQ

###################################

sub print_macfilts  {

  print "<br>\n";
  print "<a href=\"https://$webcgi/netpeek/$thisfile\"> ";
  print "back to Mac Filters home page </a> <br><br>";

  my $select_h  = $dbh->prepare("SELECT * from network.macfilters;");
  my $macfiltrecs = $select_h->execute();
  if ($macfiltrecs != 0) {
     print "<h3> Current <b>mac filters</b>: </h3>\n";
     print "<table>\n";
     print "<tr> <td><b> mac </td>  <td><b> router </td>  <td><b> vlan </td></b> </tr>";
     my ($mac,$router,$vlan);  
     my $s2 = "&nbsp;&nbsp;";
     my $mac_h;
     while ( (my @row) = $select_h->fetchrow_array ) {
       ($mac,$router,$vlan) = @row;           
       $mac_h->{$mac} = 1;
       print "<tr> <td> <a href=\"https://$webcgi/netpeek/netpeek.cgi?submit=Submit&oper=query_mac&mac=$mac\" $blank > $mac </a> $s2 </td>
                   <td> $router </td>  <td> $vlan </td>  </tr>";
     }  
     print "</table>\n";
     print "<hr> <b> Just the macs, only the macs (good for cut-n-paste): </b> <br><br>\n";
     foreach my $mac (sort keys %$mac_h)  {  print "$mac<br>";  }
  }
  else { print "No mac filters in force at this time<br><br>\n"; }

  return;
} ## print_macfilts

###################################

sub print_filterQ  {

  my $select_h = $dbh->prepare("SELECT * from network.macfilterQ;");
  my $filtQrecs = $select_h->execute();
  if ($filtQrecs != 0) {
     print "<br><b>Current contents of the Filter Queue:</b><br><br>\n";
     print "<table border=5>";
     ## Print Header
     my $header_h = $dbh->prepare("DESCRIBE network.macfilterQ;");
     my $header_recs = $header_h->execute();
     my $fields;
     while ( (my @row) = $header_h->fetchrow_array ) { push @$fields, $row[0]; }
     foreach my $field (@$fields)  { print "<th rowspan=1 align=left> $field </th> "; }
     my $s2 = "&nbsp;&nbsp;";
     my $th = "<th align=left>";
     my $td = "<td align=left>";
     print "<tr>\n";
     while ( (my @row) = $select_h->fetchrow_array ) {
         my ($addr,$oper,$tstamp,$user,$number,$comment) = @row;
         if ($comment eq "") { $comment = "none"; }
         print "<tr>  $td $addr $s2 </td> $td $oper $s2 </td> $td $tstamp $s2 </td> $td $user $s2 </td> 
                $td $number $s2 </td> $td $comment $s2 </td>  </tr>\n";
     }
     print "</table>"; 
  }
  else  { print "Filter Queue is currently <b>empty!</b> <br>\n"; }   
  print "<br><hr>";
  Front_Page($emsg);
  return;

} ## print_filterQ

###################################

sub print_filtdb  {

  my $records = shift;

  print "<br>\n";
  print "<a href=\"https://$webcgi/netpeek/$thisfile\"> ";
  print "back to Mac Filters home page </a> <br><br>";

  my $query;
  if ($records eq "full")  {
    print "Current contents of the <b> full </b> macfilter database:<br><br>\n";
    $query = "SELECT * FROM network.macfilterlog order by dateQ desc;";
  }
  else   {
    print "<b> $records most recent entries </b> from the macfilter database:<br><br>\n";
    $query = "SELECT * FROM network.macfilterlog order by dateQ desc LIMIT $records ;";
  }
  my $select_h  = $dbh->prepare($query);
  my $filtrecs = $select_h->execute();
  if ($filtrecs != 0) {
     print "<table>";
     ## Print Header
     my $header_h = $dbh->prepare("DESCRIBE network.macfilterlog;");
     my $header_recs = $header_h->execute();
     my $fields;
     while ( (my @row) = $header_h->fetchrow_array ) { push @$fields, $row[0]; }
     foreach my $field (@$fields)  { print "<th rowspan=1 align=left> $field </th> "; }
     print "<tr>\n";
     my $th = "<th rowspan=1 align=left>";
     my $td = "<td align=left>";
     while ( (my $row) = $select_h->fetchrow_arrayref ) {
        my ($dateQ,$datefilt,$oper,$type,$mac,$pub_ip,$priv_ip,$vlan,$rtr,$n,$who,$comment) = @$row;      
        if ($priv_ip eq " ") { $priv_ip = "n/a"; }
        unless ($comment) { $comment = "none"; }
        print "<tr>";
        print "$td $dateQ</td>  $td $datefilt</td>  $td $oper</td>  $td $type</td> ";
        if ($mac =~ /\A[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\z/) {
          print "$td <a href=\"https://$webcgi/netpeek/$thisfile?submit=Submit&oper=query_addr&addr=$mac\" $blank > $mac </a> </td>\n";
        }
        else   { print "$td $mac</td>\n"; }
        if ($pub_ip =~ /\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/)  {
          print "$td <a href=\"https://$webcgi/netpeek/$thisfile?submit=Submit&oper=query_addr&addr=$pub_ip\" $blank > $pub_ip  </td>\n";
        }
        else  { print "$td $pub_ip </td>\n";  }  ## we saw some ip issue here ???? not sure what 
        if ($priv_ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)  {
          print "$td <a href=\"https://$webcgi/netpeek/$thisfile?submit=Submit&oper=query_addr&addr=$priv_ip\" $blank > $priv_ip </td>\n";
        }
        else  { print "$td $priv_ip</td>\n"; }
        print "$td $vlan</td>  $td $rtr</td>  $td $n</td>  $td $who</td>  $td $comment</td>";
        print "</tr>\n";
     }
  }
  else  { print "macfilter database is currently <b>empty!</b> <br>\n"; }
  print "</table>";
  return;
}

#################################

## NOT USED! -- NOT INVOKED  --- MAYBE LATER
sub mail_it  {

  my $rogue_filts= shift;

open (SENDMAIL, "|/usr/lib/sendmail -oi -t -odq")  or die "Can't fork for sendmail: $!\n";

print SENDMAIL <<"EOF";
From: Mac Filter Checker <$webid\@$webbox>
To: network admin <$nuser\@$domain>
Subject: manual mac filter alert

The following lines show macfilters on the routers that are
on the router, but not in the network.macfilterlog database.

Insert these lines on network.macfilterlog

EOF

foreach (@$rogue_filts)  { print SENDMAIL "$_\n"; }
print SENDMAIL "Fire Chief \n";
close(SENDMAIL)  or warn "sendmail didn't close nicely";

}  ## mail_it

#####

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

######################

sub dhcp_mac  {

  my $addr = shift;

  $addr = lc($addr);   ## I'm case chauvanistic  ;->
  $addr =~ s/\.//g;
  $addr =~ s/\://g;
  $addr =~ s/\-//g;
  $addr =~ s/\s+//g;
  my $aa = substr($addr,0,2);
  my $bb = substr($addr,2,2);
  my $cc = substr($addr,4,2);
  my $dd = substr($addr,6,2);
  my $ee = substr($addr,8,2);
  my $ff = substr($addr,10,2);
  $addr = "$aa:$bb:$cc:$dd:$ee:$ff";
  return($addr);

}  ## dhcp_mac

##################################

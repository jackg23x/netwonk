#!/usr/bin/perl
# by jackg - Jack Gallagher
#
# chvlan.cgi
# written for managers of the Forum so that they can change the vlan assignments
# of ports on certain network switches in area they control.
# This is one of those pages that creates an entry in a queueing table, which is then
# processed by an independent script.
# The queueuing table is on world: network.forum_chvlanQ
# The processing script is on gregson:  /root/switches/bin/forum_chvlan.pl
# The history database of processed interactions is on world:  network.forum_chvlan
# That's pretty much it.
#

use strict;

print "Content-type: text/html\n\n<html><body>";
print "<title> chvlan - Forum vlan changer </title>";
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
my $admin       = admin();
my $nuser       = network();
my $domain      = dnssuffix();
my $webcgi      = webcgi();
my $reachdata   = deptdata();
my $changevlans = changevlans();

########## LOCAL AUTH CODE ############################################
require "$installpath/lib/auth.pl";
if (-f $reachdata)  { require "$reachdata"; }
use vars qw(%network_staff %noc_staff %security_staff %systems_staff %reachhash %forum );
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

## each of these come in as a string, but can be a series (array) of elements
my $swnames = $in->param('swnames');

## QUICK FIX FORUM
my $access = "forum  sce-fdf-m1";

my $submit  = $in->param('submit');
my $oper    = $in->param('oper');
my $sw      = $in->param('sw');

## these are for oper = q_ch_vl:
my $switchname = $in->param('switchname');
#my $portname   = $in->param('portname');
my $newvlan    = $in->param('newvlan');
my $chvlan     = $in->param('chvlan');
my ($portname,$oldvlan) = split " ", $chvlan; 
#my $oldvlan    = $in->param('oldvlan');

if ( ($submit eq "Submit") && ($chvlan ne "") && ($newvlan eq "") )  {
   print "<font color=red size=+1> <b> * No target vlan chosen - please choose a vlan from the dropdown box * </b> </font> <br><br>\n";
   $oper = "printsw";
   $sw = $switchname;
} 
if ($submit eq "Submit")  {  
   if ($oper eq "")  { print "Hmmmmm...no oper, i.e.: oper=>$oper< <br>\n"; }
}
else  { $oper = "front_page"; }  ## no Submit...

my %oper    = (
    'front_page' => sub{ Front_Page($access) },
    'printsw'    => sub{ print_switch_info($sw) },
    'q_ch_vl'    => sub{ queue_change_vlan($switchname,$portname,$newvlan,$oldvlan,$netid) },
    );

unless ($oper{$oper}) {
    print "Content-type: text/html\n\n<html><body>Bad query: $oper\n</body></html>\n";
    exit;
}
$oper{$oper}->();  ## call the subroutine
exit;

####################################

sub Front_Page  {

  my $access = shift;

  print "<br>";
  print "<b> Forum vlan changer </b> <br>\n";
  print "You have <b> $access </b> auth, which gives you access to these closet switches: <br><br>\n";

  my $blank  = "target = \"_blank\"";
  my $sp4 = "&nbsp&nbsp&nbsp&nbsp";
  my $switches;
  @$switches = split " ", $access;
  my $switch_hash = get_switchhash($switches);
  my $swlist;  # array and sort switches:
  foreach my $sw (keys %$switch_hash)  { push @$swlist, $sw; }
  @$swlist = sort @$swlist;
  foreach my $sw (@$swlist)  {
     print "<a href=\"https://$webcgi/netpeek/chvlan.cgi?submit=Submit&oper=printsw&sw=$sw\" $blank><b>$sw</b></a><br>\n";
  }
  print "<br> <hr>\n";
 
  show_queue();

} ## Front_Page     

####################################

sub print_switch_info   {

  my $sw        = shift;

  print "<form method=\"post\" action=\"$ENV{'SCRIPT_NAME'}\"> ";
  print "<input type=\"hidden\" name=\"switchname\" value=\"$sw\"> ";
  print "<input type=\"hidden\" name=\"oper\" value=\"q_ch_vl\"> ";
  print "<input type=\"hidden\" name=\"netid\" value=\"$netid\"> ";

  ## get vlanmap info for vlan selection
  my $vlanh;
  my $query = "SELECT vlan,router FROM network.vlanmap;";
  my $select_h = $dbh->prepare($query);
  $select_h->execute();
  if ($select_h->rows != 0) {
     my $sel_ary = $select_h->fetchall_arrayref;
     foreach my $rec (@$sel_ary)  {
        my ($vlan,$router) = @$rec;
        if ($router =~ /wism/)  { $vlanh->{$vlan} = "wism"; }
        else  { $vlanh->{$vlan} = "1"; }
     }
  }
  else  {  print "<b> = no info returned from vlanmap! </b> <br>\n"; }

  ## foreach my $vlan (keys %$vlanh)  { print "$vlan => ", $vlanh->{$vlan}, " <br>\n"; }

  ## set up mac data
  my $pmac_hash;
  my $query = "SELECT mac,vlan,port,swip,recent FROM switch.mac WHERE swname = \"$sw\" ORDER BY recent desc;";
  $select_h = $dbh->prepare($query);
  $select_h->execute();
  if ($select_h->rows != 0) {
     my $sel_ary = $select_h->fetchall_arrayref;
     foreach my $rec (@$sel_ary)  {
        my ($mac,$vlan,$port,$swip,$recent) = @$rec;
        if (!exists $pmac_hash->{$port}->{$mac})  {
           $pmac_hash->{$port}->{$mac} = "$recent";
        }
     }
  }

  print "<br>\n";
  print "<a HREF=\"https://$webcgi/netpeek/chvlan.cgi\"> ";
  print "Back to Forum change vlan home page </a> <br><br> <hr> <br>";
  print "<br> Changes update on the switch and in the status listing within about 15 minutes <br><br>\n";
  print "<b> Pick a target vlan, pick a port to change, click Submit </b> <br><br>  <br>\n";
  print "<b> switch: $sw </b> <br><br>\n";
  print "<input type=\"submit\" value=\"Submit\" name=\"submit\" > <b>Vlan Change</b> <br> <br><br> \n";

  ## select drop down for the new vlan:
  print "<table>";
  print "<td> <select name=\"newvlan\" size=4 > ";
  foreach my $vl (@$changevlans)  {
     if    ($vl eq "181") { print "<option value=\"$vl\"> $vl generic guest net </option>"; }
     elsif ($vl eq "2")   { print "<option value=\"$vl\"> $vl videoconferencing </option>"; }
     else                 { print "<option value=\"$vl\"> $vl </option>"; }
  }
  print "</select> </td>";
  print "</table>";

  ## set up and print port data
  my $newdate;
  my $ports;
  my $blank  = "target = \"_blank\"";
  ## get the newest tstamp first
  $query = "SELECT tstamp FROM switch.vlan WHERE swname = \"$sw\" ORDER BY tstamp desc limit 1;" ;
  $select_h = $dbh->prepare($query);
  $select_h->execute();
  if ($select_h->rows != 0) {
     my $sel_ary = $select_h->fetchall_arrayref;
     $newdate = $sel_ary->[0]->[0];  
  }
  ## now process all the lines for the switch in question
  $query = "SELECT * FROM switch.vlan WHERE swname = \"$sw\";" ;
  $select_h = $dbh->prepare($query);
  $select_h->execute();
  if ($select_h->rows != 0) {
     my $sel_ary = $select_h->fetchall_arrayref;
     print "<table>\n";
     my $current_lines;
     foreach my $rec (@$sel_ary)  {
        my $ln = join " ", @$rec;
        ## tstamp swip swname port name status vlan duplex speed type
        my ($date1,$date2,undef) = split " ", $ln, 3;
        ##if ($date ne "$date1 $date2")  {  last;  }   ## Does not match latest date: EXIT OUT
        if ($newdate !~ /$date1/)  {  last;  }   ## Does not match latest date: EXIT OUT
        push @$current_lines, $ln; 
     }
     my $sp4 = "&nbsp&nbsp&nbsp&nbsp";
     foreach my $ln (@$current_lines)  {
        my $status_hash = port_status($ln);
        my $portname = $status_hash->{port};
        my $oldvlan  = $status_hash->{vlan};
        print "<input type=\"hidden\" name=\"portname\" value=\"$portname\"> ";
        print "<tr>
               <td> $sp4 $sp4 $sp4 $sp4 $sp4 </td>
               <td> <input type=\"radio\" name=\"chvlan\" value=\"$portname $oldvlan\"> <b> change </b> </td> 
               <td> <a name=\"$sw:$portname\"> <b> $portname </b>  $sp4 </a> </td>
               <td> <b> $status_hash->{vlan} </b>  $sp4 </td>
               <td> $status_hash->{status} $sp4 </td>
               ";
        print "<td> $status_hash->{desc}   $sp4 </td> ";
        if ($vlanh->{$status_hash->{vlan}} eq "wism") { print "<td> wireless AP $sp4 </td> </tr>"; }
        elsif ($status_hash->{vlan} =~ /trunk/)       { print "<td> trunk port $sp4 </td> </tr>"; }
        elsif ($status_hash->{vlan} eq "1")           { print "<td> Contact $nuser\@$domain $sp4 </td> </tr>"; }
        elsif ($status_hash->{vlan} =~ /\A29/)        { print "<td> Contact $nuser\@$domain $sp4 </td> </tr>"; }
        else                                          { print "</tr>\n"; }
        ## this makes the linked mac address with the date below the port line:
        if ($status_hash->{vlan} !~ /trunk/)  {
           if (exists $pmac_hash->{$portname})  {
              while ( my($x,$y) = each(%{$pmac_hash->{$portname}} ))  {
                my $href = "<a href=\"https://$webcgi/netpeek/netpeek.cgi?submit=Submit&oper=query_mac&mac=$x\" $blank>$x</a>";
                print "<td> $sp4 $sp4 $sp4 $sp4 $sp4 $sp4 $sp4 $sp4 </td>
                       <td> $sp4 $sp4 $sp4 $sp4 $sp4 $sp4 $sp4 $sp4 </td>
                       <td> <b> $href </b> $sp4 </td>
                       <td>    $y      $sp4 </td></tr>";
              }
           }
        }
     }
     print "</table>";
     print "<input type=\"submit\" value=\"Submit\" name=\"submit\" > <b>Vlan Change</b> <br> <hr> <br>\n";
  } 
} ## print_switch_info

#####################################

sub port_status  {

  my $ln = shift;

  my $status_hash;
  my $status;
  if ($ln =~ /connected/)   { $status = "connected";    }
  if ($ln =~ /notconnect/)  { $status = "notconnect";   }
  if ($ln =~ /disabled/)    { $status = "disabled";     }
  if ($ln =~ /err-disab/)   { $status = "err-disabled"; }
  my ($front,$back) = split /$status/, $ln;
  my (undef,undef,undef,undef,$port,$desc) = split " ", $front, 6;
  my ($vlan,$duplex,$speed,$type) = split " ", $back;
  $status_hash->{port}   = $port;
  $status_hash->{desc}   = $desc;
  $status_hash->{vlan}   = $vlan;
  $status_hash->{status} = $status;
  $status_hash->{duplex} = $duplex;
  $status_hash->{speed}  = $speed;
  $status_hash->{type}   = $type;  

  return($status_hash);

} ## port_status

#####################################

sub queue_change_vlan  {

  ## called from oper = q_ch_vl

  my $switchname = shift;
  my $portname   = shift;
  my $newvlan    = shift;
  my $oldvlan    = shift;
  my $netid      = shift;

  if ($oldvlan == $newvlan)  {
     print "<br> <b> old vlan ($oldvlan) same as new vlan ($newvlan) - no change requested </b> <br><br>\n";
     Front_Page($access);
     print_switch_info($switchname);
     return;
  }

  print "queueing port <b> $portname </b> on switch $switchname for change to vlan$newvlan <br><br>\n";
  my $chvlan_hash;
  my $query = "SELECT * FROM network.forum_chvlanQ";
  my $select_h = $dbh->prepare($query);
  $select_h->execute();
  if ($select_h->rows != 0) {
     my $sel_ary = $select_h->fetchall_arrayref;
     foreach my $rec (@$sel_ary)  {
        my($swname,$port,$vlan,undef) = @$rec;
        $chvlan_hash->{"$swname $port $vlan"} = 1;
     }
  }

  if (exists $chvlan_hash->{"$switchname $portname $newvlan"})  {
     # print "$switchname $portname<br>\n";
     print "<font color=red> <b> = port previously queued - already in process = </b> </font> <br><br>\n";
  }
  else  {
     my $sql_cmd  = "INSERT INTO network.forum_chvlanQ (swname,port,vlan,netid) VALUES (?,?,?,?)";
     my $insert_h = $dbh->prepare($sql_cmd);
     $insert_h->execute($switchname,$portname,$newvlan,$netid);
     print " = port queued for vlan change = <br><br>\n";
  }
  print "<hr>\n";
  Front_Page($access);  # shows current queue
  print_switch_info($switchname);
 
  return;

} ## queue_change_vlan

#######################################

sub show_queue  {

  my $chvlan_hash;

  print "<b>current queue: </b> <br><br>\n";
  my $query = "SELECT * FROM network.forum_chvlanQ";
  my $select_h = $dbh->prepare($query);
  $select_h->execute();
  if ($select_h->rows != 0) {
     print "<table>";
     my $sel_ary = $select_h->fetchall_arrayref;
     foreach my $rec (@$sel_ary)  {
        my($swname,$port,$vlan,undef) = @$rec;
        #$chvlan_hash->{"$swname $port $vlan"} = 1;
        print "<tr> <td> $swname </td> <td> $port </td> <td> $vlan </td> </tr> \n";
     }
     print "</table>";
  }
  else  {  print "<b>...empty queue</b><br>\n"; }

}

###########################################

sub get_switchhash  {

  my $args = shift;
  my ($bldg,       # switchname prefix
      $bldgs,      # array of swname prefix instances
     );

  for (my $i=0; $i< scalar(@$args); $i++)  {
       while ($i < scalar(@$args))  {
          $bldg .= "$args->[$i] ";
          $i++;
       }
       @$bldgs = split " ", $bldg;
  }
  my ($switch_hash,$ping_switch_hash);
  my $select_h = $dbh->prepare("SELECT * from switch.ping WHERE ping = \"1\" ;" );
  $select_h->execute();
  my $sel_ary = $select_h->fetchall_arrayref;
  foreach my $rec (@$sel_ary)  {
     my($swname,$swip,undef) = @$rec;
     $ping_switch_hash->{$swip} = $swname;
  }
  if ($args)  {
     while (my($swip,$swname) = each(%$ping_switch_hash))  {
        foreach my $b (@$bldgs)  {
           if ($swname =~ /\A$b/)  {
              $switch_hash->{$swname} = $swip;   ### reverse of ping_switch_hash
           }
           if ($b =~ /\As30|s40/)  {
              $b =~ s/s//g;
              $switch_hash->{$b} = "128.248.149.$b" ;
           }
        }
     }
  }
  else  { %$switch_hash = reverse(%$ping_switch_hash); }

  return($switch_hash);
} ## get_switchhash

##########################################

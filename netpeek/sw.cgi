#!/usr/bin/perl
# by jackg -- Jack Gallagher
#
# switches.cgi
#
# For new code installs, check $ipprefix1 carefully - probably unneeded, but you may need...
#

use strict;

print "Content-type: text/html\n\n<html><body>";
print "<title> switches - all sorts of switch info </title>";
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
my $reachdata = deptdata();
my $dns1      = dns1();
my $dns2      = dns2();
my $dns3      = dns3();
my $ipprefix1 = ipprefix1();

## GLOBAL SCRIPT VARS
use vars qw(%network_staff %noc_staff %security_staff %systems_staff %auth %reachhash $fakenetid );
my $blank     = "target = \"_blank\"";
my $s4     = "&nbsp&nbsp&nbsp&nbsp";
my $s2     = "&nbsp&nbsp";

########## LOCAL AUTH CODE ############################################
require "$installpath/lib/auth.pl";
if (-f $reachdata)  {  require "$reachdata";  }
my $host = $ENV{REMOTE_ADDR} || "host unknown";
my %auth_hash = (%reachhash, %network_staff , %noc_staff , %security_staff, %systems_staff, %auth );
my ($netid,$realnetid);
$netid = $ENV{REMOTE_USER};
$netid =~ s/\/tacacs//;
$realnetid = $netid;
my @su = ("$admin","$netmgr","$neteng");  ## su can impersonate users by appending ?fakenetid=<user> to URL
if ( grep /^$realnetid$/, @su )  {
   $netid = $in->param('fakenetid') ? $in->param('fakenetid') : $realnetid;
   $fakenetid = $in->param('fakenetid');
   if ($fakenetid)  { print "*** superuser $realnetid connecting as $fakenetid <br>\n"; }
}
if (exists $auth_hash{$netid})  { print "netid '$netid' connecting from $host <br>\n"; }
else {
     print "<body bgcolor=red> <br><br> <h2><b><font color=green> User Authorization Failure </font></b> <br><br>";
     print "<b> Use of this page by $netid not authorized. <br><br>";
     print "Please contact <a href=\"mailto:$nuser\@$domain\">$nuser\@$domain</a></b>\n";
     exit;
}
#######################################################################

## each of these come in as a string, but that string can be a space-delimited list of elements
my $submit  = $in->param('submit');
my $vlannum = $in->param('vlannum');
my $swnames = $in->param('swnames');
if ($swnames =~ /systems/i)  {  $swnames = "s30 s40";  } ## special hack for Systems...

my $oper = $in->param('oper');  ## ALL the action starts here!

if ($submit eq "Submit")  {  
   unless ($oper)  {
      my $msg = "Please enter a search query.<br><br>\n";
      $oper = "main";
      Front_Page($msg);
      exit;
   }
}
else  {  $oper = "main";  }

## print "oper = >$oper<   swnames = >$swnames<  vlannum = >$vlannum<  <br>\n";
print "<a name=\"TOP\"> </a><br>\n";

my %oper    = (
    'main'    => sub{ Front_Page()   },
    'swlist'  => sub{ swnames_query($swnames) },
    'vlan'    => sub{ vlan_switch_query($vlannum) },
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
<h3> sw.cgi - switch stuff </h3>
<br><br>
<input type=\"submit\" value=\"Submit\" name=\"submit\" >
<table>
<tr>
<td align=left> 
EOF

print <<EOF;
<tr>
<td> <input type=\"radio\" value=\"swlist\" name=\"oper\" checked=\"checked\"> 
     <b> Any part of a building or switch name (multiples ok): </b> </td>
<td> <input type=\"text\" size=23 name=\"swnames\" value=\"\" > </td> </tr>
<tr> <td> To get switch 30, type s30, for 40, type s40. You can get both by typing  <b>systems</b> </tr>
<tr> <td> </td> </tr>
<tr> <td> </td> </tr>
EOF

print <<EOF;
<tr>
<td> <input type=\"radio\" value=\"vlan\" name=\"oper\">
     <b> Vlan number or name: </b> </td>
<td> <input type=\"text\" size=23 name=\"vlannum\" value=\"\" > </td> </tr>
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

sub swnames_query  {

  my $swnames = shift;
  #print "{swnames_query}: swnames = >$swnames< <br>\n";
  print "<b>Switchname based search of switches: </b> <br><br>";

  my $switchlist;
  @$switchlist = split " ", $swnames;
  ##foreach my $s (@$switchlist) { print "S: $s<br>"; }

  ## GET_PING_SWITCHES
  my $switch_hash;
  my $ping_switch_hash;
  my $select_h  = $dbh->prepare("SELECT * from switch.ping WHERE ping = \"1\" ;" );
  $select_h->execute();
  my $sel_ary = $select_h->fetchall_arrayref;
  foreach my $rec (@$sel_ary)  {
     my($swname,$swip,undef) = @$rec;
     $ping_switch_hash->{$swname} = $swip;
  }

  ## SWITCHLIST - the switches we are processing based on input text from Front_Page
  while (my($swname,$swip) = each(%$ping_switch_hash))  {
     foreach my $sw (@$switchlist)  {
        if ($swname =~ /\A$sw/)  {  $switch_hash->{$swname} = $swip;  }
        if ($sw =~ /\As30|s40/)  {
           $sw =~ s/s//g;
           $switch_hash->{$sw} = "$ipprefix1.$sw" ;  ## addressing for old routers (auther LOCAL hack)
        }
     }
  }
  my $swlist;  # array used to sort keys of switch_hash for printing in order
  foreach my $swname (keys %$switch_hash)  {  push @$swlist, $swname;  }
  @$swlist = sort @$swlist;
  foreach my $swname (@$swlist)  {  print "<a href=\"#$swname\"><b> $swname </b></a> <br>\n";  }
  foreach my $swname (@$swlist)  {
     my $swver_hash;
     my $query = "SELECT model,version,mac,swip FROM switch.version WHERE swname = \"$swname\" ";
     my $select_h  = $dbh->prepare($query); 
     $select_h->execute();
     my $sel_ary = $select_h->fetchall_arrayref;
     my ($model,$version,$mac,$swip);
     foreach my $rec (@$sel_ary)  {
        ($model,$version,$mac,$swip) = @$rec;
     }
     ## print "$swname $model $version $mac $swip <br>"; 
     print_port_info($swname,$model,$version,$mac,$swip); 
     print "<hr>";
  }
} ## swnames_query

#####################################

sub  vlan_switch_query  {

  my $vlan = shift;
  print "<b>Vlan $vlan based search of switches: </b> <br><br>";

  ## get switches on vlan
  my $query = "SELECT DISTINCT swname,swip from switch.vlan WHERE vlan = \"$vlan\";";
  my $select_h = $dbh->prepare($query);
  $select_h->execute();
  if ($select_h->rows != 0) {
     my $sel_ary = $select_h->fetchall_arrayref;
     my $swlist;
     my $swhash;
     foreach my $rec (@$sel_ary)  {
        my ($swname,$swip) = @$rec;  
        push @$swlist, $swname;        
        $swhash->{$swname} = $swip;
     }
     @$swlist = sort @$swlist;
     foreach my $sw (@$swlist)  {  print "<a href=\"#$sw\"><b> $sw </b></a> <br>\n";  }
     ##foreach my $rec (@$sel_ary)  {
     foreach my $swname (@$swlist)  {
        my $swip = $swhash->{$swname};
        my $swver_h  = $dbh->prepare("SELECT model,version,mac from switch.version WHERE swname = \"$swname\" ;" );
        $swver_h->execute();
        if ($swver_h->rows != 0) {
           my $swver_ary = $swver_h->fetchall_arrayref;
           foreach my $rec (@$swver_ary)  {
              my ($swmodel,$swversion,$swmac) = @$rec;
              print_port_info($swname,$swmodel,$swversion,$swmac,$swip);
              print "<hr>";
           }
        }
     }
  }
  else  {  print "No current entries found in switch.vlan for switches on vlan $vlan <br>\n";  }

} ## vlan_switch_query

#####################################

sub print_port_info   {

   my $sw        = shift;
   my $swmodel   = shift;
   my $swversion = shift;
   my $swmac     = shift;
   my $swip      = shift;
 
   ##print "swname=>$sw< swmodel=>$swmodel< $swversion=>$swversion< swmac=>$swmac< swip=>$swip< <br>";
 
   ## set up mac data
   my $pmac_hash;   ## all macs from that switch by port
   my $query = "SELECT * FROM switch.mac WHERE swname = \"$sw\" ORDER BY recent desc;";
   my $select_h = $dbh->prepare($query);
   $select_h->execute();
   my $sel_ary = $select_h->fetchall_arrayref;  
   if ($select_h->rows != 0) {
      foreach my $rec (@$sel_ary)  {
         my ($mac,$vlan,$port,$swip,undef,undef,$recent) = @$rec; 
         if (!exists $pmac_hash->{$port}->{$mac})  {
            $pmac_hash->{$port}->{$mac} = "$recent";    
         }   
      }
   }
   ## TEST PMAC in BLUE:
   #foreach my $p (keys %$pmac_hash) {
   #   foreach my $m (keys %{$pmac_hash->{$p}} ) {
   #      my $r = $pmac_hash->{$p}->{m};
   #      print "<font color=blue>pmac</font> <b> $p $m $r </b></br>";
   #   }
   #}

   my $voice_vlan;
   $select_h  = $dbh->prepare("SELECT port,voice from switch.intcfg where swname = \"$sw\";");
   $select_h->execute();
   if ($select_h->rows != 0) {
      $sel_ary = $select_h->fetchall_arrayref;  
      foreach my $rec (@$sel_ary)  {
         my ($pt,$vox) = @$rec;
         $voice_vlan->{$pt} = $vox;  
      }
   }
   ### TEST VOX in GREEN
   #foreach my $p (keys %$voice_vlan)  {
   #   my $v = $voice_vlan->{$p};
   #   print "<font color=green>vox</font> <b> $p $v </b></br>";
   #}
 
   my $power_h;  
   my $select_h  = $dbh->prepare("SELECT total,used,remaining from switch.power where swname = \"$sw\";");
   $select_h->execute();
   if ($select_h->rows != 0) {
      $sel_ary = $select_h->fetchall_arrayref;
      foreach my $rec (@$sel_ary)  {
         my ($tot,$used,$rem) = @$rec;
         $power_h->{"total"}     = $tot;
         $power_h->{"used"}      = $used;
         $power_h->{"remaining"} = $rem;
      }
   }

   my $inline_h;
   my $select_h  = $dbh->prepare("SELECT interface,oper,power,max,device from switch.inline where swname = \"$sw\";");
   $select_h->execute();
   if ($select_h->rows != 0) {
      $sel_ary = $select_h->fetchall_arrayref;
      foreach my $rec (@$sel_ary)  {
         my ($int,$oper,$power,$max,$device) = @$rec;
         $inline_h->{$sw} = $sw;              ## this only functions as a control flag below
         $inline_h->{$int}->{"int"}    = $int;
         $inline_h->{$int}->{"power"}  = $power;
         $inline_h->{$int}->{"oper"}   = $oper;
         $inline_h->{$int}->{"max"}    = $max;
         $inline_h->{$int}->{"device"} = $device;
      }
   }


   print "<br>\n";
   print "<a HREF=\"https://$webcgi/netpeek/sw.cgi\"> ";
   print "back to switchmeister home page </a> <br><hr>";
   print "<a href=\"#TOP\"><b> back to top </b></a>";
 
   ## set up port data
   my $ports;
   my $blank  = "target = \"_blank\"";
   $select_h = $dbh->prepare("SELECT * from switch.vlan where swname=\"$sw\"; ");
   $select_h->execute();
   if ($select_h->rows != 0) {
      ## print switch global data line
      print "<table>\n";
      print "<tr><td> <a name=\"$sw\"> </a> </td> "; 
      print "<tr> <td> <b>$sw</b>        $s2 </td>
                  <td> <b>$swip</b>      $s2 </td>
                  <td> <b>$swmac</b>     $s4 </td> 
                  <td> <b>$swmodel</b>   $s2 </td>
                  <td> <b>$swversion</b> $s4 </td> 
                  <td> <b>*</b>              </td>
                  <td> <b>Power:</b>              </td>";
      print "<td> <b> Total/Avail:", $power_h->{"total"},     "</b> </td>";
      print "<td> <b> Used:",        $power_h->{"used"},      "</b> </td>";
      print "<td> <b> Remaining:",   $power_h->{"remaining"}, "</b> </td>";
      print "</tr>";
      ## make nice headers
      print "<tr><td>$s4 $s4 $s4 $s4 $s4 </td>
                 <td> <b>port</b>             </td> 
                 <td> <b>vlan/mac</b>         </td>  
                 <td> <b>voxvlan/recent</b>   </td> 
                 <td> <b>status</b>           </td> 
                 <td> <b>duplex</b>           </td> 
                 <td> <b>speed</b>            </td>
                 <td> <b>type</b>             </td>
                 <td> <b>port_description</b> </td>";
      if (exists $inline_h->{$sw})  {
         print  "<td> <b>oper</b>             </td>
                 <td> <b>power/max</b> $s4    </td> 
                 <td> <b>device</b>           </td>" 
      }
      print "</td>";
      $sel_ary = $select_h->fetchall_arrayref;  ## 2D array
      foreach my $rec (@$sel_ary)  {  
         ## port-related data
         my (undef,$swip,$swname,$port,$name,$status,$vlan,$duplex,$speed,$type) = @$rec;      
         print "<tr><td> $s4 $s4 $s4 $s4 $s4 </td>
                    <td> <a name=\"$sw:$port\"> <b> $port </b> $s4 </a> </td>
                    <td> <b> $vlan </b> $s4 </td>
                    <td> <b> $voice_vlan->{$port} </b>  $s4 </td>
                    <td> $status $s4 </td>
                    <td> $duplex $s4 </td>
                    <td> $speed  $s4 </td>
                    <td> $type   $s4 </td>
                    <td> $name   $s4 </td>";
         if (exists $inline_h->{$sw})  {                          ## note: port = int
            print  "<td>", $inline_h->{$port}->{"oper"}, "</td>";
            print  "<td>", $inline_h->{$port}->{"power"}, "/", $inline_h->{$port}->{"max"}, "</td>";
            print  "<td>", $inline_h->{$port}->{"device"}, "</td>";
         }
         print "</tr>";

         ## mac-related data
         if (exists $pmac_hash->{$port})  {
            while ( my($x,$y) = each(%{$pmac_hash->{$port}} ))  {
               my $href = "<a href=\"https://$webcgi/netpeek/netpeek.cgi?submit=Submit&oper=query_mac&mac=$x\" $blank > $x </a> ";
               my ($day,$tim,$vl) = split " ", $y;
               print "<tr> <td> $s4 $s4 $s4 $s4 $s4 $s4 $s4 $s4 </td>
                           <td> $s4 $s4 $s4 $s4 $s4 $s4 $s4 $s4 </td>
                           <td> <b> $href </b> $s4 </td>
                           <td>     $day $tim  $s4 </td>
                           <td>     <b>$vl</b>     $s4 </td></tr>";
            }
            
         }
      }
      print "</table>";
   } 
} ## print_port_info

#################################################################################################################################


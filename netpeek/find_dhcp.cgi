#!/usr/bin/perl
# by jackg - Jack Gallagher
#
# find_dhcp.cgi
#
#
#

use strict;

## THIS FILE
my @fn = split /\//, $0;
my $thisfile = @fn[$#fn];

print "Content-type: text/html\n\n<html><body>";
print "<title> $thisfile - used to create dhcp fixies, statics, range pools, etc. </title>";
print "<body bgcolor=\"cccccc\">";

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
my $select_h;

push @INC,"$installpath/lib";
require "servers.pl";
my $admin     = admin();
my $nuser     = network();
my $domain    = dnssuffix();
my $webcgi    = webcgi();
my $dhcp1     = dhcp1();
my $dhcp2     = dhcp2();
my $dhcp1name = dhcp1name();
my $dhcp2name = dhcp2name();

use vars qw(%network_staff %noc_staff %security_staff %systems_staff %auth $webalias1 $gateway1);

########## LOCAL AUTH CODE ############################################
require "$installpath/lib/auth.pl";
my $host = $ENV{REMOTE_ADDR} || "host unknown";
my %auth_hash = (%network_staff,%noc_staff,%security_staff,%systems_staff);
my ($netid,$realnetid);
$netid = $ENV{REMOTE_USER};
$netid =~ s/\/tacacs//;
if (exists $auth_hash{$netid})  { print "netid '$netid' connecting from $host <br>\n"; }
else {
     print "<body bgcolor=red> <br><br> <h2><b><font color=green> User Authorization Failure </font></b> <br><br>";
     print "<b> Use of this page by $netid not authorized. <br><br>";
     print "Please contact <a href=\"mailto:$nuser\@$domain\">$nuser\@$domain</a></b>\n";
     exit;
}
###########################################################################

print "<a href=\"https://$webcgi/netpeek/$thisfile\"> <b> $thisfile home page </b></a> <br> <hr>";

my $oper;         
my $msg;          ## for passing error message to Front_Page
my $submit     = $in->param('submit');
my $vlan       = $in->param('vlan');
my $sub_pre    = $in->param('sub_pre');
my $datethresh = $in->param('datethresh');

if ($submit eq "Submit")  {  
   $sub_pre =~ s/\s//g;
   if ($sub_pre =~ /\d{1,3}\.\d{1,3}\.\d{1,3}/)  {
      my ($a,$b,$c,$d) = split /\./, $sub_pre;
      $sub_pre = "$a\.$b\.$c";
      $oper = "process";
   }
   elsif ($vlan ne "") { 
      $sub_pre="NONE";
      $oper = "process";
      }
   else  {  Front_Page("Please enter a vlan or a subnet prefix");  exit;  }
}
else  {  Front_Page();  exit;  }

print "<a name=\"TOP\"> </a>\n";

my %oper    = (
    'main'     => sub{ Front_Page($msg)   },
    'process'  => sub{ process($sub_pre,$vlan) },
    );

unless ($oper{$oper}) {
    print "Content-type: text/html\n\n<html><body>Bad query: oper=$oper sub_pre=$sub_pre </body></html>\n";
    exit;
}
$oper{$oper}->();  ## Action!

help();

exit;

##########################################################################

sub Front_Page  {

   my $msg = shift || "";
   print "<font color=red> $msg </font> \n";

my $s = "&nbsp";

print <<EOF;
<form method=\"post\" action=\"$ENV{'SCRIPT_NAME'}\">
<h3> $thisfile - need a dhcp ip? </h3>
<br><br>
<input type=\"submit\" value=\"Submit\" name=\"submit\" >
EOF

## input_vlan  and  sub_pre
print <<EOF;
<table>
<tr> 
<td align=left> VLAN number (takes precedence over below) </td> 
<td align=left> <input type=\"text\" size=5 name=\"vlan\" value=\"\" > </td> 
</tr>
<tr> <td>-OR-</td> </tr>
<tr>
<td>First three octets of a /24 (i.e. 192.168.199, etc.) </td>
<td align=left> <input type=\"text\" size=23 name=\"sub_pre\" value=\"\" > </td>  
</tr>
</table>
<br><br>
EOF

## datethresh
print <<EOF;
<tr>
<td> Optional: Oldest <b> recent </b> date threshold (yyyy-mm-dd)  </td>
<td> <input type=\"text\" size=23 name=\"datethresh\" value=\"\" > </td>
</tr>
<br><br>
EOF

print <<EOF;
<input type=\"submit\" value=\"Submit\" name=\"submit\" >   <br> <br>
<hr>
In case of problems with this page, send email to
<em> <a HREF=\"mailto:$nuser\@$domain\"> $nuser\@$domain </a> </em> <br>
<hr>
EOF

return;

}  ## Front_Page

###################################

sub process  {

   my $subpre = shift;
   my $vlan = shift;

   my $netnum;
   my $iphash;         ## master hash of all ips found in query
   my $ips;            ## array made from $iphash for sorting and loop control
   my $subnethash;     ## hash of subnets found in query, each in form gateway/mask
   my $dhcpserverhash; ## yes, it is a hash of dhcp servers found in query
   my $splits;         ## array of all splits in this query
   my $numsplits;

   my (undef,undef,undef,$mday,$mon,$year,undef,undef,undef) = localtime(time);
   $mon += 1;
   $year = 1900+$year;
   if ($mon  < 10)  { $mon = "0$mon";   }
   if ($mday < 10)  { $mday = "0$mday"; }
   my $today = "$year-$mon-$mday";

   # First section: figure out vlan or subpre
   # The critical thing is to build the list of ips/iphash based on the query.
   # Create for this query: %$iphash, %$subnethash, %$dhcpserverhash, 
   # If subpre, get $vlan 

   my $sel_ary;  ## we'll use this outside the loop thaet acquires this info
   my ($vlansearch,$subpresearch);  ## convenience toggles for search type
   if ($vlan ne "")  {  $vlansearch   = 1;  }  ## Vlan entered
   else              {  $subpresearch = 1;  }  ## Subpre entered
   if ($vlansearch)  { 
      print "<b>vlan search:</b> $vlan<br>";
      # process vlan query
      my $query = "SELECT * from network.vlanmap WHERE vlan = \"$vlan\" ; ";
      $select_h = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows == 0)  {  print "No network segments found searching vlan <b>$vlan</b> <br>";  }
      else  {  $sel_ary = $select_h->fetchall_arrayref;  }
   }
   else   {       ## subpre serch
      print "<b>subnet prefix search:</b> $subpre<br>";
      my $query = "SELECT * from network.vlansplits WHERE subpre like \"$subpre\.%\" ; ";
      $select_h = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows == 0)  {  print "No network segments found using <b>$subpre</b> <br>";  }
      else  {
         $sel_ary = $select_h->fetchall_arrayref; 
         my $vlan = $sel_ary->[0]->[0];
         $query = "SELECT * from network.vlanmap WHERE vlan = \"$vlan\" ; ";
         $select_h = $dbh->prepare($query);
         $select_h->execute();
         ## prob'ly don't need the 'if' check, but it would uncover a vlanmap/vlansplits mismatch, so leave it in.
         if ($select_h->rows == 0)  {  print "No network segments found searching vlan <b>$vlan</b> <br>";  }
         else  {  $sel_ary = $select_h->fetchall_arrayref;  }
      }  
   }  ## else - subpre entered
   foreach my $row (@$sel_ary)  {
      my($subnet,$dhcpserver);  ## We're assigning $vlan below (as there was none given in this subpre search)
      ($vlan,undef,$subnet,undef,$dhcpserver,undef,undef) = @$row;
      ## Need to uniquify the subnets here via gateway manipulation and hash entry
      my($gateway,$mask) = split /\//, $subnet;
      my ($a,$b,$c,$d)   = split /\./, $gateway;
      if ($mask == 24)  {  $subnet = "$a.$b.$c.1/24";  } 
      if ($mask == 16)  { }
      if ($mask > 24)   {
         my $increment = 2**(32-$mask);
         my $num = 0;
         while ($num+$increment < $d)  {  $num = $num + $increment;  }
         my $gate = $num+1;
         $subnet = "$a.$b.$c.$gate/$mask";
      }
      if ($mask > 16 && $mask < 24)  {
         my $increment = 2**(24-$mask);
         my $num;
         while ($num+$increment <= $c)  {  $num = $num + $increment;  }
         $subnet = "$a.$b.$num.1/$mask";
      }
      $subnethash->{$subnet}->{"vlan"} = $vlan;
      $subnethash->{$subnet}->{"mask"} = $mask;
      $dhcpserverhash->{$dhcpserver} = 1;   
   }  

   # Process subnets found into iphash entries
   foreach my $subnet (keys %$subnethash)  {
      my($gateway,$mask) = split /\//, $subnet;
      my ($a,$b,$c,$d)   = split /\./, $gateway;
      if ($mask == 16)  {
         $netnum = "$a.$b.0.0"; 
         print "<b>subnet found: $subnet </b> <br>";
         print "<br>";
         print "<font color=red> *** </font> For /16 network queries, please contact ";  
         print "<em> <a HREF=\"mailto:$nuser\@$domain\"> $nuser\@$domain </a> </em> directly <br> <br>";
         print "<hr>";
         exit;
      }
      if ($mask > 16 && $mask < 24)  {
         my $numsubs = 2**(24-$mask);
         my $num;
         while ($num+$numsubs < $c)  {  $num = $num + $numsubs;  }
         $netnum = "$a.$b.$num.0";
         for (my $j=0; $j<$numsubs; $j++)  { 
            for (my $i=0; $i<=255; $i++)  {
               my $t = $c + $j; 
               $iphash->{"$a.$b.$t.$i"}->{"pool"} = "-";
            }
         }
      }
      if ($mask == 24)  {
         $netnum = "$a.$b.$c.0";
         for (my $i=0; $i<=255; $i++)  {  $iphash->{"$a.$b.$c.$i"}->{"pool"} = "-";  }
      }
      if ($mask > 24)   {
         my $subsize = 2**(32-$mask);
         my $num = 0;
         while ($num+$subsize < $d)  {  $num = $num + $subsize;   }
         $netnum = "$a.$b.$c.$num";
         for (my $i=0; $i<$subsize; $i++)  {
            my $t = $num + $i;
            $iphash->{"$a.$b.$c.$t"}->{"pool"} = "-";
         }
      }
      $subnethash->{$subnet}->{"netnum"} = $netnum;
      $subnethash->{$subnet}->{"mask"}   = $mask;
   }

   # Populate @$ips array
   foreach my $ip (keys %$iphash)  {  push @$ips, $ip;   }  
   ### Get iphash parm values
   foreach my $ip (@$ips)  { 
      # Static NATs
      my $query = "SELECT * from network.staticmap WHERE pubip = \"$ip\" OR privip = \"$ip\";  ";
      $select_h = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0)  { 
         my $sel_ary = $select_h->fetchall_arrayref;
         foreach my $row (@$sel_ary)  {
            my($privip,$pubip,undef,undef,undef) = @$row;
            if ($ip eq $privip)  { $iphash->{$ip}->{"static"} = $pubip;  }
            if ($ip eq $pubip)   { $iphash->{$ip}->{"static"} = $privip; }
         }
      }
      # Fixies
      my $query = "SELECT * from network.fixies WHERE ip = \"$ip\"  ";
      $select_h = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0)  { $iphash->{$ip}->{"pool"} = "fixie";            }
      # Ranges
      my $query = "SELECT * from network.ranges WHERE ip = \"$ip\"  ";
      $select_h = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0)  { $iphash->{$ip}->{"pool"} = "range"; }
      # ReapIP
      my $query = "SELECT * from arp.reapIP WHERE ip = \"$ip\"  ";
      $select_h = $dbh->prepare($query);
      $select_h->execute();
      my $mac;
      if ($select_h->rows != 0)  {
         my $sel_ary = $select_h->fetchall_arrayref;
         $mac       = $sel_ary->[0]->[1];
         my $recent = $sel_ary->[0]->[2];
         $iphash->{$ip}->{"reapIP mac"}    = $mac;
         $iphash->{$ip}->{"reapIP recent"} = $recent;
      }
      # Reapmac
      my $query = "SELECT * from arp.reapmac WHERE mac = \"$mac\"  ";  ## mac from above reapIP query
      $select_h = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0)  {
         my $sel_ary = $select_h->fetchall_arrayref;
         my $recent = $sel_ary->[0]->[1];
         my $vlan   = $sel_ary->[0]->[4];
         $iphash->{$ip}->{"reapmac recent"} = $recent;
         $iphash->{$ip}->{"reapmac vlan"}   = $vlan;
      }
   } 

   ## SUBNETS  (and $vlanhash setup)         
   my $s2 = "&nbsp&nbsp";
   my $blank  = "target = \"_blank\"";
   print "<br>";
   print "<b>Subnets found:</b> <br>"; 
   my $subnetarray;
   foreach my $subnet (keys %$subnethash)  {  push @$subnetarray, $subnet;  }
   $subnetarray = sort_ips($subnetarray);
   print "<table border=3>";
   print "<th align=left> subnet </th> <th align=left> vlan </vlan> </th>";
   foreach my $subnet (@$subnetarray)  {
      my $vl = $subnethash->{$subnet}->{"vlan"};
      if ($subpresearch)  {  print "<tr><td> $subnet $s2</td> <td> <a href=\"./$thisfile?submit=Submit&vlan=$vl\" $blank> $vl </a> $s2 </td></tr>\n";  }
      else                {  print "<tr><td> $subnet $s2</td> <td> $vl $s2</td></tr>\n";  }
   } 
   print "</table>";
   print "<br>";

   ## VLANSPLITS -- these ip entries have the trailing '.' built-in
   my $query;
   if ($subpresearch)  {  $query = "SELECT * from network.vlansplits WHERE subpre = \"$subpre.\"  ";  }
   else                {  $query = "SELECT * from network.vlansplits WHERE vlan   = \"$vlan\"     ";  }  ## default case
   $select_h = $dbh->prepare($query);
   $select_h->execute();
   my $splitshash;
   if ($select_h->rows != 0)  {     
      my $sel_ary = $select_h->fetchall_arrayref;
      my($gate,$mask);
      foreach my $row (@$sel_ary)  { 
         my(undef,$split,$sub) = @$row;
         ($gate,$mask) = split /\//, $sub;
         if ($mask > 24)  {
            $splitshash->{$sub}->{"mask"}  = $mask;
            $splitshash->{$sub}->{"gate"}  = $gate;
            $splitshash->{$sub}->{"sub"}   = $sub;
         }
         else  {
            $splitshash->{$split}->{"mask"}  = $mask;
            $splitshash->{$split}->{"gate"}  = $gate;
            $splitshash->{$split}->{"sub"}   = $sub;
         }
      }
      foreach my $split (keys %$splitshash)  {
         ##if ($splitshash->{$split}->{"mask"} gt "24")  {  push @$splits, $splitshash->{$split}->{"sub"}; print $splitshash->{$split}->{"sub"},"<br>\n";}
         if ($splitshash->{$split}->{"mask"} gt "24")  {  push @$splits, $splitshash->{$split}->{"sub"}; }
         else                                          {  push @$splits, "$split"."0"; }
      }
   } 
   $numsplits = scalar @$splits;
   if ($vlansearch)  {
      if ($numsplits == 1)  {  print "Vlan $vlan has $numsplits split:<br>\n";  }
      else                  {  print "Vlan $vlan has $numsplits split(s):<br>\n";  }
   }
   else  {
      if ($numsplits == 1)  {  print "Subnet prefix $subpre has $numsplits split:<br>\n";  }
      else                  {  print "Subnet prefix $subpre has $numsplits split(s):<br>\n";  }
   }
   # Print Splits
   $splits = sort_ips($splits);
   foreach my $split (@$splits)  {
      if ($splitshash->{$split}->{"mask"} > 24)  { 
         my($a,$b,$c,$d) = split /\./, $splitshash->{$split}->{"gate"};
         $d = $d-1;
         my $ntn = "$a.$b.$c.$d";
         print "<a href=\"#$ntn\">", $splitshash->{$split}->{"sub"}, "</a> <br>\n";
      }
      else  {  print  "<a href=\"#$split\"> $split <\/a> <br>\n";  }
   } 
   print "<br>";

   my $s1 = "&nbsp;";
   my $s3 = "&nbsp;&nbsp;&nbsp;";

   ## DHCP Servers
   my $dhcpfilename;
   foreach my $ds (keys %$dhcpserverhash)  {
      if ($ds eq "$dhcp2") {
         $dhcpfilename = "/mnt/global/dhcp/conf/$vlan-dhcpd.conf";
         print "<b>DHCP</b> configuration file on <b>$dhcp2name</b> ($dhcp2) $s3 <b>$dhcpfilename</b> <br>\n";
         last;
      }
      elsif ($ds eq "$dhcp1") {
         $dhcpfilename = "/mnt/global/dhcp/dhcpd.conf";
         print "<b>DHCP</b> configuration file on <b>$dhcp1name</b> ($dhcp1) $s3 <b>$dhcpfilename</b> <br>\n";
         last;
      }
   } 
   #foreach my $subnet (@$subnetarray)  {  print "SUBNET $subnet<br>";  }

   ## VPN ips - grab DHCP comment documentation and populate "pool" field
   if ($dhcpfilename)  {
      foreach my $subnet (@$subnetarray)  {
         my $dhcpfh = IO::File->new("$dhcpfilename ");
         my $subnet_found;
         my $netnum = $subnethash->{$subnet}->{"netnum"}; 
         while (my $ln = <$dhcpfh>)  {
            chomp($ln);
            if ($ln =~ /\s*\#\-/)  { next; }
            if ($ln =~ /^\s*subnet/ && ($subnet_found) )  {  last;  }               ## next subnet begins
            if ($ln =~ /^\s*subnet\s+$netnum\s+netmask/)  {  $subnet_found = 1; }    ## current subnet begins
            if (!$subnet_found)    { next; }               
            if ($ln =~ /\s*\#/)  {
               $ln =~ s/\#\#/\#/g;
               $ln =~ s/\s+/ /g;
               $ln =~ s/^ //g;
               print "$ln <br>";
               if ( ($ln =~ /VPN RANGE/) || ($ln =~ /VPN USAGE/)) {
                  my (undef,undef,undef,$first,undef,$last) = split " ", $ln;
                  if ($first)  {
                     my ($a,$b,$c,$F4) = split /\./, $first;
                     my (undef,undef,undef, $L4) = split /\./, $last;
                     for (my $i=$F4; $i<=$last; $i++)  {  $iphash->{"$a.$b.$c.$i"}->{"pool"} = "VPN";  }
                  }
               }
            }
         }
      }

   }
   print "<br>";
   print "<b>Active DHCP servers on segment:</b> <br>"; 
   foreach my $ds (keys %$dhcpserverhash)  {
      if    ($ds eq $dhcp1)  {  print " <b>$dhcp1</b>";  } 
      elsif ($ds eq $dhcp2)  {  print " <b>$dhcp2</b>";   } 
      else                              {  print "$ds ";                     }
      print "<br>\n";
   } 
   print "<br>\n";

   ## IPHASH TABLE PRINT   
   print "<table border=\"5\">\n";
   print "<tr> <td><b> inside IP &nbsp&nbsp </b></td> <td><b> pool &nbsp&nbsp&nbsp </b></td> 
          <td><b> reapIP recent &nbsp&nbsp&nbsp </b></td> <td><b> reapIP mac &nbsp&nbsp&nbsp </b></td> 
          <td><b> reapmac recent &nbsp&nbsp&nbsp </b></td> <td><b> reapmac vlan &nbsp&nbsp&nbsp </b></td> 
          <td><b> static nat &nbsp&nbsp&nbsp </b></td></tr>\n";
   $ips = sort_ips($ips);
   foreach my $ip (@$ips)  {
      my $anchor = "<a name=\"$ip\">";
      my $href = "<a href=\"https://$webcgi/netpeek/netpeek.cgi?submit=Submit&oper=query_ip&ip=$ip\" $blank > ";
      print "<tr><td>$anchor $href $ip </a> $s3 </td>"; 
      print "<td> ", $iphash->{$ip}->{"pool"}, "</td>";   
      my $reaprec = $iphash->{$ip}->{"reapIP recent"};
      my ($reapyear,undef) = split /\-/, $reaprec, 2;
      if ($reaprec eq $today)       { print "<td><font color=firebrick> $reaprec </font> </td>"; }
      elsif ($reapyear eq $year)    { print "<td><font color=\"006400\"> $reaprec </font></td>"; }
      elsif ($reapyear eq $year-1)  { print "<td><font color=\"526252\"> $reaprec </font></td>"; }
      else                          { print "<td> <font color=darkgrey> $reaprec </font> </td>"; }
      my $reapIPmac = $iphash->{$ip}->{"reapIP mac"};
      $href = "<a href=\"https://$webcgi/netpeek/netpeek.cgi?submit=Submit&oper=query_mac&mac=$reapIPmac\" $blank > ";
      print "<td> $href $reapIPmac </a> </td>";
      my $rmrec = $iphash->{$ip}->{"reapmac recent"};
      my ($rmyear,undef) = split /\-/, $rmrec, 2;
      if ($rmrec eq $today)       { print "<td><font color=firebrick> $rmrec </font></td>"; }
      elsif ($rmyear eq $year)    { print "<td><font color=\"006400\"> $rmrec </font></td>"; }
      elsif ($rmyear eq $year-1)  { print "<td><font color=\"526252\"> $rmrec </font></td>"; }
      else                        { print "<td> <font color=darkgrey> $rmrec </font> </td>"; }
      print "<td> ", $iphash->{$ip}->{"reapmac vlan"}, "</td>";
      print "<td> ", $iphash->{$ip}->{"static"}, "</td>\n";
   }
   print "</table>\n";
 
print <<EOF; 
   <br>
   <a href="https://$webcgi/netpeek/$thisfile.cgi">
   <b> $thisfile home page </b> </a>  <br>
   <hr>
EOF

return;

} ## process


#####################################

sub sort_ips  {

  my $list = shift;
  # print "{sort_ips} <br>\n";
  # sort with Schwartzian transform/Goldstein variant:
  @$list =
    map {$_->[0]}
        sort {    ($a->[1] <=>$b->[1])
               || ($a->[2] <=>$b->[2])
               || ($a->[3] <=>$b->[3])
               || ($a->[4] <=>$b->[4])
             }
    map {[$_, split( '[ \.]', $_) ]} @$list;

  return($list);
} ## sort_ips  

###########################################

sub help  {

print "<hr>";
print <<EOF;
   <b> find_dhcp </b> helps to figure out the next best IP to use in a fixie.  <br>
   <br>
   <b> inside ip </b> = all IPs in the segment, excluding the existing fixies. <br>
   That leaves open IPs, range and VPN IPs, and mystery IPs like manual config IPs on the segment.
   <br>
   <b> pool </b> = status of IP
   <br>
   <b> recent arp </b> = last date an IP was seen in the arp cache at its gateway
   <br>
   <b> last mac used </b> = last mac address associated with this IP
   <br>
   <b> recent mac addr </b> = last date mac address was seen on a switch (from a db born 2012-04-28)
   <br>
   <b> recent mac vlan </b> = associated vlan for 'last mac addr'
   <br>
   <b> staticNAT </b> = outside IP associated with inside IP listed (if any). <br>
   Note that staticNATs generally have fixies, so a staticNAT without a fixie might be a little odd, <br>
   unless the whole net is still on public IPs (partial conversion) -- it will just show up that way. <br>
   <br> <br>
EOF

}



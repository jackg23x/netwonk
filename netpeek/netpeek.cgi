#!/usr/bin/perl
#
# by jackg - Jack Gallagher
#
# netpeek.cgi -- network/securityu data query web script
#

use strict;

print "Content-type: text/html\n\n<html><body>";
print "<title> netpeek - network data lookups </title>";
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

## GLOBAL SCRIPT VARS 
use vars qw(%reachhash %network_staff %noc_staff %security_staff %systems_staff %auth $vlanhash $vlan2subs 
            $fakenetid $datethresh $ipprefixes $script $blank $lim $s4 $s2 );

$script    = "netpeek.cgi";                                 

$blank     = "target = \"_blank\"";
$lim       = 5;   ## mysql select default lines limit
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
my ($date,$time) = date_time();
if (exists $auth_hash{$netid})  { print "netid '$netid' connecting from $host at $date $time<br>\n"; }
else {
  print "<body bgcolor=red> <br><br> <h2><b><font color=green> User Authorization Failure </font></b> <br><br>";
  print "<b> Use of this page by $netid not authorized. <br><br>";
  print "Please contact <a href=\"mailto:$nuser\@$domain\">$nuser\@$domain</a></b>\n";
  exit;
}
#######################################################################

my $submit      = $in->param('submit');
my $vlan        = $in->param('vlan');
   $vlan        =~ s/\s+//g;
   $vlan        =~ s/vlan//i;
my $vlanlong    = $in->param('vlanlong');
my $addr        = $in->param('addr');
   $addr        =~ s/;/ /g;
my $ip          = $in->param('ip');
   $ip          =~ s/;/ /g;
my $mac         = $in->param('mac');
   $mac         =~ s/;/ /g;
my $datethresh  = $in->param('datethresh');
my $ipprefix    = $in->param('ipprefix');
my $ipprefixes;
   @$ipprefixes = split " ", $ipprefix;

## set default $datethresh if needed
if ($datethresh eq "")  {
   my ($yyyy,$mm,$dd) = split /-/, $date;
   $yyyy = $yyyy-1;
   $datethresh = "$yyyy-$mm-$dd";
}

$vlanlong =~ s/vlan//i;
$vlan = $vlanlong || $vlan;

my $subs;
($vlanhash,$subs,$vlan2subs) = make_vlan_hash();
### two hashes, $ip->fixed-mac  and  mac->fixed-ip

my $msg;
my $oper = $in->param('oper');
if ($submit eq "Submit")  {
   unless ($oper)  { 
     $msg = "Please enter a search query.<br><br>\n";
     $oper = "main";
     Front_Page($vlanhash,$subs,$msg);
     exit;
   }  
}
else  {  $oper = "main";  }

my %oper = (
    main             => sub{Front_Page($vlanhash,$subs,$msg)},               # Front_Page
    query_vlan       => sub{query_vlan($vlan)},                              # vlan page
    query_address    => sub{query_address($addr)},                           # addresses page -> mac panels, ip panels
    query_vlan_ips   => sub{query_vlan_ips($vlan)},                          # vlan by ip   
    query_vlan_macs  => sub{query_vlan_macs($vlan,$datethresh,$ipprefixes)}, # vlan by mac
    unearth_mac_list => sub{unearth_mac_list($addr)},                        # addresses by mac
    morph_ip_list    => sub{morph_ip_list($addr)},                           # addresses by ip   
    query_mac        => sub{query_mac($mac)},                                # called in hyperlink text, not Front_Page
    query_ip         => sub{query_ip($ip)},                                  # called in hyperlink text, not Front_Page
);

unless (exists $oper{$oper}) {
    print "Content-type: text/html\n\n<html><body>Bad action $oper \n</body></html>\n";
    exit;  
}
print "<a href=\"https://$webcgi/netpeek/$script\">  <b> netpeek home page </b> </a>  <br><br> <hr>\n";
$oper{$oper}->();    ## *** Here's where it all happens ***
print "<br> <a href=\"https://$webcgi/netpeek/$script\"> <b> netpeek home page </b> </a>  <br><br>\n";
   
exit;

###############################################################################

sub Front_Page {

my $vlanhash = shift;
my $subs     = shift;
my $msg      = shift || "";


## TEST STUFF for hashes:
my $prtjackg = 0;
if ($netid eq "jackg" && $prtjackg)  {
   foreach (@$subs)  { print "subs: $_<br>\n"; }
   foreach my $key (sort keys %$vlanhash)  {  print "vlanhash: $key => ", $vlanhash->{$key}, "<br>\n";  }
   foreach my $key (sort keys %$vlan2subs)  {
      print "vlan2subs.key: $key<br>\n";
      foreach my $v ( @{$vlan2subs->{$key}} )  { print "vlan2subs.value: * $v <br>\n"; }
   }
}

print "<font color=red> $msg </font> \n";

print <<EOF;
  <form method=\"post\" action=\"$ENV{'SCRIPT_NAME'}\">
  <input type=\"hidden\" name=\"fakenetid\" value=\"$fakenetid\" >

<h3> $script - request network data  </h3>
<input type=\"submit\" value=\"Submit\" name=\"submit\" > <br>
<br> <b> Search options: </b> <br>
EOF

## Address Search
print <<EOF;
<table>
<tr><td><BR></td></tr>
<tr> 
<td> <input type=\"radio\" value=\"query_address\" name=\"oper\" checked=\"checked\"> <b> Address(es)</b> : </td>
<td> <input type=\"text\" size=23 name=\"addr\" value=\"\" >
     <b> mac or IP address(es) </b> - space delimited list accepted (interspersed text ok) </td>
</tr>
<tr> <td> $s4 <input type=\"radio\" value=\"unearth_mac_list\" name=\"oper\" > Mac based search of list (unearth) </td> </tr>
<tr> <td> $s4 <input type=\"radio\" value=\"morph_ip_list\" name=\"oper\" > IP based search of list (morph) </td> </tr>
<tr><td></td></tr>  
EOF

### Vlan Search
print <<EOF;
<tr>
<td align=left>
<input type=\"radio\" value=\"query_vlan\" name=\"oper\" >
<b>Vlan</b> overview -- switch, static, macfilter, DHCP data: </td>
<td align=left> <input type=\"text\" size=23 name=\"vlan\" value=\"\" >
enter one vlan only or choose here (overrides textbox):
EOF

print "<select size=4 name=\"vlanlong\">";
foreach my $s (@$subs)  {
    # my $sv = $vlanhash->{$s};
    # print "sv = $sv<br>\n";
    # print "<option value=\"$s\"> $s -> $vlanhash->{$s} </option>";
  print "<option value=\"$vlanhash->{$s}\"> $s -> $vlanhash->{$s} </option>";
}
print "</select>";
print "</tr>\n";

## Unearth macs
print <<EOF;
<tr>
<td colspan=2> $s4 <input type=\"radio\" value=\"query_vlan_macs\" name=\"oper\" >
               Mac address based search of vlan above - w/dhcp info (unearth) </td>
</tr>
EOF

## Morph IP
print <<EOF;
<tr>
<td colspan=2> $s4 <input type=\"radio\" value=\"query_vlan_ips\" name=\"oper\" >
 IP address based search of vlan above (morph) </td>
</tr>

<tr><td><hr></td></tr>

<tr>
<td> Global Option: Oldest <b> recent </b> date threshold (yyyy-mm-dd)                   </td>
<td> <input type=\"text\" size=23 name=\"datethresh\" value=\"\" > (Default filter = 1 year) </td> </tr>
<tr>

<td> Global Option: IP prefixes included (space delimited, by regex)     </td>
<td> <input type=\"text\" size=23 name=\"ipprefix\" value=\"\" > (eg. 192.168.4 192.168.5) </td> </tr>
</tr>

</table>

EOF

} ## Front_Page

################################################################################

sub make_vlan_hash  {

   my $vlanhash;  #
   my $subs;  # array

   ## source: network.vlanmap  ( Note - this is very different than network.ipvlanmap )
   my $query = "SELECT vlan,subnet FROM network.vlanmap";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   while ( (my @row) = $select_h->fetchrow_array )  {
      my ($vlan,$subnet) = @row;
      my ($ip,$mask) = split /\//, $subnet;
      if ($mask > 28)  {  next;  }
      if ($mask == 0)  {  next;  }
      if (exists $reachhash{$netid})  {
         if ($vlan =~ /\A667|672|305|301|455\z/)  { next; }  ## Reach folks can't see these
      }
      my ($net,$mask) =  split /\//, $subnet;
      my ($a,$b,$c,$d) = split /\./, $net;
      $d = $d-1;  ## gateway to network number correction
      my $newsub = "$a\.$b\.$c\.$d/$mask";
      $vlanhash->{"$newsub"} = $vlan;              
   }
 
   my $temps;  ## for $admin thing below
   foreach my $k (keys %$vlanhash)  {
      push @$subs, $k;
      push @$temps, "$k => $vlanhash->{$k} ";
   }
   $subs = sort_by_ip($subs);
 
   ## Make %$vlan2subs hash too.
   while (my($x,$y) = each(%$vlanhash))  {  push @{ $vlan2subs->{$y} }, $x;  }
 
   ########################
   my $prt=0; 
   if ($prt)  {
      if ($netid eq "$admin")  {
        print "<b>vlanhash</b> <br>";
       # while (my($x,$y) = each(%$vlanhash))  { print "$x => $y <br>\n"; }
        my $tempary;
        while (my($x,$y) = each(%$vlanhash))  { push @$tempary, $x; }
        $tempary = sort_by_ip($tempary);
        foreach my $i (@$tempary)  {
           print "$i => ", $vlanhash->{$i}, "<br>\n";
        }
        print "<hr>";
        print "<b>vlan2subs</b> <br>";
        foreach my $key (sort keys %$vlan2subs)  {
           print "$key<br>\n";   
           foreach my $v ( @{$vlan2subs->{$key}} )  { print "&nbsp&nbsp&nbsp $v <br>\n"; }  
        } 
        print "<hr> <b>subs</b> <br>";
        foreach (@$subs)  { print "$_<br>\n"; }
        print "<hr> <b>temps</b> <br>";
        foreach (@$temps)  { print "$_<br>\n"; }
      }
   }
   #######################
 
   return($vlanhash,$subs,$vlan2subs);
} ## make_vlan_hash

#################################################################################

sub query_address  {

   my $addr = shift;

   ## print "{query_addresses}:  addr = >$addr<  <br>\n";

   $addr =~ s/\n/  /g;  ## replace linefeeds with space
   my ($addrs,$unique_addrs);     
   @$addrs = split " ", $addr;    ## split the address textbox info

   my ($aips,$amacs);  ## collector array refs
   foreach my $a (@$addrs)  {  
      if ($a =~ /\A\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\%\s*\z/)  {   ## subnet wildcard
         if ( $a =~ /\A255\./ )  {  next;  }
         if ( $a =~ /\A0\./ )  {  next;  }
         $a =~ s/\.\%//;   ## remove last octet
         for (my $i=0; $i<256; $i++)  { 
            if ( exists $unique_addrs->{"$a.$i"} )  {  next;  }     ## avoid presenting duplicates
            $unique_addrs->{"$a.$i"} = 1;
            push @$aips,"$a.$i";
         }  
      }
      elsif ($a =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {   
         if ( $a =~ /\A255\./ )  {  next;  }
         if ( exists $unique_addrs->{$a} )  {  next;  }             ## avoid duplicates
         $unique_addrs->{$a} = 1;
         push @$aips,$a;
      }
      else  {
         $a = fix_mac($a);
         if ($a =~ /^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$/)  {
            if ( exists $unique_addrs->{$a} )  {  next;  }          ## avoid duplicates
            $unique_addrs->{$a} = 1;
            push @$amacs,$a;
         }
      }
   }
   $aips  = sort_by_ip($aips);
   ##   foreach my $a (@$aips)   {  print "addr: $a <br>";   }
   foreach my $a (@$aips)   {  query_ip($a);   }
   foreach my $a (@$amacs)  {  query_mac($a);  }

   return;
}  ## query_address

#################################################################################

sub p  {
   my $n = shift;
   print "CHECKPOINT $n <br>\n";
return;
}

#################################################################################

sub print_header  {

   my $header = shift;

   print "<tr>"; 
   foreach my $hd (@$header)  { print "<th align=left> $hd </th>"; }
   print "</tr>";
   return;
}

#################################################################################

sub print_lines  {

   my $lines_array = shift;  ## 2D array of lines, each line an array
   my $htmlcode    = shift;  ## a mask-like array that tells whether a variable needs an html wrap

   ### foreach my $line (@$lines_array)  {  print "test: >", @$line, "< <br>";  }

   my $macfilters;      ## hash where filtered mac is key
   my $macflag;         
   foreach my $flag (@$htmlcode) {
      if ($flag eq "mac")  { $macflag = 1;  }
   }
   if ($macflag)  {
      ## get macfilter hash
      my $query = "SELECT DISTINCT(mac) from network.macfilters";
      my $select_h  = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0) {
         my $sel_ary = $select_h->fetchall_arrayref;
         foreach my $row (@$sel_ary)   {  $macfilters->{$row->[0]} = 1;  } 
      }
   }

   my $s = "&nbsp&nbsp";
   foreach my $line (@$lines_array)  {
      print "<tr>";
      my $i = 0;
      foreach my $rec (@$line)  {
         my $field = $htmlcode->[$i];
         my $rec = $line->[$i];
         my $href;              ## set the href printing options
         if ($field eq "mac" && $macfilters->{$rec} && $rec ne "-") {
            my $href = "<a href=\"https://$webcgi/netpeek/$script?submit=Submit&oper=query_$field&fakenetid=$fakenetid&$field=$rec\" $blank > ";
            print "<td align=left> $href <font color=red> $rec</a> $s </font> </td> \n";  
         }
         elsif ($field eq "swname") {
            my $href = "<a href=\"https://$webcgi/netpeek/sw.cgi?submit=Submit&oper=swlist&swnames=$rec\" $blank > ";
            print "<td align=left> $href $rec</a> $s </td> \n";  
         }
         elsif ($field && $rec ne "-") {
            my $href = "<a href=\"https://$webcgi/netpeek/$script?submit=Submit&oper=query_$field&fakenetid=$fakenetid&$field=$rec\" $blank > ";  
            print "<td align=left> $href $rec</a> $s </td> \n";  
         }
         else  {  print "<td align=left> $rec</a> $s </td> \n";  }
         $i++;
      }
      print "</tr>";
   }
   return;
}  ## print_lines

#################################################################################

sub query_domain_name  {

   my $ip = shift;

   my $dname;
   my $res = Net::DNS::Resolver->new;
   $res->nameservers($dns1,$dns2,$dns3);
   my $query = $res->search("$ip");
   if ($query) {
       foreach my $rr ($query->answer) {
           next unless $rr->type eq "PTR";
           $dname = $rr->ptrdname;
       }
   }
   return($dname);
}

#################################################################################

sub query_staticnat  {

   my $ip = shift;

   my ($privip,$pubip,$vlan,$context,$int);  ## the privip/pubip info found in a staticNAT mapping
   my $static_hash;
   my $select_h  = $dbh->prepare("SELECT * FROM network.staticmap WHERE pubip = \"$ip\" OR privip = \"$ip\"; " );
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      ($privip,$pubip,$vlan,$context,$int) = @{$sel_ary->[0]};
      if ($privip == $pubip)  {  next;  }
      if (exists $static_hash->{"$pubip => $privip"} )  {  next;  }
      print "<b> Static NAT: $pubip => $privip </b> ";
      if (exists $reachhash{$netid})  {  print "<br>";  }
      else  { print "<b> on $context  $int </b> <br>";  }
      $static_hash->{"$pubip => $privip"} = 1;
   }
   ### else  {   print "<b> Static NAT: none </b> <br>";   }

   return($privip,$pubip);
}

#################################################################################

sub query_ip  {

   my $ip = shift;

   print "<b> query ip: $ip </b> <br> ";

   my $mac;                    
   my $no_current_entries;   ## array ref - tables with no return data
   my $htmlcode;             ## array ref, tells which fields need an html wrap for secondary netpeek call
   my ($priv_ip,$pub_ip);

   ## Domain name
   my $dname = query_domain_name($ip) || "not registered in dns";
   print "<b> hostname: $dname </b> <br>";

   ## StaticNAT
   ($priv_ip,$pub_ip) = query_staticnat($ip);   ## routine also prints StaticNAT info

   ## NETWORK.FIXIE
   my $select_h = $dbh->prepare("SELECT mac FROM network.fixies WHERE ip = \"$ip\" OR ip = \"$priv_ip\"; ");
   $select_h->execute();
   my $fsel_ary = $select_h->fetchall_arrayref;
   if (@$fsel_ary) {
      my $fixmac = $fsel_ary->[0]->[0];
      my $dhcp_mac = dhcp_mac($fixmac);
      if ($dhcp_mac =~ /^[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}$/)  {
         print "<b> ip $ip has fixed dhcp lease mac = ", $dhcp_mac,  "</b> <br>";
      }
      else  {  print "<b> Fixed lease: none </b> <br>";  }
   }

   ## DHCP
   my $query = "SELECT mac,tstamp FROM network.last_dhcp WHERE ip = \"$ip\" ORDER BY tstamp desc LIMIT 1;";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      my $mac    = $sel_ary->[0]->[0];
      my $tstamp = $sel_ary->[0]->[1];
      print "<b> Last dhcp lease for $ip => $mac $s4 ", dhcp_mac($mac), "$s4 at $tstamp </b> <br>"; 
      my $mfquery = "SELECT DISTINCT(mac) from network.macfilters where mac = \"$mac\" ";
      my $mf_h  = $dbh->prepare($mfquery);
      $mf_h->execute();
      if ($mf_h->rows != 0) {
         my $href = "<a href=\"https://$webcgi/macfilter.cgi?submit=Submit&oper=query_addr&addr=$mac\"  $blank > ";
         print "<b><font color=red> $mac is filtered: </font> macfilter link: $href $mac </b> </a> <br> ";
      }
   }
   print "<br>";

   my $query = "SELECT DISTINCT(mac) from network.macfilters where mac = \"$mac\" ";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $href = "<a href=\"https://$webcgi/macfilter.cgi?submit=Submit&oper=query_addr&addr=$mac\"  $blank > ";
      print "<b><font color=red> $mac is filtered: </font> macfilter link: $href $mac </b> </a> <br> ";
   }

   ### ASA.XLATE 
   print "<table>";
   ## @$htmlcode = qw ( 0 0 ip ip context 0 );   
   @$htmlcode = qw ( 0 0 ip ip 0 0 );   
   my $query = "SELECT * from fw.xlate WHERE pub_ip=\"$ip\" OR priv_ip=\"$ip\" ORDER by recent desc LIMIT $lim";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      $priv_ip = $sel_ary->[0]->[2];                                                      
      $pub_ip  = $sel_ary->[0]->[3];                                                       
      print "<tr><td> <b> NAT data from fw.xlate </b> </td></tr>";
      my $header;
      @$header = qw( birth recent priv_ip  pub_ip context active );
      print_header($header);
      print_lines($sel_ary,$htmlcode);
   }
   else  {  push @$no_current_entries, "fw.xlate";  }

   ### ASA.ARP
   my $asa_mac;  ## save for switch search
   @$htmlcode = qw ( 0 0 ip mac 0 0 0 );
   my $query;
   if ($priv_ip ne "")  {  $query = "SELECT * from fw.arp WHERE arpip=\"$priv_ip\" ORDER by recent desc LIMIT $lim";   }
   else                 {  $query = "SELECT * from fw.arp WHERE arpip=\"$ip\"      ORDER by recent desc LIMIT $lim";   }
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary  = $select_h->fetchall_arrayref;
      ### $asa_mac = $sel_ary->[0]->[3];
      $mac = $sel_ary->[0]->[3];
      print "<tr><td> <b> ARP data from fw.arp </b> </td></tr>";
      my $header;
      @$header = qw( birth recent arpip mac vlan context active );
      print_header($header);
      print_lines($sel_ary,$htmlcode);
   }

   ### RTR.ARP 
   #my $rtr_mac;   ## save for switch search
   @$htmlcode = qw ( 0 0 mac ip rtr vlan );
   if ($priv_ip ne "")  {  $query = "SELECT * from rtr.arp WHERE ip=\"$priv_ip\" ORDER by recent desc LIMIT $lim";  }
   else                 {  $query = "SELECT * from rtr.arp WHERE ip=\"$ip\" ORDER by recent desc LIMIT $lim";       }
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      #$rtr_mac = $sel_ary->[0]->[2];
      $mac = $sel_ary->[0]->[2];
      print "<tr><td> <b> ARP data from rtr.arp </b> </td></tr>";
      my $header;
      @$header = qw( arp_birth arp_recent mac ip rtr vlan );
      print_header($header);
      print_lines($sel_ary,$htmlcode);
   }
   else  {  push @$no_current_entries, "rtr.arp";  }

   ### ROUTER.ARP 
   ##  birth  recent  mac  ip  router  vlan  active 
   my $router_mac;   ## save for switch search
   @$htmlcode = qw ( 0 0 mac ip 0 0 );
   $select_h = $dbh->prepare("SELECT birth,recent,mac,ip,vlan,router,active FROM router.arp WHERE ip=\"$ip\" order by recent desc limit $lim;");
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      ##$router_mac = $sel_ary->[0]->[1];
      $mac = $sel_ary->[0]->[2];
      print "<tr><td> <b> ARP data from router.arp </b> </td></tr>";
      my $header;
      @$header = qw( birth recent mac ip vlan router active );
      print_header($header);
      print_lines($sel_ary,$htmlcode);
   }
   else  {  push @$no_current_entries, "router.arp";  }

   ### ARP.REAPIP
   #my $reapip_mac;    ## for switch search below
   my $reapIP_line;  ## for print at end of query_ip
   my $by;   ## ip actually used in the search
   if ($priv_ip ne "")  { $by = "<b> $priv_ip: </b> &nbsp";
                          $query = "SELECT * FROM arp.reapIP WHERE ip = \"$priv_ip\" ORDER by recent desc";    }
   else                 { $query = "SELECT * FROM arp.reapIP WHERE ip = \"$ip\" ORDER by recent desc";           }
   $select_h = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      my (undef,$mac,$recent,$router,$vlan) = @{$sel_ary->[0]};
      ## prep reapIP statement
      my $href = "<a href=\"https://$webcgi/netpeek/$script?submit=Submit&oper=query_mac&fakenetid=$fakenetid&mac=$mac\" $blank > ";
      $reapIP_line = "<b>$ip</b> last seen in an arp table via <b> $href $mac </a> </b> $s4 $s4 <b>$recent</b>
                      $s4 on Router <b>$router</b> $s4 Vlan <b>$vlan</b> <br>";
   }
   else  {  push @$no_current_entries, "arp.reapIP";  }

   ### SWITCH.MAC   new database and table 2020-06-04
   @$htmlcode = qw ( 0 0 mac 0 0 0 swname 0 0 );
   my $fields = "birth,recent,mac,vlan,port,swip,swname,type,active"; 
   my $headprint;
   if ($mac ne "")  {
      my $query = "SELECT $fields from switch.mac WHERE mac=\"$mac\"  ORDER by recent desc LIMIT 11";
      $select_h = $dbh->prepare($query);  
      $select_h->execute();
      if ($select_h->rows != 0) {
         $headprint = 1;
         my $sel_ary = $select_h->fetchall_arrayref;
         print "<tr><td> <b> Port data from switch.mac </b> </td></tr>";
         my $header;
         @$header = qw( birth recent mac vlan port swip swname type active );
         print_header($header);
         print_lines($sel_ary,$htmlcode);
      }
   }
   else  {  push @$no_current_entries, "switch.mac";  }
  
   print "</table>";  ## treating almost whole routine as one table to have nice columns

   print "<br>";
   if ($reapIP_line)  {  print "$reapIP_line ";  }

   print "No current data in: ";
   foreach my $nc (@$no_current_entries)  {  print "<b>$nc, </b>";  }
   print "<hr>";

   #my $dhcp_mac;
   #if ($mac ne "")       { $dhcp_mac = dhcp_mac($mac);    print "asa dhcp_mac: >$dhcp_mac< <br>"; }
   #elsif ($rtr_mac ne "")    { $dhcp_mac = dhcp_mac($rtr_mac);    print "rtr dhcp_mac: >$dhcp_mac< <br>"; }
   #elsif ($router_mac ne "") { $dhcp_mac = dhcp_mac($router_mac); print "router dhcp_mac: >$dhcp_mac< <br>"; }
   #elsif ($reapip_mac ne "") { $dhcp_mac = dhcp_mac($reapip_mac); print "reapip dhcp_mac: >$dhcp_mac< <br>"; }


}  ## query_ip

#################################################################################

sub query_mac  {

   my $mac = shift;

   my $vendor;   ## mac vendor info
   my $oui = $mac;
   $oui =~ s/\.//g;
   $oui = substr($oui,0,6);
   #print "OUI: $oui<b>";
   my $query = "SELECT * from network.macvendor where oui = \"$oui\"; ";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      $vendor = $sel_ary->[0]->[1];
   }
   else  {  $vendor = "unknown";  }

   print "<b> query mac: $mac $s4 ", dhcp_mac($mac), " $s4 vendor: $vendor </b> <br> ";

   my $no_current_entries;   ## array ref - tables with no return data
   my $htmlcode;             ## array ref, tells which fields need an html wrap for secondary netpeek call
   my ($priv_ip,$pub_ip);

   my $ip;                                    
   # FIXIE on mac address
   $select_h = $dbh->prepare("SELECT ip FROM network.fixies WHERE mac = \"$mac\"; ");
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $fsel_ary = $select_h->fetchall_arrayref;
      $ip = $fsel_ary->[0]->[0];
      my $dhcp_mac4ip = dhcp_mac($mac);
      if ($dhcp_mac4ip =~ /^[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}\:[0-9a-f]{2}$/)  {
         print "<b> mac $dhcp_mac4ip has fixed dhcp lease ip = ", $ip,  "</b> <br>";
      }
      else  {  print "<b> Fixed lease: none </b> <br>";  }
   }

   ## StaticNAT
   ($priv_ip,$pub_ip) = query_staticnat($ip);   ## routine also prints StaticNAT info

   ## DHCP
   my $query = "SELECT ip,tstamp FROM network.last_dhcp WHERE mac = \"$mac\" ORDER BY tstamp desc LIMIT 1;";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   my $dhcpip;
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      $dhcpip     = $sel_ary->[0]->[0];
      my $tstamp  = $sel_ary->[0]->[1];
      print "<b> Last dhcp lease for $mac => $dhcpip at $tstamp </b> <br>";
   }

   my $query = "SELECT DISTINCT(mac) from network.macfilters where mac = \"$mac\" ";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $href = "<a href=\"https://$webcgi/macfilter.cgi?submit=Submit&oper=query_addr&addr=$mac\"  $blank > ";
      print "<b><font color=red> $mac is filtered: </font> macfilter link: $href $mac </b> </a> <br> ";   
   }

   my $query = "SELECT * from network.swmacfilters where mac = \"$mac\" ";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      my $swname  = $sel_ary->[0]->[1];
      my $vlan    = $sel_ary->[0]->[2];
      my $href = "<a href=\"https://$webcgi/swmacfilter.cgi?submit=Submit&oper=query_mac&addr=$mac\"  $blank > ";
      print "<b><font color=red> $mac is swmacfiltered: </font> swmacmacfilter link: $href $mac </b> </a> <br> ";
   }
   print "<br>";

   print "<table>";  ## single table to align routine table info

   ## DO ASA.ARP-ONLY stuff
   my $asa_arp_ret;
   @$htmlcode = qw ( 0 0 ip mac 0 0 0 );
   my $query = "SELECT * from fw.arp WHERE mac = \"$mac\" ORDER by recent desc LIMIT $lim";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      ## my $sel_ary = $select_h->fetchall_arrayref;
      my $asa_arp_ret = $select_h->fetchall_arrayref;
      print "<b> ARP data from fw.arp </b> <br>";
      my $header;
      @$header = qw( birth recent arpip mac vlan context active );
      print_header($header);
      print_lines($asa_arp_ret,$htmlcode);
   }

   ## RTR.ARP 
   @$htmlcode = qw ( 0 0 mac ip rtr vlan );
   ##$query = "SELECT birth,recent,mac,ip,rtr,vlan from rtr.arp WHERE mac = \"$mac\" ORDER by recent desc LIMIT $lim;" ; #sql end
   $query = "SELECT * from rtr.arp WHERE mac = \"$mac\" ORDER by recent desc LIMIT $lim;" ; #sql end
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      print "<tr><td> <b> ARP data from rtr.arp </b> </td></tr>";
      my $sel_ary = $select_h->fetchall_arrayref;
      my $header;
      @$header = qw( arp_birth arp_recent mac ip rtr vlan active );
      print_header($header);
      print_lines($sel_ary,$htmlcode);
   }
   else  {  push @$no_current_entries, "rtr.arp";  }

   ## ROUTER.ARP                
   @$htmlcode = qw ( 0 0 mac ip 0 0 0);
   $select_h = $dbh->prepare("SELECT birth,recent,mac,ip,vlan,router,active FROM router.arp WHERE mac=\"$mac\" order by recent desc limit $lim;");
   $select_h->execute();
   my $sel_ary = $select_h->fetchall_arrayref;
   if ($select_h->rows != 0) {
      print "<tr><td> <b> ARP data from router.arp </b> </td></tr>";
      my $header;
      @$header = qw( birth recent mac ip vlan router active );
      print_header($header);
      print_lines($sel_ary,$htmlcode);
   }
   else  {  push @$no_current_entries, "router.arp";  }

   ## ARP.REAPMAC
   my $reapmac_line;  
   my $select_h = $dbh->prepare("SELECT * FROM arp.reapmac WHERE mac = \"$mac\";");
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      my ($reapmac,$recent,$port,$swname,$vlan) = @{$sel_ary->[0]};
      ##my $href = "<a href=\"https://$webcgi/netpeek/$script?submit=Submit&oper=query_ip&fakenetid=$fakenetid&mac=$reapmac\" $blank > ";
      $reapmac_line = "<b>arp.reapmac: $reapmac</b></a> $s4 last seen on switch <b> $swname $s4  port $port $s4 vlan $vlan $s4 $recent</b>";
   }
   else  {  push @$no_current_entries, "arp.reapmac";  }
   
   ## ARP.REAPIP - most recent ip for this mac 
   my $reapIP_line;  ## for print at end of query_mac
   my $select_h = $dbh->prepare("SELECT * FROM arp.reapIP WHERE mac = \"$mac\" order by recent desc;");
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      my ($reapip,$mac,$recent,$router,$vlan) = @{$sel_ary->[0]};
      ## prep reapIP statement
      my $href = "<a href=\"https://$webcgi/netpeek/$script?submit=Submit&oper=query_ip&fakenetid=$fakenetid&ip=$reapip\" $blank > ";
      $reapIP_line = "<b>arp.reapIP: $mac</b> last seen in an arp table via <b> $href $reapip </a>:$s4  
                      $s4 router/context <b>$router</b> $s4 vlan <b>$vlan</b> <b>$recent</b>";
   }
   else  {  push @$no_current_entries, "arp.reapIP";  }

   ### ASA.XLATE - check last dhcpip
   ## @$htmlcode = qw ( 0 0 ip ip context 0 );
   @$htmlcode = qw ( 0 0 ip ip 0 0 );
   my $query = "SELECT * from fw.xlate WHERE pub_ip=\"$dhcpip\" OR priv_ip=\"$dhcpip\" ORDER by recent desc LIMIT $lim";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      $priv_ip = $sel_ary->[0]->[2];
      $pub_ip  = $sel_ary->[0]->[3];
      print "<tr><td> <b> NAT data from fw.xlate </b> </td></tr>";
      my $header;
      @$header = qw( birth recent priv_ip  pub_ip context active );
      print_header($header);
      print_lines($sel_ary,$htmlcode);
   }
   else  {  push @$no_current_entries, "fw.xlate";  }

   ### SWITCH.MAC   new database and table 2020-06-04
   @$htmlcode = qw ( 0 0 mac 0 0 0 swname 0 0 );
   my $fields = "birth,recent,mac,vlan,port,swip,swname,type,active";
   my $headprint;
   if ($mac ne "")  {
      my $query = "SELECT $fields from switch.mac WHERE mac=\"$mac\"  ORDER by recent desc LIMIT 11";
      $select_h = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0) {
         $headprint = 1;
         my $sel_ary = $select_h->fetchall_arrayref;
         print "<tr><td> <b> Port data from switch.mac </b> </td></tr>";
         my $header;
         @$header = qw( birth recent mac vlan port swip swname type active );
         print_header($header);
         print_lines($sel_ary,$htmlcode);
      }
      else  {  push @$no_current_entries, "switch.mac";  }
   }

   print "</table>";  ## treating almost whole routine as one table to have nice columns

   print "<br>";
   if ($reapmac_line)  {  print "$reapmac_line <br>";  }
   if ($reapIP_line)  {  print "$reapIP_line <br>";  }
   print "<br>";
   print "No current data in: ";
   foreach my $nc (@$no_current_entries)  {  print "<b>$nc, </b>";  }
   print "<hr>";


}  ## query_mac

#################################################################################

sub query_vlan  {

   my $vlan = shift;
   #print "{query_vlan}: $vlan<br>\n";

   print "<a href=\"#SWPORTS\"> <b> Switches with ports on $vlan </b></a> <br>\n";
   print "<a href=\"#FIXIES\">  <b> DHCP Fixied Leases on $vlan </b></a> <br>\n";
   print "<a href=\"#STATICS\"> <b> Static NAT mappings $vlan </b></a> <br>\n";
   print "<a href=\"#FILTERS\"> <b> Current macfilters $vlan </b></a> <br>\n";
   print "<a href=\"#LASTDHCP\"><b> Last DHCP lease info $vlan </b></a> <br>\n";
   print "<br>";

   #### my $find_ref = "<a href=\"https://$webcgi/find_dhcp.cgi?submit=Submit&sub_pre==$swname\" $blank > $swname </a> ";

   my $subprefixes;  ## array subnet prefixes
   ## get subnets on vlan
   print "<b> Subnets on $vlan </b> <br>\n";
   my $headline = "<b> Subnets on vlan $vlan </b>";
   foreach my $v ( @{$vlan2subs->{$vlan}} )  {
      my ($nums,$mask) = split /\//, $v;
      ## get the fwcontext info
      my $select_h  = $dbh->prepare('SELECT * from network.ipvlanmap where ip like ? ');
      $select_h->execute($nums);
      if ($select_h->rows == 0) { 
         print " * $v  (no context info found) <br>";  
      }
      else  {
         my $sel_ary = $select_h->fetchall_arrayref;
         my $context = $sel_ary->[0]->[2];
         print " * $v * $context <br>\n";
      }
      ### work out the non-/24 mask issue here:        
      my $maskfac = 24 - $mask;
      for (my $i=0; $i<2**$maskfac; $i++)  {
         my ($a,$b,$c) = split /\./, $nums;
         my $bump = $c+$i;
         my $pre = "$a\.$b\.$bump";
         ## print "$pre<br>";
         push @$subprefixes, $pre;
      }
   }

   print "<br> <b> DHCP/NAT info by /24 slice (fixed leases and pool ranges, includes static NATS): </b> <br>";
   print "<table>";
   foreach my $pre (@$subprefixes)  {
      my $find_ref = "<a href=\"https://$webcgi/find_dhcp.cgi?submit=Submit&sub_pre=$pre\"
                         $blank > $pre DHCP info </a> ";
      print "<td> $find_ref </td></tr> \n";
   }
   print "</table>";


   ## get switches on vlan
   my $svlan = $vlan;
   $svlan =~ s/Vlan//i;
   my $query = "SELECT distinct swname,swip FROM switch.vlan  WHERE vlan = \"$svlan\";";
   my $select_h  = $dbh->prepare($query);                                            
   $select_h->execute();
   if ($select_h->rows != 0) {
      ##print "<br> <a name=\"SWPORTS\"> <br> <b> Switches with ports on $vlan </b></a> <br>\n";
      print "<br> <a id=\"SWPORTS\"> <br> <b> Switches with ports on $vlan </b></a> <br>\n";
      if (exists $network_staff{$netid})  { print "(select switchname for switchmeister)"; }
      if (exists $noc_staff{$netid})      { print "(select switchname for switchmeister)"; }
      print ": <br>\n";
      print "<table border=5>";
      my $sel_ary = $select_h->fetchall_arrayref;
      foreach my $row (@$sel_ary)  {
         my ($swname,$swip) = @$row;                 
         my $href = "<a href=\"https://$webcgi/sw/sw.cgi?submit=Submit&oper=swlist&swnames=$swname\" $blank > $swname </a> ";
         if    (exists $network_staff{$netid})  { print "<tr><td> $href </td> <td>$swip</td>"; }
         elsif (exists $noc_staff{$netid})      { print "<tr><td> $href </td> <td>$swip</td>"; }
         else  { print "<tr><td> $swname </td> <td>$swip</td>"; }

      }  
      print "</table>";
   }
   else  {  print "No current entries found in switch.vlan for switches on vlan $vlan <br>\n"; }


   ## FIXIES:
   my $ipfixies;   ## hash ref
   my $query = "SELECT * FROM network.fixies; ";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      foreach my $row (@$sel_ary)  {
         my ($mac,$ip)      = @$row;                 
         $ipfixies->{$ip}   = $mac;
      }
   }
   print "<br> <a name=\"FIXIES\"> <br> <b> DHCP Fixed Leases on vlan $vlan: </b></a> <br><br>\n";
   print "<table border=5>";
   my $sp3 = "&nbsp;&nbsp;&nbsp;";
   foreach my $pre (@$subprefixes)  {
      for (my $i=0; $i<256; $i++)  {
         my $ip = "$pre.$i";
         if (exists $ipfixies->{$ip})  {
            my $mac = $ipfixies->{$ip};
            print "<tr> <td> <a href=\"https://$webcgi/netpeek/$script?submit=Submit&oper=query_ip&ip=$ip\" $blank > $ip $sp3 </a> </td>
                   <td> <a href=\"https://$webcgi/netpeek/$script?submit=Submit&oper=query_mac&mac=$mac\" $blank >  $mac $sp3 </a> </td>  </tr>\n";
         }
      }
   }
   print "</table>";

   ## StaticNAT mappings:
   my $vlannum = $vlan;
   $vlannum =~ s/vlan//i;
   my $query = "SELECT privip,pubip FROM network.staticmap WHERE vlan = \"$vlannum\"; ";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      print "<br> <a name=\"STATICS\"> <br> <b> Vlan $vlannum StaticNAT mappings: </b></a> <br><br>\n";
      my $temp;                           ## array ref
      print "<table border=5>";
      my $sel_ary = $select_h->fetchall_arrayref;
      foreach my $row (@$sel_ary)  {
         my ($privip,$pubip) = @$row;
         push @$temp, "$privip $pubip";    ## flipping them around 
      }
      $temp = sort_by_ip($temp);    
      foreach my $str (@$temp)  {
         my ($privip,$pubip) = split " ", $str;
         print "<tr> <td> <a href=\"https://$webcgi/netpeek/$script?submit=Submit&oper=query_ip&ip=$privip\" $blank > $privip $sp3 </a> </td>
                <td> <a href=\"https://$webcgi/netpeek/$script?submit=Submit&oper=query_ip&ip=$pubip\" $blank > $pubip $sp3 </a> </td>  </tr>\n";

      }
      print "</table>";
   }

   ## MACFILTERS
   my $query = "SELECT mac FROM network.macfilters WHERE vlan = \"$vlannum\"; ";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      print "<br> <a name=\"FILTERS\"> <br> <b> Current macfilters on Vlan $vlannum: </b></a> <br><br>\n";
      my $temp;                           ## array ref
      my $sel_ary = $select_h->fetchall_arrayref;
      foreach my $row (@$sel_ary)  {
         my $mac = $row->[0];
         push @$temp, $mac;   
      } 
      @$temp = sort(@$temp);
      foreach my $mac (@$temp)  {
         print "<a href=\"https://$webcgi/netpeek/$script?submit=Submit&oper=query_mac&mac=$mac\" $blank > $mac </a> <br>";
      }
      #print "<br>";
   }

   ## DHCP last lease
   my $temp;   ## array ref of last_dhcp records - we have straight access to vlan# via the form of the gateway data
   ## Check for gateway-1 dhcp records (these have a different "gateway" field format that includes the vlan#)
   my $query = "SELECT mac,ip,tstamp FROM network.last_dhcp WHERE gateway like \"eth1.$vlan\" ";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      foreach my $row (@$sel_ary)  {
         my ($mac,$ip,$tstamp) = @$row;
         push @$temp, "$ip $mac $tstamp";
      }
      $temp = sort_by_ip($temp);
   }
   ## Check for dhcp records (shows up as [webalias|webalias1|webalias-1] in some code/comments)
   my $subhash;    ## catches multi subnets in a vlan
   $query = "SELECT subnet from network.vlanmap where vlan = \"$vlannum\"; ";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      foreach my $row (@$sel_ary)  {
         my $subnet = $row->[0];
         $subhash->{$subnet} = 1;
      }
      foreach my $sb (keys %$subhash)  {
         my ($gateway,undef) = split "/", $sb;
         my $query = "SELECT mac,ip,tstamp FROM network.last_dhcp WHERE gateway = \"$gateway\";";
         my $select_h  = $dbh->prepare($query);
         $select_h->execute();
         if ($select_h->rows != 0) {
            my $sel_ary = $select_h->fetchall_arrayref;
            foreach my $row (@$sel_ary)  {
               my ($mac,$ip,$tstamp) = @$row;
               push @$temp, "$ip $mac $tstamp";
            }
         }
      }
   }
   ## print dhcp_lastlease
   print "<br> <a name=\"LASTDHCP\"> <br> <b> DHCP last lease info for vlan $vlannum: </b></a> <br><br>\n";
   print "<table border=5>";
   foreach my $t (@$temp)  {
      my ($ip,$mac,$tstamp) = split " ", $t;
      print "<tr><td> <a href=\"https://$webcgi/netpeek/$script?submit=Submit&oper=query_ip&ip=$ip\" $blank > $ip $sp3 </a></td>\n";
      print "    <td> <a href=\"https://$webcgi/netpeek/$script?submit=Submit&oper=query_mac&mac=$mac\" $blank > $mac $sp3 </a></td>\n";
      print "    <td>$tstamp $sp3</td> </tr>\n";
   }
   print "</table>";
   print "<br>";

   return;

}  ## query_vlan

######################################################################

sub query_vlan_ips  {    # DONE

   my $vlan       = shift;

   my $ipmach;    ## hashref key = "ip mac"  and  value = array of related ip and switch field data
   my $htmlcode;  ## array ref, tells which fields need an html wrap for secondary netpeek call
   my $query;

   print "<b>Entries for vlan $vlan. <br></b>\n";
   print "Date threshold <b> $datethresh </b> enabled for display data. <br>\n"; 
   if ($ipprefixes) {
      print "IP prefixes included in display data: \n";
      foreach my $ipp (@$ipprefixes)  { print "&nbsp;&nbsp;&nbsp; <b> $ipp </b> "; }
   }
   print "<b> Associated macs listed in <font color=red> red </font> are <font color=red> filtered </font> </b><br>\n";
   $query = "SELECT ip,mac,recent,router from arp.reapIP WHERE vlan=\"$vlan\" AND recent >= \"$datethresh\" ; "; 
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   print "<b>IP entries found: ", $select_h->rows, "</b><br>";
   my $reaprows;    ## ref of array of sel_ary for later
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      foreach my $row (@$sel_ary)  { 
         my($ip,$mac,$recent,$router) = @$row;   
         push @$reaprows, "$ip $mac $recent";
         if ($router =~ /\./)  {  (undef,$router) = split /\./, $router;  }
         # check for fixie based on mac address
         my $fixip;   ## ip from fixed dhcp lease
         my $select_h = $dbh->prepare("SELECT ip FROM network.fixies WHERE mac = \"$mac\"; ");
         $select_h->execute();
         if ($select_h->rows != 0) {
            my $fsel_ary = $select_h->fetchall_arrayref;
            $fixip = $fsel_ary->[0]->[0];
         }
         ## Get DNS info
         my $res   = Net::DNS::Resolver->new( nameservers => [qw(128.248.171.50 128.248.2.50 128.248.7.50)],);
         my $query = $res->search("$ip");
         my $dnsname;
         if ($query) {
             foreach my $rr ($query->answer) {
                 next unless $rr->type eq "PTR";
                 $dnsname = $rr->ptrdname || "<font color=rred> unregistered </font>";
             }
         }
         ## if we're using ipprefixes, check that the ip matches one of the prefixes listed
         if (@$ipprefixes) {
            foreach my $ipp (@$ipprefixes)  {
               if ($ip =~ /$ipp/)  {
                  push @{$ipmach->{"$ip $mac"}}, $ip;
                  push @{$ipmach->{"$ip $mac"}}, $dnsname || "<font color=red>unregistered</font>";
                  push @{$ipmach->{"$ip $mac"}}, $mac;
                  push @{$ipmach->{"$ip $mac"}}, $vlan;
                  push @{$ipmach->{"$ip $mac"}}, $router;
                  push @{$ipmach->{"$ip $mac"}}, $recent;
                  push @{$ipmach->{"$ip $mac"}}, $fixip || "-";
               }
            }
         }
         else  {
            push @{$ipmach->{"$ip $mac"}}, $ip;
            push @{$ipmach->{"$ip $mac"}}, $dnsname  || "<font color=red>unregistered</font>";
            push @{$ipmach->{"$ip $mac"}}, $mac;
            push @{$ipmach->{"$ip $mac"}}, $vlan;
            push @{$ipmach->{"$ip $mac"}}, $router;
            push @{$ipmach->{"$ip $mac"}}, $recent;
            push @{$ipmach->{"$ip $mac"}}, $fixip || "-";
         }
      }  ## foreach
   }  ## if

   ## get switch info
   foreach my $ip_mac (keys %$ipmach)  {
      my ($ip,$mac) = split " ", $ip_mac;
      $query = "SELECT port,swip,swname,recent FROM switch.mac WHERE mac=\"$mac\" and port not like \"Po%\" ORDER by recent desc LIMIT 1;";  
      my $select_h  = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0) {
         my @row = $select_h->fetchrow_array;
         my ($port,$swip,$swname,$recent) = @row;  
         push @{$ipmach->{"$ip $mac"}}, $port;
         push @{$ipmach->{"$ip $mac"}}, $swip;
         push @{$ipmach->{"$ip $mac"}}, $swname;
         push @{$ipmach->{"$ip $mac"}}, $recent;
      }  
   }    
   ## prepare @$lines_array for printing in ip order 
   my $lines_array;
   my $sorted_ips;
   foreach my $ip_mac ( keys %$ipmach)  {  push @$sorted_ips, $ip_mac;  }
   $sorted_ips = sort_by_ip($sorted_ips);
   foreach my $si (@$sorted_ips)  {    push @$lines_array,$ipmach->{$si};  } 

   my $header;
   @$htmlcode = qw ( ip 0 mac 0 0 0 ip 0 0 swname 0 );
   @$header = qw (ip hostname mac last_vlan rtr/fw arp_date fixed_IP port swip swname sw_recent); 
   print "<table>";
   print_header($header);
   print_lines($lines_array,$htmlcode);
   print "</table>";

   print "<br> <b> Simple ip based list </b> <br><br>";
   my $sp3 = "&nbsp;&nbsp;&nbsp;";
   $reaprows = sort_by_ip($reaprows);
   foreach my $str (@$reaprows)  {
      my($ip,$mac,$recent) = split " ", $str;
      print "$ip";
      for (my $i = length($ip); $i < 17; $i++)   {  print "&nbsp";  }
      print "$mac $sp3 $recent <br>";
   }


}  ## query_vlan_ips

#################################################################################

sub query_vlan_macs  {     ## DONE

   my $vlan       = shift;

   my $mach;      ## hashref key = "mac ip"  and  value = array of related ip and switch field data
   my $htmlcode;  ## array ref, tells which fields need an html wrap for secondary netpeek call
   my $query;

   print "<b>Entries for vlan $vlan. <br></b>\n";
   print "Date threshold <b> $datethresh </b> enabled for display data. <br>\n"; 
   if ($ipprefixes) {
      print "IP prefixes included in display data: <br>\n";
      foreach my $ipp (@$ipprefixes)  { print "&nbsp;&nbsp;&nbsp; <b> $ipp </b> <br>\n"; }
   }
   print "<b> macs listed in <font color=red> red </font> are <font color=red> filtered </font> </b><br>\n";

   $query = "SELECT ip,mac,recent from arp.reapIP WHERE vlan=\"$vlan\" AND recent >= \"$datethresh\" ; "; 
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   print "<b>Mac entries found: ", $select_h->rows, "</b><br>";
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      foreach my $row (@$sel_ary)  {
         my($ip,$mac,$recent) = @$row;   ##  split " ", $ln;
         # check for fixie based on mac address
         my $fixip;   ## ip from fixed dhcp lease
         my $select_h = $dbh->prepare("SELECT ip FROM network.fixies WHERE mac = \"$mac\"; ");
         $select_h->execute();
         if ($select_h->rows != 0) {
            my $fsel_ary = $select_h->fetchall_arrayref;
            $fixip = $fsel_ary->[0]->[0];
         }
         ## DHCP info
         my $last_dhcp;
         $query = "SELECT ip,tstamp FROM network.last_dhcp WHERE mac = \"$mac\" ORDER by tstamp desc LIMIT 1";
         my $select_h  = $dbh->prepare($query);
         $select_h->execute();
         if ($select_h->rows != 0) {
            my @row = $select_h->fetchrow_array;
            my ($ip,$tstamp) = @row;
            $last_dhcp = "$ip $tstamp";
         }
         else  {  $last_dhcp = "<font color=green> NO_DHCP lease <font>";  }

         ## if we're using ipprefixes, check that the ip matches one of the prefixes listed
         if (@$ipprefixes) {
            foreach my $ipp (@$ipprefixes)  {
               if ($ip =~ /$ipp/)  {
                  push @{$mach->{"$mac $ip"}}, $mac;
                  push @{$mach->{"$mac $ip"}}, $last_dhcp;
                  push @{$mach->{"$mac $ip"}}, $recent;
                  push @{$mach->{"$mac $ip"}}, $ip;
                  push @{$mach->{"$mac $ip"}}, $fixip || "-";
               }
            }
         }
         else  {
            push @{$mach->{"$mac $ip"}}, $mac;
            push @{$mach->{"$mac $ip"}}, $last_dhcp;
            push @{$mach->{"$mac $ip"}}, $recent;
            push @{$mach->{"$mac $ip"}}, $ip;
            push @{$mach->{"$mac $ip"}}, $fixip || "-";
         }
      }  ## foreach
   }  ## if
   ## get switch info
   foreach my $mac_ip (keys %$mach)  {
      my ($mac,$ip) = split " ", $mac_ip;
      $query = "SELECT port,swip,swname,recent FROM switch.mac WHERE mac=\"$mac\" and port not like \"Po%\" ORDER by recent desc LIMIT 1;";
      my $select_h  = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0) {
         my @row = $select_h->fetchrow_array;
         my ($port,$swip,$swname,$recent) = @row;  
         push @{$mach->{"$mac $ip"}}, $port;
         push @{$mach->{"$mac $ip"}}, $swip;
         push @{$mach->{"$mac $ip"}}, $swname;
         push @{$mach->{"$mac $ip"}}, $recent;
      }  
   }    

   my $lines_array;
   foreach my $mac_ip (sort keys %$mach)  {  push @$lines_array,$mach->{$mac_ip};  }

   my $header;
   @$htmlcode = qw ( mac 0 0 ip ip 0 0 swname 0 );
   @$header = qw (mac last_dhcp last_arp arp_ip fixed_IP port swip swname sw_recent); 
   print "<table>";
   print_header($header);
   print_lines($lines_array,$htmlcode);
   print "</table>";

}  ## query_vlan_macs

###################################################

sub unearth_mac_list  {     

   my $maclist = shift;  ## this is a STRING 
   my @macs    = split " ", $maclist;
   my $mac_list_hash;

   if ($datethresh)  {  print "Date threshold <b> $datethresh </b> enabled for display data. <br>\n";  }
   print "<br>";

   foreach my $m (@macs)  {
      if ($m =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)  { next;  }  ## gotta ditch IPs or the next line will fix 12-digit IPs!! :)
      $m = fix_mac($m);
      if ($m !~ /\A[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\z/)  {  next;  }  ## NOT a mac!
      $mac_list_hash->{$m} = $m;
   }
   my $mac_list_array;

   foreach my $m (keys %$mac_list_hash)  {  push @$mac_list_array, $m;  }
   @$mac_list_array = sort @$mac_list_array;
   my($table,$fields,$query);
   my $mach;   ## hashref
   ##foreach my $m (keys %$mac_list_hash)  {
   foreach my $m (@$mac_list_array)  {
      my $dhcp_mac = dhcp_mac($m); 
      $query = "SELECT ip,mac,recent FROM arp.reapIP WHERE mac = \"$m\" ORDER by recent desc limit 1;"; ## note sql ending
      my $select_h  = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0) {
         my $sel_ary = $select_h->fetchall_arrayref;
         foreach my $row (@$sel_ary)  {
            my ($ip,$mac,$recent) = @$row;      
            $mach->{$m} = " $mac $dhcp_mac $recent $ip ";  
            # check for fixed mac based on ip address for possible mismatch
            my $fixdhcpmac;
            my $dhcp_h = $dbh->prepare("SELECT mac FROM network.fixies WHERE ip = \"$ip\"; ");
            $dhcp_h->execute();
            if ($dhcp_h->rows != 0) {
               my $dhcp_ary = $dhcp_h->fetchall_arrayref;
               $fixdhcpmac = $dhcp_ary->[0]->[0];
               $mach->{$m} .= " $fixdhcpmac ";
            }
            else  {  $mach->{$m} .= " n/a ";  }
         }
      }
      my $reapmac_hash;
      $query  = "SELECT * from arp.reapmac WHERE mac = \"$m\" ;"; ## note sql ending
      my $select_h  = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0) {
         my $sel_ary = $select_h->fetchall_arrayref;
         foreach my $row (@$sel_ary)  {
            #my($mac,$vlan,$port,$swip,$swname,undef,$recent,undef,undef) = @$row;
            my($mac,$recent,$port,$swname,$vlan) = @$row;
            if ($port eq "")  {  $port eq "unknown";  }
            if (defined $reapmac_hash->{$mac})  {  next;  }
            $reapmac_hash->{$mac} = $recent;
            if (!defined $mach->{$m})   {  $mach->{$m} = "$m $dhcp_mac unknown unknown n/a ";  }
            $mach->{$m} .= " $port $swname $vlan $recent ";
         }
      }
      else  {  $mach->{$m} .= " n/a  n/a  n/a  n/a  n/a ";  }
      if ($mach->{$m} eq " n/a  n/a  n/a  n/a  n/a ")  {
         $mach->{$m} = "$m $dhcp_mac unknown unknown n/a  n/a  n/a  n/a  n/a ";
      }
   } 
   print "<b>", scalar(@$mac_list_array), " mac entries found </b> <br>";
   print "<br>";

   my $prt_ary;
   foreach my $mmm (@$mac_list_array)  {  
      my $str = $mach->{$mmm};
      my $temp;
      @$temp = split " ", $str;
      push @$prt_ary, $temp;
   }
   my $htmlcode;
   @$htmlcode = qw  ( mac 0 0 ip 0 0 0 0 0 );
   my $header;
   @$header = qw( mac dhcp_mac last_dhcp ip fixed_mac  port switch_name vlan reapmac_recent );
   print "<table>";
   print_header($header);
   print_lines($prt_ary,$htmlcode);
   print "</table>";  
   print "<br>";

   my $s3 = "&nbsp&nbsp&nbsp";
   print "<table>";
   print "<b>DHCP Use</b><br>";
   print "<tr> <td><b>dhcp_mac</b></td> <td><b>ip</b></td> <td><b>last lease</b></td>  </tr></b>";
   ##  foreach my $m (keys %$mac_list_hash)  {
   foreach my $m (@$mac_list_array)  {
      my $dhcp_mac = dhcp_mac($m); 
      $query  = "SELECT * from network.last_dhcp WHERE mac=\"$m\" ORDER by tstamp desc LIMIT 1" ;
      my $select_h  = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0) {
         my $sel_ary = $select_h->fetchall_arrayref;
         foreach my $row (@$sel_ary)  {
            my ($mac,$ip,undef,$tstamp) = @$row;  
            print "<b><tr> <td>$dhcp_mac $s3</td> <td>$ip $s3</td> <td>$tstamp $s3</td> </tr></b>";
         } 
      }
      else { print "<tr><td><font color=green><b> $dhcp_mac </b></font></td> <td><font color=green><b>NO DHCP lease</b></font></td></tr>"; }
   }
   print "</table>";  

   return;

} ## unearth_mac_list

###################################

sub morph_ip_list  {

   my $ip = shift;         ## this is not a reference, it's a big friggin' string.
                                    
   if ($datethresh)  {  print "Date threshold <b> $datethresh </b> enabled for display data. <br>\n";  }
   if (@$ipprefixes) {
      print "IP prefixes included in display data: \n";
      foreach my $ipp (@$ipprefixes)  {  print "&nbsp;&nbsp;&nbsp; <b> $ipp </b> ";  }
      print "<br><br>";
   }

   my $unique_ip;  ## hash
   my $all_ips;
   @$all_ips = split " ", $ip;

   foreach my $i (@$all_ips)  {
      if (@$ipprefixes)  {
         my $pretest = 0;
         foreach my $pr (@$ipprefixes)  {
            if ($i =~ /$pr/)  {  $pretest = 1;  }
         }
         if ($pretest == 0)  {  next;  }   ## not included in ip prefixes
      }
      ## if you have a host octet wildcard, expand it here
      if ($ip =~ /\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\%/)  {
         my $sub = $ip;
         $sub =~ s/\.\%\z//;
         for (my $j=1; $j<256; $j++)   {
            if ( exists $unique_ip->{"$sub.$j"} )      {  next;  }            
            $unique_ip->{"$sub.$j"} = 1;
         } 
      }
      if ($i !~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)  {  next;  }      ##  remove the garbage text  
      if ( $i =~ /\A255\./ )                           {  next;  }
      if ( exists $unique_ip->{$i} )                   {  next;  }
      $unique_ip->{$i} = 1;
   }
 
   my $ip_hash;   
   my $ip_array;
   my $dhcp_mac;
   foreach my $i (keys %$unique_ip)  {
      my $mac;
      my $dname = dns_lookup($i) || "unregistered";
      my $query  = "SELECT * from arp.reapIP where ip = \"$i\" ORDER by recent desc limit 1; "; 
      my $select_h  = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0) {
         my $sel_ary = $select_h->fetchall_arrayref;
         foreach my $row (@$sel_ary)  {
            my ($ip,$reapmac,$recent,$router,$vlan) = @$row;
            if ($recent ge $datethresh)  {
               $mac = $reapmac;
               $dhcp_mac = dhcp_mac($mac); 
               $ip_hash->{$i} = " $ip $dname $reapmac $dhcp_mac $vlan $router $recent ";
               push @$ip_array, $i;
            } 
         }
      }
      $query  = "SELECT mac from network.fixies WHERE ip = \"$i\" "; 
      my $select_h  = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0) {
         my $sel_ary = $select_h->fetchall_arrayref;
         my $fixmac = $sel_ary->[0]->[0];     
         $ip_hash->{$i} .= " $fixmac ";
      }
      else  {  $ip_hash->{$i} .= " n/a ";  }
      my $swmac_hash;
      ## Attempt to get the real client port, not a Portchannel entry from the same mac:
      ## $query = "SELECT * from switch.mac where mac = \"$mac\"  order by recent desc LIMIT 1;"; ## note sql ending
      $query = "SELECT * FROM switch.mac WHERE mac = \"$mac\" and port not like \"Po%\"  ORDER BY recent desc LIMIT 1;"; ## note sql ending
      my $select_h  = $dbh->prepare($query);
      $select_h->execute();
      if ($select_h->rows != 0) {
         my $sel_ary = $select_h->fetchall_arrayref;
         foreach my $row (@$sel_ary)  {
            my($mac,$vlan,$port,$swip,$swname,undef,$recent,undef,undef) = @$row;
            if (defined $swmac_hash->{$mac})  {  print "defined swmac_hash <br>";   }
            if (defined $swmac_hash->{$mac})  {  next;  }
            $swmac_hash->{$mac} = $recent;
            if (!defined $ip_hash->{$i})  {  $ip_hash->{$i} = "$i unknown unknown ";  }
            $ip_hash->{$i} .= " $port $swip $swname $recent ";
         }
      }
      else  {  $ip_hash->{$i} .= " none none none none ";  }
   }

   $ip_array = sort_by_ip($ip_array);
   print "<b>", scalar(@$ip_array), " ip entries found </b> <br>";
   print "<br>";
   ##foreach my $i (@$ip_array)  {  print "<b>",  $ip_hash->{$i}, "</b> <br>";  }

   my $prt_ary;
   foreach my $mmm (@$ip_array)  {
      my $str = $ip_hash->{$mmm};
      my $temp;
      @$temp = split " ", $str;
      push @$prt_ary, $temp;
   }
   my $htmlcode;
   @$htmlcode = qw ( ip 0 mac 0 0 0 0 mac 0 0 swname 0 );
   my $header;
   @$header = qw( ip hostname mac dhcp_mac vlan context/rtr&nbsp&nbsp last_arp fixed_mac port swip swname recent );
   print "<table>";
   print_header($header);
   print_lines($prt_ary,$htmlcode);
   print "</table>";
   print "<br>";

   print "<b> Simple ip list: </b><br>";
   print "<table>";
   my $s2 = "&nbsp&nbsp";
   foreach my $i (@$ip_array)  {
      my ($ip,$dname,$mac,undef) = split " ", $ip_hash->{$i};
      print "<tr><td> $ip $s2 </td> <td> $dname $s2 </td> <td> $mac $s2 </td></tr>";
   }
   print "</table>";


} ## morph_ip_list

###################################################

sub dns_lookup  {

   my $ip = shift;

   my $res  = Net::DNS::Resolver->new;
   $res->nameservers($dns1,$dns2,$dns3);
   my $query = $res->search("$ip");
   if ($query) {
       foreach my $rr ($query->answer) {
           next unless $rr->type eq "PTR";
           ##print $rr->ptrdname, "\n";
           return($rr->ptrdname);
       }
   }

} ## dns_lookup

########################
sub date_time  {
                                
   ## Returns string with Date and Time as:
   ##  "mm/dd/yy hh/mm/ss"
   my ($sec,$min,$hour,$mday,$mon,$year,undef,undef,undef) = localtime(time);
   $mon += 1;
   # Y2K fix:
   my $yr=1900+$year;
   if ( $mon  < 10 )  { $mon  = "0"."$mon"; }
   if ( $mday < 10 )  { $mday = "0"."$mday"; }
   my $date = "$yr-$mon-$mday";
   if ( $hour < 10 )  { $hour = "0"."$hour"; }
   if ( $min  < 10 )  { $min  = "0"."$min"; }
   if ( $sec  < 10 )  { $sec  = "0"."$sec"; }
   my $time = "$hour:$min:$sec";

   ## for this script, we split 'em!!
   return($date,$time);
}  ## date_time

#################################################################################

sub fix_mac  {

  my $addr = shift;

  $addr = lc($addr);   ## I'm case chauvanistic  ;->
  $addr =~ s/\.//g;
  $addr =~ s/\://g;
  $addr =~ s/\-//g;
  my $aa = substr($addr,0,4);
  my $bb = substr($addr,4,4);
  my $cc = substr($addr,8,4);
  $addr = "$aa.$bb.$cc";
  return($addr);

}  ## fix_mac

###################################

sub dhcp_mac  {

  my $addr = shift;

  $addr = lc($addr);   ## I'm case chauvanistic  ;->
  $addr =~ s/\.//g;
  $addr =~ s/\://g;
  $addr =~ s/\-//g;
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


###########
###########

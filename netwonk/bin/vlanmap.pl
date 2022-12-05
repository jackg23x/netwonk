#!/usr/bin/perl
# jackg@uic.edu

## vlanmap.pl
##
## creates vlanmap table on world.cc
## - goes through all router,asa,rtr configs and processes them
##
## creates network.vlanmap  network.vlansplits 
## creates network.ipvlanmap for PaloAlto firewalls only
## 

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use lib "$installpath/lib";
use IO::File;
use SshPa;
use vars qw($allvlanhash);

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});
my ($insert_h,$update_h,$select_h);

#control variables
my $asa  = 1;
my $fw   = 1;
my $rout = 1;
my $rtr  = 1;
my $db   = 1;
my $prt  = 1;
print "control variables: asa=$asa fw=$fw rout=$rout  rtr=$rtr  db=$db  prt=$prt\n";  

## THIS FILE
my @fn = split /\//, $0;
my $thisfile = @fn[$#fn];
my ($thisfn,undef) = split /\./, $thisfile;

my $tf  = "$installpath/forensic/$thisfn.temp";
my $tfh = IO::File->new(">$tf");
my $of  = "$installpath/forensic/$thisfn.log";
my $ofh = IO::File->new(">$of");

require "$installpath/lib/servers.pl";
# GATEWAY OVERRIDE 
my $gatevlanhash;
my $dhcp1      = dhcp1();
my $dhcp2      = dhcp2(); 
my $gw1cfgpath = dhcpconfpath();
my $dhcpcfgs;
@$dhcpcfgs = `ls $gw1cfgpath`;    ## gateway-1 configs path.  backticks are safe here in this literal.
## check to see if a vlan shows up in the gateway1 dhcp configs - they all start with a {1,4} digit number followed by a dash
foreach my $dc (@$dhcpcfgs)  {
   chomp $dc;
   if ($dc !~ /\A\d{1,4}\-/)  {  next;  }
   my ($vlan,$rest) = split "-", $dc;
   $gatevlanhash->{$vlan} = 1;
   #print "gateway $vlan\n";
}

my $routercfgdir = "$installpath/configs/routers";
my $asacfgdir = "$installpath/configs/asa";
my $fwcfgdir = "$installpath/configs/firewalls";
my $rtrcfgdir = "$installpath/configs/rtr";
my $helperhash;
my $vlanmaphash;
my $vlansplitshash;

my $ipvlanmap;    ## for Palo Alto only - done in *configproc for Cisco boxen
if ($fw)  {
   opendir(DIR, $fwcfgdir) || die "can't opendir $fwcfgdir: $!";
   my @cfgs = grep { /\.cfg\z/  } readdir(DIR);
   closedir DIR;
   foreach my $cfg (@cfgs)  {             
      fw_process($cfg,"firewall");
   }
}
if ($rout) {
   opendir(DIR, $routercfgdir) || die "can't opendir $routercfgdir: $!";
   my @cfgs = grep { /\.cfg\z/  } readdir(DIR);
   closedir DIR;
   foreach my $cfg (@cfgs)  {             
      router_process($cfg,"router");
   }
}
if ($asa) {
   opendir(DIR, $asacfgdir) || die "can't opendir $asacfgdir: $!";
   my @cfgs = grep { /\.cfg\z/  } readdir(DIR);
   closedir DIR;
   foreach my $cfg (@cfgs)  {
      if ($cfg =~ /\.system\.cfg\z/)  {  next;  } 
      if ($cfg =~ /\.temp\.cfg\z/)  {  next;  }
      asa_process($cfg,"asa");
   }
}
if ($rtr) {
   opendir(DIR, $rtrcfgdir) || die "can't opendir $rtrcfgdir: $!";
   my @cfgs = grep { /\.cfg\z/  } readdir(DIR);
   closedir DIR;
   foreach my $cfg (@cfgs)  {
      if ($cfg =~ /\.system\.cfg\z/)  {  next;  } 
      if ($cfg =~ /\.temp\.cfg\z/)  {  next;  }
      rtr_process($cfg,"rtr");
   }
}

## Create vlansplitshash
foreach my $key (keys %$vlanmaphash)  {
   my($vlan,$router,$subnet,$dhcpserver) = split " ", $key;
   my($status,$state,$desc) = split " ", $vlanmaphash->{$key};
   if ($state eq "shutdown")  {  next;  }   ## shutdown interfaces do not function here
   if ($subnet eq "nosub")    {  next;  }   ## no need for vlansplits entry, as no subnet
   my($ipnum,$mask)  = split /\//, $subnet;
   my($a,$b,$c,$d) = split /\./, $ipnum;
   my $subpre;
   if ($mask == 16)  {
      $subpre = "$a.$b.";
      $subnet = "$a.$b.0.1/$mask";
   }
   if ($mask == 24)  {
      $subpre = "$a.$b.$c.";
      $subnet = "$a.$b.$c.1/$mask";
      $vlansplitshash->{"$subpre $vlan $subnet"} = 1;
    }
   if ($mask > 24)  {
      $subpre = "$a.$b.$c.";
      my $increment = 2**(32-$mask);
      my $num;
      while ($num+$increment < $d)  {  $num = $num + $increment;  }
      $num = $num+1;     ## turn netnum into default gateway num
      $subnet = "$a.$b.$c.$num/$mask";
      $vlansplitshash->{"$subpre $vlan $subnet"} = 1;
   }
   if ($mask > 16 && $mask < 24)  {
      my $j = $c + (2**(24-$mask));
      for (my $i=$c; $i<$j; $i++)  {
         $subpre = "$a.$b.$i.";
         $vlansplitshash->{"$subpre $vlan $subnet"} = 1;
      }
   }
}
## Print/database vlanmaphash
my $vmapprtf = "%-6s %-32s %-19s %-6s %-16s %-8s %-32s\n";
my $vsplprtf = "%-12s %-5s %-20s\n";
if ($db)  {
   my $delete_h = $dbh->prepare("DELETE FROM network.vlanmap;");
   $delete_h->execute();
}
foreach my $key (keys %$vlanmaphash)  {
   my($vlan,$router,$subnet,$dhcpserver) = split " ", $key;
   if (exists($gatevlanhash->{$vlan}))  {  $dhcpserver = $dhcp2;  }
   my($status,$state,$desc) = split " ", $vlanmaphash->{$key};
   printf $ofh $vmapprtf, $vlan, $router, $subnet, $status, $dhcpserver, $state, $desc;
   if ($db)  {
      #  added 2020-09-18 because shutdown interfaces do not function in this table
      if ($state ne "shutdown")  {
         my $insert_h = $dbh->prepare('INSERT into network.vlanmap (vlan,router,subnet,status,dhcpserver,state,description) VALUES (?,?,?,?,?,?,?)');
         $insert_h->execute($vlan,$router,$subnet,$status,$dhcpserver,$state,$desc);
      }
   }
}
## Print/database vlansplitshash
if ($db)  {
   my $delete_h = $dbh->prepare("DELETE FROM network.vlansplits;");
   $delete_h->execute();
}
foreach my $key (keys %$vlansplitshash)  {
   my($subpre,$vlan,$subnet) = split " ", $key;
   printf $tfh $vsplprtf, $subpre, $vlan, $subnet; 
   if ($db)  {
     my $query = "INSERT into network.vlansplits VALUES(\"$vlan\",\"$subpre\",\"$subnet\"); ";
     my $insert_h = $dbh->prepare($query);
     $insert_h->execute();
     #print "$query\n";
   }
}
## Palo Alto only (wireless): Print/database ipvlanmaphash
print $tfh "Palo Alto IPVLANMAP\n";
if ($db) {
   my $query    = "DELETE from network.ipvlanmap where context = \"wireless\"; ";
   my $delete_h = $dbh->prepare($query);
   $delete_h->execute();
}
my $iv;
foreach my $key (sort keys %$ipvlanmap)  { push @$iv, $key; }
$iv = sort_by_ip($iv);
foreach my $ln (@$iv)  {
   print $tfh "$ln\n";
   my($ip,$vlan,$context,$nameif,$nat_type,$outside) = split " ", $ln;
   if ($vlan eq "")  { $vlan = "0"; }
   print $tfh " $ip  $vlan  $context  $nameif  $nat_type  $outside\n";
   if ($db)  {
      $insert_h  = $dbh->prepare("INSERT IGNORE into network.ipvlanmap VALUES (?,?,?,?,?,?)");
      $insert_h->execute($ip,$vlan,$context,$nameif,$nat_type,$outside);
   }
}

print "\n";
exit;

################################

sub fw_process  {

   my $cfg = shift; 
   my $dev = shift;

   require "$installpath/lib/servers.pl";
   my $domain = dnssuffix();
   my $dhcpserver = dhcp1();  
   my ($fwname, undef) = split /\./, $cfg;
   my $infh = IO::File->new("$fwcfgdir/$cfg");
   my $session = SshPa->new("$fwname.fw.$domain");
   my $state = $session->connect;
   if ($state =~ /passive/)  {  return;  }
   if ($state =~ /active/)   {  $state = "active";   }
   $session->command("set cli pager off");
   my $cmd_ret;
   my $pacmd = "show interface all";
   $cmd_ret = $session->command($pacmd);
   $session->command("exit");
   $session->close();
   ## process interface data
   foreach my $cr (@$cmd_ret)  {
      chomp($cr);
      ## name      id   vsys zone     forwarding         tag  address
      ## ae6.889   142  2    vlan889  vr:east-wireless   889  10.44.208.1/22
      my($pipe,undef,undef,$vlantag,undef,$vlan,$subnet) = split " ", $cr;       ## vlantag = nameif
      ($pipe,undef) = split /\./, $pipe;
      if ($subnet !~ /10\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{2}/)  {  next;  }
      if ($vlan =~ /\d{4}/)  {  next;  }
      $vlanmaphash->{"$vlan $fwname $subnet $dhcpserver"} = "primary $state wireless";
      ## ipvlanmap:  ip   vlan   context   nameif   nat_type   outside   
      my ($gw,$mask) = split /\//, $subnet;
      my ($i1,$i2,$i3,$i4) = split /\./, $gw;
      if ($mask eq "32")     {  $ipvlanmap->{"$gw $vlan wireless $vlantag d $pipe"} = 1; }
      if ($mask gt "23" && $mask lt "32")  {
         my $exp = 32 - $mask;
         my $subsize = 2**$exp;     ## $subsize was $ipspace
         my $rem = $i4 % $subsize;  ## $rem = how far gw is above network number
         my $netnum = $i4 - $rem;
         foreach my $n ($netnum..$netnum+$subsize-1)  {  $ipvlanmap->{"$i1.$i2.$i3.$n $vlan wireless $vlantag d $pipe"} = 1; }
      }
      if ($mask lt "24" && $mask gt "16" )  {
         my $lastsub = $i3 + 2**(24-$mask) - 1;
         my $last = "$i1.$i2.$lastsub.254";
         my $j;
         for ($j = $i3; $j <= $lastsub ; $j++)  {
             foreach my $n (0..255)  {  $ipvlanmap->{"$i1.$i2.$i3.$n $vlan wireless $vlantag d $pipe"} = 1; }
             $ipvlanmap->{"$last $vlan wireless $vlantag d $pipe"} = 1;
         }
      }
      if ($mask lt "17")  {  $ipvlanmap->{"$gw $vlan wireless $vlantag d $pipe"} = 1; }
   }
}  ## fw_process

################################

sub router_process  {

  my $cfg = shift; 
  my $dev = shift;

  my ($interface,$state,@subnets,$mask,$sec,@helpers,$helper,$desc); ## loop persistents
  my ($router, undef) = split /\./, $cfg;
  my $infh = IO::File->new("$routercfgdir/$cfg");
  while (my $ln = <$infh>)  {
     chomp($ln);
     if ($ln =~ /\A\s*interface Vlan/)  {
        ## Interface line - so process all the *Previous* Interface's stuff before you go on
        $ln =~ s/GigabitEthernet/Gi/;
        $ln =~ s/Ethernet/Eth/;
        my $int = $ln;  
        $int =~ s/interface Vlan//g;  
        if (scalar(@helpers) == 0)  {  push @helpers, "none";  }  ## so if no dhcp, you still get an entry
        if (($interface ne "") && ($interface ne "1")) {    ## ( 1st time around && Vlan1 )
           foreach my $sub (@subnets)  {   ## router can have multiple subnets
              if ($sub)  {
                 ($sub,$sec) = split " ", $sub;  ## grab off the primary/secondary designation
                 foreach my $dhcpserver (@helpers)  {
                    if (!$dhcpserver)  {  $dhcpserver = "none";  }
                    if ($sec eq "secondary")  { $dhcpserver = "none";  }
                    $helperhash->{"$interface $router $dhcpserver"} = "$router $sub $sec $state $desc";
                    $vlanmaphash->{"$interface $router $sub $dhcpserver"} = "$sec $state $desc";
                 }
              }
           } ## foreach
        }  
        ## clean loop persistents
        $state = "active";
        @helpers=();
        @subnets=();
        $mask=$sec=$helper=$desc="";
        $interface = $int;   ## assign for future loops
     }
     if ($ln =~ /\A\s*ip address/)  { 
        my($g,$m);
        (undef,undef,$g,$m,$sec) = split " ", $ln;
        $m = re_mask($m); 
        if ($sec eq "")  { $sec = "primary"; }
        push @subnets, "$g$m $sec";
     }
     if ($ln =~ /\A\s*ip helper-address/)  { 
        $helper = $ln;             
        $helper =~ s/\s*ip helper-address\s*//g;
        $helper =~ s/\s*global\s*//g;
        push @helpers, $helper;
     }
     if ($ln =~ /\A\s*shutdown/)  { 
        $state = "shutdown";
     }
     if ($ln =~ /\A\s*description/)  {
        $ln =~ s/description//;
        $desc = $ln;
        $desc =~ s/\,/\-/g;
        $desc =~ s/\'/\-/g;
        if ($desc =~ /\A\s*\z/)  {  $desc = "none";  }
     }
  }  ## while
  ## Do the last interface, which would not be fully processed by a simple loop
  if (!exists $allvlanhash->{$interface})  {
     if (($interface) and ($interface ne "1"))  {
	if (scalar(@helpers) == 0)  {  push @helpers, "none";  }
	foreach my $sub (@subnets)  {
           if ($sub)  {
              ($sub,$sec) = split " ", $sub;  ## grab off the primary/secondary designation
              foreach my $dhcpserver (@helpers)  {
                 if (!$dhcpserver)  {  $dhcpserver = "none";  }
                 $helperhash->{"$interface $router $dhcpserver"} = "$router $sub $sec $state $desc";
                 $vlanmaphash->{"$interface $router $sub $dhcpserver"} = "$sec $state $desc";
              } 
           }
       	}
     }
  }

  return;
} ## router_process;

############################################

sub rtr_process  {

  my $cfg = shift;
  my $dev = shift;

  my($rtr, undef) = split /\./, $cfg;
  my $infh = IO::File->new("$rtrcfgdir/$cfg");

  my ($interface,$state,$subnet,$mask,$vrf,$sec,@helpers,$helper,$desc); ## loop persistents
  while (my $ln = <$infh>)  {
     chomp($ln);
     if ($ln =~ /\A\s*interface Vlan/)  {
        $ln =~ s/GigabitEthernet/Gi/;
        $ln =~ s/Ethernet/Eth/;
        ## Interface line - therefore: process all the *Previous* Interface's stuff before you go on
        my $int = $ln; ## save $int for end of this loop and process current "$interface"
        $int =~ s/interface Vlan//g;
        if (scalar(@helpers) == 0)  {  push @helpers, "none";  }  ## so if no dhcp, you still get an entry
        if (($interface ne "") && ($interface ne "1")) {    ## ( 1st time around && Vlan1 )
           foreach my $dhcpserver (@helpers)  {
              if (!$dhcpserver)  {  $dhcpserver = "none";  }
              $helperhash->{"$interface $rtr $dhcpserver"} = "$rtr.$vrf $subnet primary $state $desc";
              $vlanmaphash->{"$interface $rtr.$vrf $subnet $dhcpserver"} = "primary $state $desc";
           }
        } 
        ## clean loop persistents
        $state = "active";
        @helpers=();
        $mask=$subnet=$sec=$helper=$desc=$vrf="";
        $interface = $int;   ## assign for future loops
     }
     if ($ln =~ /\A\s*ip address/)  {
        my($g,$m);
        (undef,undef,$g,$m,$sec) = split " ", $ln;
        $m = re_mask($m);
        $subnet = "$g$m";
     }
     if ($ln =~ /\A\s*ip helper-address/)  {
        if ($ln =~ /\A\s*ip helper-address vrf/)  { next; }  ## 2021-06-08
        $helper = $ln;
        $helper =~ s/\s*ip helper-address\s*//g;
        $helper =~ s/\s*global\s*//g;
        push @helpers, $helper;
     }
     if ($ln =~ /\A\s*ip vrf forwarding/)  { ## 3850 version
        $ln =~ s/\s*ip vrf forwarding\s*//g;
        $vrf = $ln;             
     }
     if ($ln =~ /\A\s*vrf forwarding/)  { ## 3750X version
        $ln =~ s/\s*vrf forwarding\s*//g;
        $vrf = $ln;             
     }
     if ($ln =~ /\A\s*shutdown/)     { $state = "shutdown"; }
     if ($ln =~ /\A\s*description/)  {
        $ln =~ s/description//;
        $desc = $ln;
        $desc =~ s/\,/\-/g;
        $desc =~ s/\'/\-/g;
        if ($desc =~ /\A\s*\z/)  {  $desc = "none";  }
     }
  }  ## while
  ## Do the last interface processing, which is not completed by the loop
  if (!exists $allvlanhash->{$interface})  {
     if ($interface ne "1")  {
        if (scalar(@helpers) == 0)  {  push @helpers, "none";  }
        foreach my $dhcpserver (@helpers)  {
#           if (exists($gatevlanhash->{$interface}))  {
#              if ($dhcpserver eq $dhcp1)  {  $dhcpserver = $dhcp2;  }
#           }
           if (!$dhcpserver)  {  $dhcpserver = "none";  }
           if ($vrf ne "")  {   
              $helperhash->{"$interface $rtr $dhcpserver"} = "$rtr.$vrf $subnet primary $state $desc";
              $vlanmaphash->{"$interface $rtr.$vrf $subnet $dhcpserver"} = "primary $state $desc";
           }
           else  {
              $helperhash->{"$interface $rtr $dhcpserver"} = "$rtr $subnet primary $state $desc";
              $vlanmaphash->{"$interface $rtr.$vrf $subnet $dhcpserver"} = "primary $state $desc";
           }
        }
     }
  }

  return;
} ## rtr_process;

############################################

sub asa_process  {

  my $cfg = shift;
  my $dev = shift;

  my $context = $cfg;
  $context =~ s/\.cfg//g;
  my $infh = IO::File->new("$asacfgdir/$cfg");
  my (@ints,$interface,$description,$state,$subnet,@dhcpservers,$desc);
  ## get the array of dhcp servers first - you need them to process interfaces:
  while (my $ln = <$infh>)  {
     chomp($ln);
     if ($ln =~ /\Adhcprelay server/)  {
        my(undef,undef,$server,undef) = split " ",$ln;
        push @dhcpservers, $server;
     }
  }
  if (scalar(@dhcpservers) == 0)  {  push @dhcpservers, "none";  }  ## so if no dhcp, you still get an entry

  my $do_description = 1;  ## means: include description line in the data
  ## get interfacess and the rest
  my $infh = IO::File->new("$asacfgdir/$cfg");
  while (my $ln = <$infh>)  {
        chomp($ln);
     ## If interface line, save new one and process off old one:
     if ($ln =~ /\A\s*interface/)  {
        $ln =~ s/GigabitEthernet/Gi/;
        $ln =~ s/Ethernet/Eth/;
	my (undef,$iname) = split / /, $ln;
        my (undef,$vlan) = split /\./, $iname;
        if ($interface)  {  ## skip first time, process previous
           foreach my $dhcpserver (@dhcpservers)  {
              if ($subnet eq "")  { $subnet = "nosub"; }
              if ($interface eq "Management0/0") { }  #####  print $tfh "skipping $context:$interface\n";  } 
              else {
                 $helperhash->{"$interface $context $dhcpserver"} = "$context $subnet primary $state $desc"; 
                 $vlanmaphash->{"$interface $context $subnet $dhcpserver"} = "primary $state $desc";
              }
	      $allvlanhash->{$interface} = $interface;
           }
        }
        $state = "active";
	if ($vlan) {  $interface = $vlan;  }    ## save for process
        else       {  $interface = $iname;  }   ## put m0/0 into hash. We'll skip it later.  
        $subnet = "";
        $desc   = "";
        $do_description = 1;
     }
     if ($ln =~ /\A\s*ip address/)  {
        my($g,$m);
        (undef,undef,$g,$m) = split " ", $ln;  
        $m = re_mask($m);
        $subnet = "$g$m";
     }
     if ($ln =~ /\A\s*shutdown/)  {   $state = "shutdown";  }
     if ($do_description)  {
        if ($ln =~ /\A\s*description/)  {
           $ln =~ s/description//;
           $desc = $ln;
           $desc =~ s/,/-/g;
           $desc =~ s/\'/\-/g;
           if ($desc =~ /\A\s*\z/)  {  $desc = "none";  }
        }
     }
  }
  ## Do the last interface, which would not be fully processed by a simple loop
  if (($interface) and ($interface ne "1"))  {
     foreach my $dhcpserver (@dhcpservers)  {
        if ($dhcpserver)  {
           if ($subnet eq "")  { $subnet = "nosub"; }
           if (($interface eq "Management0/0") or ($interface =~ /GigabitEthernet/))  {  }  ##### print $tfh "skipping $context:$interface\n";  }
           else {
              $helperhash->{"$interface $context $dhcpserver"} = "$context $subnet primary $state $desc";
              $vlanmaphash->{"$interface $context $subnet $dhcpserver"} = "primary $state $desc";
           }
        }
     }
  }
   return;
}  ##asa_process

#########################################################################

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
#####################################################
#
# Given an old style octet mask, returns a slash mask
#
#####################################################

sub re_mask   {

   my $mask = shift;

   if ($mask eq "255.255.128.0")   { $mask = "/17"; }
   if ($mask eq "255.255.192.0")   { $mask = "/18"; }
   if ($mask eq "255.255.224.0")   { $mask = "/19"; }
   if ($mask eq "255.255.240.0")   { $mask = "/20"; }
   if ($mask eq "255.255.248.0")   { $mask = "/21"; }
   if ($mask eq "255.255.252.0")   { $mask = "/22"; }
   if ($mask eq "255.255.254.0")   { $mask = "/23"; }
   if ($mask eq "255.255.255.0")   { $mask = "/24"; }
   if ($mask eq "255.255.255.128") { $mask = "/25"; }
   if ($mask eq "255.255.255.192") { $mask = "/26"; }
   if ($mask eq "255.255.255.224") { $mask = "/27"; }
   if ($mask eq "255.255.255.240") { $mask = "/28"; }
   if ($mask eq "255.255.255.248") { $mask = "/29"; }
   if ($mask eq "255.255.255.252") { $mask = "/30"; }
   if ($mask eq "255.255.255.255") { $mask = "/32"; }
   return($mask);
}

######################################################

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

######################################


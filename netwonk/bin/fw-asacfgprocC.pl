#!/usr/bin/perl

# jackg@uic.edu
#
# fw-asacfgprocC.pl
#
# Reads and processes one asa config (via @ARG), either from Parent process via asacfgprocP.pl
# or entered by a single command line argument - the .cfg filename.  
# Collects various data, creates ip data map of network: network.ipvlanmap, also network.staticmap 
#

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use IO::File;

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});
my ($insert_h,$update_h,$select_h);

require "$installpath/lib/servers.pl";
my $ipprefix1 = ipprefix1();
my $ipprefix2 = ipprefix2();
my $ipprefix3 = ipprefix3();

use vars qw ( $ipvlanmap $statics );   ## hash refs

#my ($of,$ofh);
my ($asa,$context);
my $cfg_path = "$installpath/configs/asa";
if (@ARGV)  {    ## a single config file as argument - manual run
   my $configfile = $ARGV[0];
   my $fwn = $configfile;
   $fwn =~ tr/\./ /;
   ($asa,$context) = split " ", $fwn;
   #$of  = "/$installpath/forensic/asa/$asa.$context.asacfgprocC.out";
   #$ofh = IO::File->new(">$of");
   my $fh = IO::File->new("$cfg_path/$configfile");
   my $cfg;  ## array ref - one config
   while (my $ln = <$fh>)  {
      chomp($ln);
      push @$cfg, $ln;
   }
   process_asacfg($cfg);  ## asa
}
else  {  
   print "No argument entered -- argument is asa .cfg full filename.\n";
}

exit;

###########################################

sub process_asacfg  {

   my $cfg = shift;

   my $cfghash;
   ## get the outside vlan
   my @rtln = grep /route\s\w+\s0\.0\.0\.0/, @$cfg;
   chomp($rtln[0]);
   my (undef,$outnameif,undef,undef,$outgw) = split " ", $rtln[0];
   my $outsidevlan;
   if ($outnameif eq "outside")  {
      my $int;    
      foreach my $ln (@$cfg)  {
         if ($ln =~ /\A\s*interface/)  {
            chomp $ln;
            (undef,$int) = split " ", $ln;
         }
         if ($ln =~ /\A\s*nameif outside/)  {
            chomp $ln;
            (undef,$outsidevlan) = split /\./, $int; 
         }
         if ($ln =~ /\A\s*!/)  { 
            $int   = "";
         }
         if ($ln =~ /\A\s*object/)  {  last;  }           ## no more interface lines
      }
   }

   my $tempifh;  ## array of one interface worth of config
   foreach my $ln (@$cfg)  {
      chomp $ln;
      if ($ln =~ /\Ainterface/)          {  $tempifh->{"interface"}      = $ln; }
      if ($ln =~ /\A\s*description/)     {  $tempifh->{"description"}    = $ln; }
      if ($ln =~ /\A\s*nameif/)          {  $tempifh->{"nameif"}         = $ln; }
      if ($ln =~ /\A\s*security-level/)  {  $tempifh->{"security-level"} = $ln; }
      if ($ln =~ /\A\s*ip address/)      {  $tempifh->{"ip address"}     = $ln; }
      if ($ln =~ /\A\s*no ip address/)   {  $tempifh->{"ip address"}     = $ln; }
      if ($ln =~ /\s*!\s*\z/)  {         ## meaning we reached the end of this interface block
         if (! $tempifh)  {  next;  }
         ## while (my($x,$y) = each(%$tempifh)) { print "tempifh: $x => $y\n";  }
         my(undef,$interface) = split " ", $tempifh->{"interface"};
         my(undef,$vlan) = split /\./, $interface;   # Port-channel.vlan interface syntax      
         my $nameif;
         if (not $tempifh->{"nameif"})   {  $nameif = $vlan;  }  ## RARE: no nameif? use vlantag  
         else  {  (undef,$nameif) = split " ", $tempifh->{"nameif"};  }
         if ($nameif eq "")  {  next;  } 
         $cfghash->{$nameif}->{"interface"} = $interface;
         $cfghash->{$nameif}->{"vlan"} = $vlan;
         my (undef,$desc)  = split " ", $tempifh->{"description"}, 2;  ## peel off word "description"
         $cfghash->{$nameif}->{"description"} = $desc || "none";
         my (undef,$sec)  = split " ", $tempifh->{"security-level"};
         $cfghash->{$nameif}->{"security-level"} = $sec;
         ## work out all the host addresses from this interface
         $ln = $tempifh->{"ip address"};
         if ($ln =~ /no ip address/)    {
            $cfghash->{$nameif}->{"gateway"} = 0;
            $cfghash->{$nameif}->{"mask"}    = 0;
            $cfghash->{$nameif}->{"standby"} = 0;
         } 
         else  {      ## ip address
            my (undef,undef,$gateway,$mask,undef,$standby) = split " ", $ln;
            ## while ( my($x,$y) = each(%{$cfghash->{$nameif}}) )  {  print $ofh "$x => $y\n";  }
            $cfghash->{$nameif}->{"gateway"} = $gateway;
            $cfghash->{$nameif}->{"mask"}    = $mask;     
            $cfghash->{$nameif}->{"standby"} = $standby;
            ## if $outnameif does not exist, try to create one based on nameif = "outside"
            #print $ofh "=> ", $cfghash->{"outside"}->{"vlan"}, "\n";
            #if ($outnameif eq "" || $outnameif eq "0")  {         ## i.e. no route statement in config - see above
            #   $outnameif = $cfghash->{"outside"}->{"vlan"} || "0" ;  
            #}
            ## create ipvlanmap entries from interface definition
            foreach my $ip ( @{expand_subnet($gateway,$mask)} )  {
               push @{$cfghash->{$nameif}->{"iplist"}}, $ip;
               my $type = "0";  ## not a nat .'. no nat type - interface defined
               if ($vlan eq "")  { $vlan = "0"; }
               $ipvlanmap->{"$ip $vlan $context $nameif $type $outnameif"} = 1;
            }
         }
         %$tempifh = ();  ## go for another interface group
      }
   }

   ## Skip the Services, just do the networks.  If we ever need to automate services, it can be done within this scope.
   ## Then just work the nat statements, which is where the addresses are going to come from
   my $objln;       ## used to save 'name' line of objects 
   foreach my $ln (@$cfg)  {
      chomp $ln;
      if ($ln =~ /subnet 10.0.0.0/)  { next; }  # quick/dirty
      if ($ln =~ /subnet \d{1,3}.\d{1,3}.0.0/)  { next; }  # quick/dirty
      if ($ln =~ /\A\s*object/)  {
         $objln = $ln;
         next;
      }
      if ($ln =~ /^access-/)   {  $objln = "";  }  ## no more objects in cfg
      if ($ln =~ /^nat/)   {     ## global nat line, *not* tied to an object definition
         if ($ln =~ /source static/)  {
            ## identity nat:
            if ($ln =~  /destination static/)  {
               my(undef,undef,undef,undef,$s1,$s2,undef,undef,$d1,$d2) = split " ", $ln;
               if ($s1 eq $s2 && $d1 eq $d2)  {
                  ## print "identity nat $s1 \n";
                  next; 
               }
            }
            else  {
               my(undef,undef,undef,undef,$s1,$s2,undef) = split " ", $ln;
               if ($s1 eq $s2)  {
                  ## print "identity nat $s1 \n";
                  next; 
               }
               
            } 
         }  ## if source static  
         if ($ln =~ /source dynamic/)  {
            if ($ln =~ /pat-pool/)  {
               my(undef,$inout,undef,undef,undef,undef,$outobj) = split " ", $ln;
               $inout =~ s/\(//;
               $inout =~ s/\)//;
               my($in,$out) = split ",", $inout;  ## $in and $out are nameif entries
               my $vlan    = $cfghash->{$in}->{"vlan"};
               my $outside = $cfghash->{$out}->{"vlan"};
               my $type = "p";  ## PAT
               foreach my $ip ( @{$cfghash->{$outobj}->{"iplist"}} )  {
                  ## usually only one, but multi is possible   
                  $ipvlanmap->{"$ip $vlan $context $in $type $outside"} = 1;
               }
               next;
            }  
            #if ($ln =~ /destination static/)  {
            #   ## policy nat
            ###  Not doing anything with this right now - these are processed below
            #   next;     
            #}
            else  {
               my(undef,$inout,undef,undef,undef,$outobj,undef) = split " ", $ln;
               $inout =~ s/\(//;
               $inout =~ s/\)//;
               my($in,$out) = split ",", $inout;  ## $in and $out are nameif entries
               my $vlan    = $cfghash->{$in}->{"vlan"};
               my $outside = $cfghash->{$out}->{"vlan"};
               if ($in eq "any")  {  $vlan = "any";  }  ## fake a wildcard vlan on keyword any
               my $type = "d";  ## dynamic
               foreach my $ip ( @{$cfghash->{$outobj}->{"iplist"}} )  {
                  ## usually only one, but multi is possible
                  $ipvlanmap->{"$ip $vlan $context $in $type $outside"} = 1;
               }
               next;
            }
         }
      }  ## if nat 
      ## Now we look at lines tied to an object/object-group definition
      if ($objln ne "")  {   ## there is a saved 'object network' line  (object-group network)
         my ($obj,$objtype,$objname) = split " ", $objln;
         $cfghash->{$objname}->{"class"} = $obj;
         $cfghash->{$objname}->{"type"} = $objtype;
         if ($ln =~ /^\s*host\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)  {
            my(undef,$hostip) = split " ", $ln;
            $cfghash->{$objname}->{"host"} = $hostip;
             push @{$cfghash->{$objname}->{"iplist"}}, $hostip;
         }
         if ($ln =~ /^\s*range\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)  {
            my(undef,$range1,$range2) = split " ", $ln;
            $cfghash->{$objname}->{"range"} = "$range1 $range2";
            ## add the returned iplist from expand range 
            foreach my $ip ( @{expand_range($range1,$range2)} )  {
               push @{$cfghash->{$objname}->{"iplist"}}, $ip;
            }
	 }
         if ($ln =~ /^\s*subnet\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)  {
            my(undef,$subnet,$mask) = split " ", $ln;
            $cfghash->{$objname}->{"subnet"} = "$subnet $mask";
            foreach my $ip ( @{expand_subnet($subnet,$mask)} )  {
               push @{$cfghash->{$objname}->{"iplist"}}, $ip;
            } 
         }
         if ($ln =~ /^\s*network-object host\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*\z/)  {
            my(undef,undef,$hostip) = split " ", $ln;
            push @{$cfghash->{$objname}->{"network-object host"}}, $hostip;
            push @{$cfghash->{$objname}->{"iplist"}}, $hostip;
         }
         if ($ln =~ /^\s*network-object\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)  {
            my(undef,$subnet,$mask) = split " ", $ln;
            push @{$cfghash->{$objname}->{"network-object"}}, "$subnet $mask";
            my($subnet_ok,$mask_ok);
            if ($subnet =~ /^$ipprefix1/ || $subnet =~ /^$ipprefix2/ || $subnet =~ /^$ipprefix3/ ||
               $subnet =~ /^10\./ || $subnet =~ /^172\./ || $subnet =~ /^192\.168/)   {
               $subnet_ok = 1;
            }
            my $remask = re_mask($mask);
            if (re_mask($mask) > 17)  {
               $mask_ok = 1;
            }
            if ($subnet_ok && $mask_ok)  {
               foreach my $ip ( @{expand_subnet($subnet,$mask)} )  {
                  push @{$cfghash->{$objname}->{"iplist"}}, $ip;
               }
            }
            else  {
               push @{$cfghash->{$objname}->{"iplist"}}, $subnet;
            } 
         }
         if ($ln =~ /^\s*group-object/)  {
            my(undef,$oname) = split " ", $ln;
            push @{$cfghash->{$objname}->{"group-object"}}, "$oname";
            foreach my $ip ( @{$cfghash->{$oname}->{"iplist"}} )  {
               push @{$cfghash->{$objname}->{"iplist"}}, $ip;
            }            
         }
         if ($ln =~ /^\s*network-object object\s+/)  {
            my(undef,undef,$oname) = split " ", $ln;
            push @{$cfghash->{$objname}->{"network-object object"}}, "$oname";
            foreach my $ip ( @{$cfghash->{$oname}->{"iplist"}} )  {
               push @{$cfghash->{$objname}->{"iplist"}}, $ip;
            }
         }
         if ($ln =~ /^\s*nat/)  {    ## nat line inside an object
            my(undef,$inout,$nattype,$outobj) = split " ", $ln;
            $inout =~ s/\(//;
            $inout =~ s/\)//;
            my($in,$out) = split ",", $inout;  ## $in and $out are nameif entries
            if ($in eq "any") { next; }  ## don't need nat ips inside objects should already be defined
            my $vlan    = $cfghash->{$in}->{"vlan"}; 
            my $outside = $cfghash->{$out}->{"vlan"}; 
            if ($nattype eq "static")  {
               my $type = "s";
               my $pubip  = $outobj;
               my $privip = $cfghash->{$objname}->{"host"}; 
               $statics->{"$privip $pubip $vlan $context $outside"} = 1;  
               $ipvlanmap->{"$pubip $vlan $context $in $type $outside"} = 1;
            }
            if ($nattype eq "dynamic")  {
               my $type = "d";
               ## process each ip in outobj, i.e. the nat global pool
               foreach my $ip ( @{$cfghash->{$outobj}->{"iplist"}} )  {
                  $ipvlanmap->{"$ip $vlan $context $in $type $outside"} = 1;
               }
            }
         }  ## if $ln =~ nat
      }  ## if ($objln ne "")
   }  ## foreach my $ln (@$cfg)  
   

my $run = 1;
if ($run) {
   my $query    = "DELETE from network.staticmap where context = \"$context\"; ";
   my $delete_h = $dbh->prepare($query);
   $delete_h->execute();
      foreach my $ln (keys %$statics)  {
         my($privip,$pubip,$vlan,$context,$outside) = split " ", $ln;
         if ($privip =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ && $pubip =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)  {     
            $insert_h  = $dbh->prepare("INSERT IGNORE into network.staticmap VALUES (?,?,?,?,?)");
            $insert_h->execute($privip,$pubip,$vlan,$context,$outside);
         }
      }
}

$run = 1;
if ($run) {
   my $query = "SELECT ip,vlan FROM network.ipvlanmap where context = \"$context\"; ";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      foreach my $row (@$sel_ary)   {
         my ($ip,$vlan) = @$row;
         my $dquery = "DELETE FROM network.ipvlanmap WHERE ip=\"$ip\" AND vlan=\"$vlan\" ";
         my $delete_h = $dbh->prepare($dquery);
         $delete_h->execute();
      }
   }
   my $iv;
   foreach my $key (sort keys %$ipvlanmap)  { push @$iv, $key; }   
   $iv = sort_by_ip($iv);
   foreach my $ln (@$iv)  { 
      my($ip,$vlan,$context,$nameif,$nat_type,$outside) = split " ", $ln;
      $outside =~ s/vlan//i;
      if ($outside eq "outside")  {  $outside = $outsidevlan;  }   
      if ($vlan eq "")  { $vlan = "0"; }
      $insert_h  = $dbh->prepare("INSERT IGNORE into network.ipvlanmap VALUES (?,?,?,?,?,?)");
      $insert_h->execute($ip,$vlan,$context,$nameif,$nat_type,$outside);  
   }
}

}  ## process_asacfg

#####################

sub expand_range  {

   my $range1 = shift;
   my $range2 = shift;

   my $iplist;  ## ip array
   my($i1,$i2,$i3,$i4) = split /\./, $range1;
   my($j1,$j2,$j3,$j4) = split /\./, $range2;
   foreach my $n ($i4..$j4)  {
      push @$iplist, "$i1.$i2.$i3.$n";
   }
   return($iplist);

}  ## expand_range

######################

sub expand_subnet   {

  my $gw      = shift;
  my $mask    = shift;
  my $iplist;  ## hash ref
  my ($i1,$i2,$i3,$i4) = split /\./, $gw;
  my $slashmask = re_mask($mask);
  if ($slashmask eq "32")     {  push @$iplist, $gw;  }
  #elsif ($slashmask gt "23")  {   ## /24 and smaller slices of network
  if ($slashmask gt "23" && $slashmask lt "32")  {
     my $exp = 32 - $slashmask;
     my $subsize = 2**$exp;     ## $subsize was $ipspace
     my $rem = $i4 % $subsize;  ## $rem = how far gw is above network number
     my $netnum = $i4 - $rem;
     foreach my $n ($netnum..$netnum+$subsize-1)  {
        push @$iplist, "$i1.$i2.$i3.$n";
     }
  }
  #else  {    ## supernets
  if ($slashmask lt "24" && $slashmask gt "16" )  {
     my $lastsub = $i3 + 2**(24-$slashmask) - 1;
     my $last = "$i1.$i2.$lastsub.254";
     my $j;
     for ($j = $i3; $j <= $lastsub ; $j++)  {
         foreach my $n (0..255)  {
            push @$iplist, "$i1.$i2.$j.$n";
         }
     push @$iplist, $last;
     }
  }
  if ($slashmask lt "17")  {
     push @$iplist, $gw;
  } 
  return($iplist);

}  ## expand_subnet

######################

sub re_mask   {

   ## early versions had the "/" in the returned mask
 
   my $mask = shift;

   if ($mask eq "255.0.0.0")       { return(8); }
   if ($mask eq "255.128.0.0")     { return(9); }
   if ($mask eq "255.192.0.0")     { return(10); }
   if ($mask eq "255.224.0.0")     { return(11); }
   if ($mask eq "255.240.0.0")     { return(12); }
   if ($mask eq "255.248.0.0")     { return(13); }
   if ($mask eq "255.252.0.0")     { return(14); }
   if ($mask eq "255.254.0.0")     { return(15); }
   if ($mask eq "255.255.0.0")     { return(16); }
   if ($mask eq "255.255.128.0")   { return(17); }
   if ($mask eq "255.255.192.0")   { return(18); }
   if ($mask eq "255.255.224.0")   { return(19); }
   if ($mask eq "255.255.240.0")   { return(20); }
   if ($mask eq "255.255.248.0")   { return(21); }
   if ($mask eq "255.255.252.0")   { return(22); }
   if ($mask eq "255.255.254.0")   { return(23); }
   if ($mask eq "255.255.255.0")   { return(24); }
   if ($mask eq "255.255.255.128") { return(25); }
   if ($mask eq "255.255.255.192") { return(26); }
   if ($mask eq "255.255.255.224") { return(27); }
   if ($mask eq "255.255.255.240") { return(28); }
   if ($mask eq "255.255.255.248") { return(29); }
   if ($mask eq "255.255.255.252") { return(30); }
   if ($mask eq "255.255.255.255") { return(32); }
   #return($mask);
   return("I'M LOST!");

}  ## re_mask

#################################################

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


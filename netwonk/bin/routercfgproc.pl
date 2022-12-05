#!/usr/bin/perl

# jackg@uic.edu
#
# Reads router configs, contributes to ipvlanmap, the ip data map of the network, 
# collects various other data.
#
#

use strict;
use IO::File;
use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

#use lib "$installpath/lib";

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});
my ($insert_h,$update_h,$select_h);

#my $of  = "/root/routers/bin/routercfgproc.out";
#my $ofh = IO::File->new(">$of");

# control variables
my $pr = 1;  # used to run in print mode
my $db = 1;  # used to execute database processing

my $ipvlanmap;  ## hash ref - all ipvlanmap info
my $statics;    ## hash ref - all static nat entries

my $args;
@$args = @ARGV;
if (!@ARGV)  { 
   print "No argument entered -- argument is <router>.cfg filename (no path).\n";
   exit;
}

my $cfghash;
my $router;   ## scalar, holds currently processed router
my $routers;  ## array ref of all the routers processing this time through
my $cfg_path = "/$installpath/configs/routers";
my $cfgfile = $args->[0];        ## one .cfg file as argument
my $file = "$cfg_path/$cfgfile";
my $fh = IO::File->new("$file");
#my $fh = IO::File->new("$cfg_path/$cfgfile");
my $cfg;  ## array ref - one config
while (my $ln = <$fh>)  {
   chomp($ln);
   push @$cfg, $ln;
}
## $router is global to the program
($router,undef) = split /\./, $cfgfile;
push @$routers, $router;
process_cfg($cfg,$router);  

## foreach my $key (sort keys %$ipvlanmap)  { print "$key\n"; }
##

if ($db) {
   my $query    = "DELETE from network.ipvlanmap where context = \"$router\"; ";
   my $delete_h = $dbh->prepare($query);
   $delete_h->execute();
   my $iv;
   foreach my $key (sort keys %$ipvlanmap)  { push @$iv, $key; }
   $iv = sort_by_ip($iv);
   foreach my $ln (@$iv)  {
      #print "$ln\n";
      my($ip,$vlan,$router,$nameif,$nat_type,$outside) = split " ", $ln;
      $insert_h  = $dbh->prepare("INSERT IGNORE into network.ipvlanmap VALUES (?,?,?,?,?,?)");
      $insert_h->execute($ip,$vlan,$router,$nameif,$nat_type,$outside);
   }
}

exit;

###########################################

sub process_cfg  {

   my $cfg    = shift;
   my $router = shift;

   ## print "{process_cfg}: $router\n";
   ## routed vlan interfaces -> ipvlanmap
   my $tempifh;  ## array of one interface worth of config
   foreach my $ln (@$cfg)  {
      #if ($pr)  {  print "$ln \n";  }
      chomp $ln;
      if ($ln =~ /\A\s*shutdown/)  {
         %$tempifh = ();  ## go for another interface group
         next;
      }
      ##if ($ln =~ /\Ainterface/)           {  $tempifh->{"interface"}      = $ln; }
      if ($ln =~ /\Ainterface\s*Vlan/)      {  $tempifh->{"interface"}      = $ln; }
      if ($ln =~ /\A\s*description/)        {  $tempifh->{"description"}    = $ln; }
      if ($ln =~ /\A\s*ip vrf forwarding/)  {  $tempifh->{"ip vrf forwarding"} = $ln; }
      if ($ln =~ /\A\s*ip address/)         {  $tempifh->{"ip address"}     = $ln; }
      if ($ln =~ /\A\s*no ip address/)      {  $tempifh->{"ip address"}     = $ln; }
      if ($ln =~ /\s*!\s*\z/)  {
         if (not defined $tempifh->{"interface"})  {      ## not an interface group
            %$tempifh = (); 
            next;
         }  
         if (!%$tempifh)  {  next;  }
         ## while (my($x,$y) = each(%$tempifh)) { print "tempifh: $x => $y\n";  }
         my(undef,$interface) = split " ", $tempifh->{"interface"};
         my $vlan = $interface;
         $vlan =~ s/Vlan//i;
         $cfghash->{$router}->{$interface}->{"interface"} = $interface;
         $cfghash->{$router}->{$interface}->{"vlan"} = $vlan;
         my (undef,$desc)  = split " ", $tempifh->{"description"}, 2;  ##
         $cfghash->{$router}->{$interface}->{"description"} = $desc || "none";
         my (undef,$sec)  = split " ", $tempifh->{"ip vrf forwarding"};
         $cfghash->{$router}->{"ip vrf forwarding"} = $sec;
         ## work out all the host addresses from this interface
         $ln = $tempifh->{"ip address"};
         if ($ln =~ /no ip address/)    {
            $cfghash->{$router}->{$interface}->{"gateway"} = 0;
            $cfghash->{$router}->{$interface}->{"mask"}    = 0;
         }
         else  {
            my (undef,undef,$gateway,$mask) = split " ", $ln;
            $cfghash->{$router}->{$interface}->{"gateway"} = $gateway;
            $cfghash->{$router}->{$interface}->{"mask"}    = $mask;
            ## create ipvlanmap entries from interface definition
            ## the array of IPs here comes from the returned @$iplist array of expand_subnet
            foreach my $ip ( @{expand_subnet($gateway,$mask)} )  {
               push @{$cfghash->{$router}->{$interface}->{"iplist"}}, $ip;
               my $type = "0";  ## not a nat .'. no nat type - interface defined
               $ipvlanmap->{"$ip $vlan $router $interface r 0"} = 1;
            }
         }
         %$tempifh = ();  ## go for another interface group
      }
   }

   return;

}  ## process_cfg

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


#!/usr/bin/perl
#jackg@uic.edu 
#
# swmisc.pl (was SSmisc.pl)   collect misc power , version, inventory, boot info
#
# this supports to  -db0  command-line flag to turn off database processing
#

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use lib "$installpath/lib";
use SshSwcon;
use IO::File;
use Data::Dumper;
use strict;

my ($date,$time)=SshSwcon::date_time();
my $tstamp = "$date $time";

## control switches
my $db = 1;      ## switch to turn on/off writing to switch.* database

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

my $args;
@$args  = @ARGV;

if ($args->[0] eq "")  {
   print "syntax:  ./SSmisc.pl <switch_ip> <switch_name>\n...exiting...\n";
   exit;
}

for (my $i = 0; $i <= $#$args; $i++ )  {
   if ($args->[$i] =~ /-db0/)  {
      $db = 0;                   ## turn database execution off
      splice @$args, $i, 1;      ## remove from @args
   }
}
my $swip   = $args->[0];
my $swname = $args->[1];

## Connect
my $session = SshSwcon->new($swip);
my $state = $session->connect();
if ($state eq "notconnected")  {
   my $query = "INSERT into switch.noconnect (swname,swip,tstamp) VALUES(?,?,?)";
   my $insert_h = $dbh->prepare($query);
   $insert_h->execute($swname,$swip,$tstamp);
   exit;  
}
else {
   my $query = "SELECT * from switch.lastconnect WHERE swname = '$swname'";
   my $select_h = $dbh->prepare($query);
   my $lastconnects = $select_h->execute();
   if ($lastconnects != 0) {
      $query = "UPDATE switch.lastconnect SET recent = \"$tstamp\" WHERE swname = \"$swname\" ";
      my $update_h = $dbh->prepare($query);
      $update_h->execute();
   }
   else  {
      my $query = "INSERT into switch.lastconnect (swname,swip,recent) VALUES(?,?,?)";
      my $insert_h = $dbh->prepare($query);
      $insert_h->execute($swname,$swip,$tstamp);
   }
}
my $ena_ret;
if ($state ne "enabled")  {
   $ena_ret = $session->enable();
}
$session->command("term len 0");

my $of  = "$installpath/forensic/switches/$swname.swmisc";
my $ofh  = IO::File->new(">$of");
print $ofh "swmisc.pl $swip $swname\n";

my $prtlns;  ## array

## boot:  swname  swip  *module  *bootpath  tstamp
my $boot_h;
$boot_h->{"bootpath"} = "unknown";     ## default
$boot_h->{"module"} = 1;   ## default value for single switches
my $boot_lns = $session->command("show boot");
foreach my $ln (@$boot_lns)  {
   print $ofh "BOOT: $ln\n";
   if ($ln =~ /boot\s*path/i)  {
      my (undef,$bpath) = split ":", $ln, 2;  # only split on the first ':'
      ## ($bpath,undef) = split ";", $bpath;     # split up multi-boot entries, like on a 6500
      $bpath =~ s/\s+//;
      $boot_h->{"bootpath"} = $bpath;
   }
   if ($ln =~ /BOOT variable =/i)  {
      my (undef,$bpath) = split "=", $ln, 2;  
      $bpath =~ s/\s+//;
      $boot_h->{"bootpath"} = $bpath;
   }
   if ($ln =~ /^\s*Switch \d/)  {
      my (undef,$module) = split " ", $ln; 
      $boot_h->{"module"} = $module;
   }
}

## inline: swname  swip  *interface  *admin  *oper  *power  *device  *class  *max  tstamp 
if ($db) {
   my $sql_cmd = "DELETE from switch.inline WHERE swname = \"$swname\" ";
   my $delete_h = $dbh->prepare($sql_cmd);
   $delete_h->execute();
}
my $inline_h;
my $power_h;  ## needs to be definted here early
my $power_inline_lns = $session->command("show power inline");
my ($id6500,$id3550,$standard);
foreach my $ln (@$power_inline_lns)  {
   print $ofh "POWER INLINE: $ln\n";
   if ($ln =~ /^\s*\d+\s+\d+\.\d+/)  { 
      my ($module,$available,$used,$remaining) = split " ", $ln;
      $inline_h->{"module"}    = $module;
      $inline_h->{"available"} = $available;
      $inline_h->{"used"}      = $used;
      $inline_h->{"remaining"} = $remaining;
      $power_h->{"available"}  = $available;
      $power_h->{"used"}       = $used;
      $power_h->{"remaining"}  = $remaining;
   }
   if ($ln =~ /^\s*Available:/)  {
      $ln =~ s/\(w\)//g;
      my @pow = split " ", $ln;
      foreach my $p (@pow)  {
         if ($p =~ /Available/)  {
            my (undef,$available) = split ":", $p;
            $inline_h->{"available"} = $available;
            $power_h->{"available"}  = $available;
         }
         if ($p =~ /Used/)  {
            my (undef,$used) = split ":", $p;
            $inline_h->{"used"} = $used;
            $power_h->{"used"}  = $used;
         }
         if ($p =~ /Remaining/)  {
            my (undef,$remaining) = split ":", $p;
            $inline_h->{"remaining"} = $remaining;
            $power_h->{"remaining"}  = $remaining;
         }
      }
   }
   if ($ln =~ /^\s*Interface/)  {
      if ($ln =~ /^\s*Interface\s+Admin\s+Oper\s+Power\(Watts/)                     {  $id6500   = 1;  }
      if ($ln =~ /^\s*Interface\s+Admin\s+Oper\s+Power\s+Device\s*$/)               {  $id3550   = 1;  }
      if ($ln =~ /^\s*Interface\s+Admin\s+Oper\s+Power\s+Device\s+Class\s+Max\s*/)  {  $standard = 1;  }
      ##  analyze the header to see what kind of box you have and variabilize accordingly
      ## see srcs-fdf-f4.out and comrb-fdf-a1.out 
   }
   if ($ln =~ /^\s*\w+\d+\//)  {
      ## load the entries into %$inline_h here
      if ($id6500)  {
         my ($interface,$admin,$oper,$max,$power,$therest) = split " ", $ln, 6;
         my $device = substr($therest,0,20);
         my $tail   = substr($therest,20);
         my ($class,undef) = split " ", $tail, 2;
         $inline_h->{"$interface"}->{"interface"} = $interface;
         $inline_h->{"$interface"}->{"admin"}     = $admin;
         $inline_h->{"$interface"}->{"oper"}      = $oper;
         $inline_h->{"$interface"}->{"max"}       = $max;
         $inline_h->{"$interface"}->{"power"}     = $power;
         $inline_h->{"$interface"}->{"device"}    = $device;
         $inline_h->{"$interface"}->{"class"}     = $class;
         #my $max = "-";
         #$inline_h->{"$interface"}->{"max"}       = $max;
         push @$prtlns, "inline: $swname $swip $interface $admin $oper $power $device $class $max $tstamp";
         if ($db) {
            my $sql_cmd  = "INSERT into switch.inline (swname,swip,interface,admin,oper,power,device,class,max,tstamp) VALUES (?,?,?,?,?,?,?,?,?,?)";
            my $insert_h = $dbh->prepare($sql_cmd);
            $insert_h->execute($swname,$swip,$interface,$admin,$oper,$power,$device,$class,$max,$tstamp);
         }
      }
      elsif ($id3550)  {
         my ($interface,$admin,$oper,undef,$power,$device) = split " ", $ln, 6;
         $inline_h->{"$interface"}->{"interface"} = $interface;
         $inline_h->{"$interface"}->{"admin"}     = $admin;
         $inline_h->{"$interface"}->{"oper"}      = $oper;
         $inline_h->{"$interface"}->{"power"}     = $power;
         $inline_h->{"$interface"}->{"device"}    = $device;
         my $class = "-";
         $inline_h->{"$interface"}->{"class"}     = $class;
         my $max = "-";
         $inline_h->{"$interface"}->{"max"}       = $max;
         push @$prtlns, "inline: $swname $swip $interface $admin $oper $power $device $class $max $tstamp";
         if ($db) {
            my $sql_cmd  = "INSERT into switch.inline (swname,swip,interface,admin,oper,power,device,class,max,tstamp) VALUES (?,?,?,?,?,?,?,?,?,?)";
            my $insert_h = $dbh->prepare($sql_cmd);
            $insert_h->execute($swname,$swip,$interface,$admin,$oper,$power,$device,$class,$max,$tstamp);
         }
      }
      elsif  ($standard)  {
         my ($interface,$admin,$oper,$power,$therest) = split " ", $ln, 5;
         my $device = substr($therest,0,20);
         my $tail   = substr($therest,20);
         my ($class,$max) = split " ", $tail;
         $inline_h->{"$interface"}->{"interface"} = $interface;
         $inline_h->{"$interface"}->{"admin"}     = $admin;
         $inline_h->{"$interface"}->{"oper"}      = $oper;
         $inline_h->{"$interface"}->{"power"}     = $power;
         $inline_h->{"$interface"}->{"device"}    = $device;
         $inline_h->{"$interface"}->{"class"}     = $class;
         $inline_h->{"$interface"}->{"max"}       = $max;
         push @$prtlns, "inline: $swname $swip $interface $admin $oper $power $device $class $max $tstamp";
         if ($db) {
            my $sql_cmd  = "INSERT into switch.inline (swname,swip,interface,admin,oper,power,device,class,max,tstamp) VALUES (?,?,?,?,?,?,?,?,?,?)";
            my $insert_h = $dbh->prepare($sql_cmd);
            $insert_h->execute($swname,$swip,$interface,$admin,$oper,$power,$device,$class,$max,$tstamp);
         }
      }
      else  {  print $ofh "===> POWER INLINE: CANNOT ID SWICTH TYPE <===\n";  }
   }
}


## power:  swname  swip  module  redunancy  total  used  avail  tstamp  
## $power_h is defined at the top of inline
if (!defined $power_h->{"available"}) { $power_h->{"available"} = 0; }
if (!defined $power_h->{"used"})      { $power_h->{"used"}      = 0; }
if (!defined $power_h->{"remaining"}) { $power_h->{"remaining"} = 0; }
my $power_lns = $session->command("show power");  ## 6500 
foreach my $ln (@$power_lns)  {
   print $ofh "POWER: $ln\n";
   ## not going to use redundancy now, since 6500 only, but maybe later so here it is
   if ($ln =~ /system power redundancy mode/i)  {  # 6500
      my (undef,$redundancy) = split "=", $ln;
      $power_h->{"redundancy"} = $redundancy;
   }
   # "available used remaining" is default terminology for all but 6500, so our standard 
   if ($ln =~ /system power total/)  {            # 6500
      my (undef,$totalfull)   = split "=", $ln;
      my ($total,undef)       = split " ", $totalfull, 2;
      $power_h->{"available"} = $total;
   }
   if ($ln =~ /system power used/)  {             # 6500
      my (undef,$usedfull)  = split "=", $ln;
      my ($used,undef)      = split " ", $usedfull, 2;
      $power_h->{"used"}    = $used;
   }
   if ($ln =~ /system power available/)  {        #6500
      my (undef,$remainfull)  = split "=", $ln;
      my ($remain,undef)      = split " ", $remainfull, 2;
      $power_h->{"remaining"} = $remain;
   }
}
if ($power_h->{"module"} eq "")     { $power_h->{"module"}    = $boot_h->{"module"};      }
##


## inventory:  swname  swip  partname  descr  pid  vid  serial  tstamp 
if ($db) {
   my $sql_cmd = "DELETE from switch.inv WHERE swname = \"$swname\" ";
   my $delete_h = $dbh->prepare($sql_cmd);
   $delete_h->execute();
}
my $inv_h;
my $inventory_lns = $session->command("show inventory");
my ($name,$descr);
foreach my $ln (@$inventory_lns)  {
   print $ofh "INVENTORY: $ln\n";
   if ($ln =~ /^NAME:/i)  {
      my @nmlns = split ",", $ln;
      foreach my $nl (@nmlns)  {
         $nl =~ s/^\s+//;
         if ($nl =~ /NAME:/i)  {
            (undef,$name) = split /\"/, $nl;
            $inv_h->{"$name"}->{"name"} = $name;
         }
         if ($nl =~ /DESCR:/i)  {                ## 'descr' is the cisco string
            (undef,$descr) = split /\"/, $nl;
            $inv_h->{"$name"}->{"descr"} = $descr;
         }
      }
   }
   if ($ln =~ /^PID:/i)  {
      my ($pid,$vid,$serial);
      my @nmlns = split ",", $ln;
      foreach my $nl (@nmlns)  {
         $nl =~ s/^\s+//;
         if ($nl =~ /PID:/i)  {
            (undef,$pid) = split " ", $nl;
            $inv_h->{"$name"}->{"pid"} = $pid;
         }
         if ($nl =~ /VID:/i)  {
            (undef,$vid) = split " ", $nl;
            if ($vid eq "")  {  $vid = "-";  }
            $inv_h->{"$name"}->{"vid"} = $vid;
         }
         if ($nl =~ /SN:/i)  {
            (undef,$serial) = split " ", $nl;
            $inv_h->{"$name"}->{"serial"} = $serial;
         }
      }
      ##  $swname  $swip  $partname  $descr  $pid  $vid  $serial  $tstamp 
      push @$prtlns, "inv: $swname $swip $name $descr $pid $vid $serial $tstamp";
      if ($db) {
         my $sql_cmd  = "INSERT into switch.inv (swname,swip,partname,descr,pid,vid,serial,tstamp) VALUES (?,?,?,?,?,?,?,?)";
         my $insert_h = $dbh->prepare($sql_cmd);
         $insert_h->execute($swname,$swip,$name,$descr,$pid,$vid,$serial,$tstamp);
      }
   }
}

## version:  swname  swip  module  version  software/feature  reboot  uptime  image  mac  model  serial  tstamp      Ditch:reboot,reload
my $ver_h;
my ($software, $version, $image,$uptime);
$version  = "unknown";       ## default
$software = "unknown";       ## default
my $version_lns = $session->command("show version");
my $current_module = "temp";   ## internal switch module number
foreach my $ln (@$version_lns)  {
   print $ofh "VERSION: $ln\n";
   if ($ln =~ /Cisco IOS Software|IOS \(tm\)/i)  {
      $ln =~ s/\(tm\)//;
      my @ioslns = split ",", $ln;
      foreach my $i (@ioslns)  {
         $i =~ s/^\s+//;
         if ($i =~ /Software \(/)  {
            (undef,$software) = split /\(/, $i;
            $software =~ s/\)//;
            ##$ver_h->{"software"} = $software;
         }   
         if ($i =~ /Version/)  {
            (undef,$version) = split / /, $i;
            ##$ver_h->{"version"} = $version;
         }   
      }   
   }
   if ($ln =~ /System image file/i)  {
      (undef,$image) = split /\"/, $ln;
      if ($image =~ /^\s*$/)    {  $image = "unknown";  }
      ##$ver_h->{"image"} = $image;
   }
   if ($ln =~ /uptime is/i)  {
      (undef,undef,undef,$uptime) = split " ", $ln, 4;
      $uptime = fixuptime($uptime);
   }
   
   ## group - first time collected as temp until $current_module is set
   ## after that, current module is set before the lines are read
   if ($ln =~ /MAC Address/i)  {
      my (undef,$mac) = split /:/, $ln, 2;
      $mac =~ s/\s+//g;
      $mac = fix_mac_address_format($mac);
      $ver_h->{$current_module}->{"mac"} = $mac; 
   }  
   if ($ln =~ /Model Number/i)  {
      my (undef,$model) = split ":", $ln;
      $model =~ s/\s+//g;
      $ver_h->{$current_module}->{"model"} = $model; 
   }  
   if ($ln =~ /System Serial Number/i)  {
      my (undef,$serial) = split ":", $ln;
      $serial =~ s/\s+//g;
      $ver_h->{$current_module}->{"serial"} = $serial; 
   }  
   ## end group 
   if ($ln =~ /^\s*\*\s+(\d)\s+\d\d\s+/)  {       ## grabbing the active module number for temp entries
      $current_module = $1;
      $ver_h->{$current_module}->{"module"}   = $current_module; 
      $ver_h->{$current_module}->{"mac"}      = $ver_h->{"temp"}->{"mac"}; 
      $ver_h->{$current_module}->{"model"}    = $ver_h->{"temp"}->{"model"}; 
      $ver_h->{$current_module}->{"serial"}   = $ver_h->{"temp"}->{"serial"}; 
   }
   if ($ln =~ /^Switch \d(\d)/)  {         ## grabbing futher module numbers in multi module switches
      $current_module = $1;
   }
}
if ($current_module eq "temp")  {
   $current_module = "1";
   $ver_h->{$current_module}->{"module"}   = $current_module; 
   $ver_h->{$current_module}->{"mac"}      = $ver_h->{"temp"}->{"mac"}; 
   $ver_h->{$current_module}->{"model"}    = $ver_h->{"temp"}->{"model"}; 
   $ver_h->{$current_module}->{"serial"}   = $ver_h->{"temp"}->{"serial"}; 
}
delete $ver_h->{"temp"};   ## no longer needed
if ($ver_h->{$current_module}->{"mac"}    eq "")  {  $ver_h->{$current_module}->{"mac"}    = "unknown";  }
if ($ver_h->{$current_module}->{"model"}  eq "")  {  $ver_h->{$current_module}->{"model"}  = "unknown";  }
if ($ver_h->{$current_module}->{"serial"} eq "")  {  $ver_h->{$current_module}->{"serial"} = "unknown";  }

if ($db) {
   my $sql_cmd = "DELETE from switch.version WHERE swname = \"$swname\" ";
   my $delete_h = $dbh->prepare($sql_cmd);
   $delete_h->execute();
}
print $ofh "version: software = >$software<   version = >$version<   image = >$image<   uptime = >$uptime< \n";
foreach my $mod (keys %$ver_h)  {
   printf $ofh "version:    %-16s %-16s %-3s %-20s %-20s %-20s %-48s %-16s %-20s %-14s %-20s \n", $swname, $swip, $mod, $version, $software, $uptime, $image, $ver_h->{$mod}->{"mac"}, $ver_h->{$mod}->{"model"}, $ver_h->{$mod}->{"serial"}, $tstamp;
   if ($db) {
      my $sql_cmd  = "INSERT into switch.version (swname,swip,module,version,software,uptime,image,mac,model,serial,tstamp) VALUES (?,?,?,?,?,?,?,?,?,?,?)";
      my $insert_h = $dbh->prepare($sql_cmd);
      if ($uptime eq "")  { $uptime = "unknown"; }
      $insert_h->execute($swname,$swip,$mod,$version,$software,$uptime,$image,$ver_h->{$mod}->{"mac"},$ver_h->{$mod}->{"model"},$ver_h->{$mod}->{"serial"},$tstamp);
   }
}  ## if current_module

print "\n";

printf "boot:   %-16s %-16s %-3s %-20s %-20s\n", $swname, $swip, $boot_h->{"module"}, $boot_h->{"bootpath"}, $tstamp;
printf $ofh "boot:   %-16s %-16s %-3s %-20s %-20s\n", $swname, $swip, $boot_h->{"module"}, $boot_h->{"bootpath"}, $tstamp;
if ($db) {
   my $sql_cmd = "DELETE from switch.boot WHERE swname = \"$swname\" ";
   my $delete_h = $dbh->prepare($sql_cmd);
   $delete_h->execute();
   my $sql_cmd  = "INSERT into switch.boot (swname,swip,module,bootpath,tstamp) VALUES (?,?,?,?,?)";
   my $insert_h = $dbh->prepare($sql_cmd);
   $insert_h->execute($swname,$swip,$boot_h->{"module"},$boot_h->{"bootpath"},$tstamp);
}

printf "power:  %-16s %-16s %-3s %-8s %-8s %-8s %-20s\n", $swname, $swip, $power_h->{"module"}, $power_h->{"available"}, $power_h->{"used"}, $power_h->{"remaining"}, $tstamp;
printf $ofh "power:  %-16s %-16s %-3s %-8s %-8s %-8s %-20s\n", $swname, $swip, $power_h->{"module"}, $power_h->{"available"}, $power_h->{"used"}, $power_h->{"remaining"}, $tstamp;
if ($db) {
   my $sql_cmd = "DELETE from switch.power WHERE swname = \"$swname\" ";
   my $delete_h = $dbh->prepare($sql_cmd);
   $delete_h->execute();
   my $sql_cmd  = "INSERT into switch.power (swname,swip,module,total,used,remaining,tstamp) VALUES (?,?,?,?,?,?,?)";
   my $insert_h = $dbh->prepare($sql_cmd);
   $insert_h->execute($swname,$swip,$power_h->{"module"},$power_h->{"available"},$power_h->{"used"},$power_h->{"remaining"},$tstamp);
}


foreach my $ln (@$prtlns)  {
   print $ofh "$ln\n";
}

$session->close();
#$dbh->disconnect();
##
  print "\n";
  exit;  ## TESTING   
##
########################################

$session->close();

$dbh->disconnect();

exit;

#######################

sub fix_mac_address_format  {

  my $addr  = shift;

  $addr = lc($addr);   ## in case Dave typed in a mac addr  ;->
  $addr =~ s/\.//g;
  $addr =~ s/\://g;
  $addr =~ s/\-//g;
  my $aa = substr($addr,0,4);
  my $bb = substr($addr,4,4);
  my $cc = substr($addr,8,4);
  $addr = "$aa.$bb.$cc";
  return($addr);

} ## fix_mac_address_format

#####################################

sub fixuptime {          ## this routine by jlm@uic.edu, plus some tweaks

  my $uptime = shift;

  my $upnow = time;
  my %utime;
  my @timepairs = split ",", $uptime;
  foreach my $tpair (@timepairs) {
     my ($tcount, $tunit) = split ' ', $tpair;
     $tunit = lc($tunit);
     $tunit =~ s/s\z//;
     $utime{$tunit} = $tcount;
  }
  my $utmins = $utime{"year"}    * 525600;
  $utmins   += $utime{"week"}    *  10080;
  $utmins   += $utime{"day"}     *   1440;
  $utmins   += $utime{"hour"}    *     60;
  $utmins   += $utime{"minute"}  *      1;
  my $upseconds = $utmins * 60;
  my $upthen = $upnow - $upseconds;
  my ($usec,$umin,$uhour,$uday,$umon,$uyear,undef,undef,undef) = localtime($upthen);
  $uyear += 1900; # correct localtime years since 1900
  $umon  += 1;    # correct localtime month sillyness
  if ($usec  < 10)    { $usec  = "0".$usec; }
  if ($umin  < 10)    { $umin  = "0".$umin; }
  if ($uhour < 10)    { $uhour = "0".$uhour; }
  if ($uday  < 10)    { $uday  = "0".$uday; }
  if ($umon  < 10)    { $umon  = "0".$umon; }
  my $upsince = "$uyear-$umon-$uday $uhour:$umin:$usec";
  return $upsince;

} #fixuptime

#########################


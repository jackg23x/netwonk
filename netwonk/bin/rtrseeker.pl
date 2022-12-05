#!/usr/bin/perl 
#jackg@uic.edu 
#
# rtrseeker.pl - parent script for various data collection Child processes (arp, rtrcfg, etc.
#

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use lib "$installpath/lib";
use SshSwcon;
use IO::File;
use Net::DNS;
use strict;

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

if (!@ARGV)  {  help();  exit;  }
my $args;
@$args = @ARGV;
my ($command,     # special 1st arg
    $bldg,       # switchname prefix
   );

my $outf   = "$installpath/forensic/rtr/rtrseeker.out";
my $outfh  = IO::File->new(">>$outf");
my ($date,$time)=SshSwcon::date_time();
my $start_time = "$date $time";
# print $outfh "rtrseeker.pl $command  initialized: $start_time\n";
print "rtrseeker.pl $command  initialized: $start_time\n";

my $test;  ## used to set up a test hash of switches just below
$command = $args->[0];
for (my $i=0; $i< scalar(@$args); $i++)  {
   if ($args->[$i] =~ /\A-t|-test\zi/)  { $test = 1; }
   if ($args->[$i] eq "-b")  {
      $i++;
      while (($args->[$i] !~ /\A-/) && ($i< scalar(@$args)))  {
         $bldg .= "$args->[$i] ";
         $i++;
      }
   }
}

## Run in test mode using the -test parameter.
my $temp_rtrh;  ## temp hash by constant - the other method uses DNS for rtr hash
if ($test)  {
   $temp_rtrh->{"10.0.10.133"} = 'bgrc';
   $temp_rtrh->{"10.0.10.124"} = 'pharm';
}
else  {   ## This is the real production run:
    $temp_rtrh = get_DNS_switches("rtr");   ## local subroutine
}
#foreach my $k (keys %$temp_rtrh)  {  print "$k => ", $temp_rtrh->{$k}, "\n"; }

my $rtrh;
if ($bldg)  {
  my $bldgs;
  @$bldgs = split " ", $bldg;
  while (my($x,$y) = each(%$temp_rtrh))  {
     # if ($y =~ /sphw/)  { print "$y\n"; }
     foreach my $b (@$bldgs)  {
        if ($y =~ /\A$b/)  {
           print "$x => $y \n";
           $rtrh->{$x} = $y;
        }
     }
  }
}
else  {   %$rtrh = %$temp_rtrh;  }

#while (my($x,$y) = each(%$rtrh))  {  print "$x => $y\n";  }

if    ($command eq "rtrarp")     { rtrarp();  }
elsif ($command eq "rtrcfgsav")  { rtrcfgsav();   }
elsif ($command eq "rtrcfgproc") { rtrcfgproc();  }
elsif ($command eq "rtrping")    { rtrping(); }
else  {
   print "\n\n * * *\n\nUnknown command sent to script!\n\n";
   help();
}

($date,$time)=SshSwcon::date_time();
print $outfh "rseeker.pl $command  start_time: $start_time   end_time: $date $time\n";
print "\n bye bye....\n";

exit;

###############

sub rtrping  {

  ## Empty rtr.ping table
  my $query    = "DELETE from rtr.ping;";
  my $select_h = $dbh->prepare($query);
  $select_h->execute();
  $query = "INSERT INTO rtr.ping (rname,rip,ping) VALUES(?,?,?)";
  $select_h = $dbh->prepare($query);
  $select_h->execute("rundate","$start_time","0");
   
  $SIG{CHLD} = 'IGNORE';

  foreach my $rip (keys %$rtrh)  {
    my $rname = $rtrh->{$rip};
print "$rname\n";
    unless ( fork() ) {    ## execute, don't wait for status
      exec ("$installpath/bin/rtrping.pl", "$rip", "$rname", "&");
      exit (0);
    }
  }
}  ## rtrping

#######################

sub rtrarp   {

  my ($rip,$rname);

  $SIG{CHLD} = 'IGNORE';

  my $i;
  foreach my $rip (keys %$rtrh)  {
    $rname = $rtrh->{$rip};
    ## check to see if the process is running first; if so, bail
    my ($psck,$kill);
    my $hitline = "rtrarp.pl $rip $rname";
    @$psck = `ps ux | grep "$hitline" `;
    foreach my $ps (@$psck)  {
       if ($ps =~ /grep/)  {  next;  }   ## get rid of the self-referential line
       if ($ps =~ /$hitline/)  {  $kill++;  }  ## this shows it's already running
    }
    if ($kill == 0)  {                         ## it's not running, so let's run a new one
       unless ( fork() ) {    ## execute, don't wait for status
          exec ("$installpath/bin/rtrarp.pl", "$rip", "$rname", "&");
          exit (0); 
       }    
    }
    else  { print "Cannot process $rip $rname -> already running\n";  }
    $i++;
    if ($i == 50)  {
        sleep 10;
        $i = 0;
    }
  } ## foreach switch
}  ## arp  

#######################

sub rtrcfgsav  {

  my ($swname,$swip);

  $SIG{CHLD} = 'IGNORE';

  my $i;
  foreach my $swip (keys %$rtrh)  {
    $swname = $rtrh->{$swip};
    if ($swname =~ /vg224/)  { next; }
    unless ( fork() ) {    ## execute, don't wait for status
      exec ("$installpath/bin/rtrcfgsav.pl", "$swip", "$swname", "&");
      exit (0);
    }
    $i++;
    if ($i == 50)  {
       sleep 10;
       $i = 0;
    }
  } ## foreach switch
  return;

}  ## cfgsav

#######################

sub rtrcfgproc  {


   $SIG{CHLD} = 'IGNORE';

   my $cfg_path = "$installpath/configs/rtr";
   opendir(DIR, $cfg_path) || die "can't opendir $cfg_path: $!";
   my @dirlist = grep /\.cfg\z/ , readdir(DIR);
   my $i;
   foreach my $cfgfile (@dirlist)  {
      #print "$cfgfile\n";
      unless ( fork() ) {    ## execute, don't wait for status
        exec ("$installpath/bin/rtrcfgproc.pl", "$cfgfile", "&");
        exit (0);
      }
      $i++;
      if ($i == 50)  {
         sleep 5;
         $i = 0;
      }
   }
   return;
}


#######################

sub get_DNS_switches  {

  my $zone = shift;

  require "$installpath/lib/servers.pl";
  my $dns1 = dns1();
  my $dns2 = dns2();
  my $dns3 = dns3();
  my $domain = dnssuffix();
  if ($zone !~ /\.$domain/)    {  $zone = "$zone.$domain";  }

  my %switches;
  my $res  = Net::DNS::Resolver->new;
  $res->nameservers($dns1,$dns2,$dns3);
  ## get all switch entries from DNS
  my ($swip,$swname);
  my @zone = $res->axfr("$zone");
  foreach my $rr (@zone) {
    unless ($rr->type eq "A")  { next; }
    $swip   = $rr->address;
    $swname = $rr->name;
    ($swname,undef) = split /\./, $swname;
    $switches{$swip} = $swname;
  }

  return(\%switches);
}

#######################

sub help  {

print<<EOF;

rtrseeker.pl  

Syntax: rtrseeker.pl <command> [ options ]

commands:
  rtrping     - calls script rtrping.pl
  rtrarp      - calls script rtrarp.pl
  rtrcfgsav   - calls script rtrcfgsav.pl
  rtrcfgproc  - calls script rtrcfgproc.pl

options:
  -b <building prefix> front-end of a switch name, which starts with a building,
                       but you're not limited to that. You can add more.
                       * This allows PARTIAL RUNS for quick data   

  -t or -test  kicks in the use of a test rtr hash instead of the DNS-based full hash

EOF

}

#!/usr/bin/perl 
#jackg@uic.edu 

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;
use lib "$installpath/lib";

use IO::File;
use Net::DNS;

use vars qw( $ping_switch_hash $smdmf $smdmfh );

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

use SshSwcon;
my ($date,$time)=SshSwcon::date_time();
my $start_time = "$date $time";

#my $tmpf  = "$installpath/forensic/switches/swseeker.out";
#my $tmpfh = IO::File->new(">>$tmpf");

if (!@ARGV)  { 
  help();  
  exit;
}
my $args;
@$args = @ARGV;
my ($command,     # special 1st arg
    $bldg,        # switchname prefix
    $cfgcmdfile,   # for swchangeconfig - the commands we're running
    $switchfile,   # for swchangeconfig - the switches we're running them on
   );

my $test;   ## used to set up a test hash of switches just below
my $update; ## used to update configs that have old save dates. Use with ../util/swcfgcheck; creates swcfg.update;
$command = $args->[0];
for (my $i=0; $i< scalar(@$args); $i++)  {
   if ($args->[$i] =~ /\A-t|-test\zi/)    { $test   = 1; }
   if ($args->[$i] =~ /\A-u|-update\zi/)  { $update = 1; }
   if ($args->[$i] eq "-b")  {
      $i++;
      while (($args->[$i] !~ /\A-/) && ($i< scalar(@$args)))  {
         $bldg .= "$args->[$i] ";
         # print "b: $bldg\n";
         $i++;
      }
   }
}
## if running swconfigchange grap switch and command files
for (my $i=0; $i< scalar(@$args); $i++)  {
   if ($args->[$i] eq "-cf")  { $cfgcmdfile = $args->[$i+1]; }
   if ($args->[$i] eq "-sf")  { $switchfile = $args->[$i+1]; }
}

require "$installpath/lib/servers.pl";
my $dns1 = dns1();
my $dns2 = dns2();
my $dns3 = dns3();
my $domain = dnssuffix();

if ($test)  {
   ### Test hash - edit as needed for your current test
   $ping_switch_hash->{"10.100.32.64"} = 'mrh-fdf-f2';
}
elsif ($update)  {
   my $updatef  = "$installpath/util/swcfgcheck.out";
   my $updatefh = IO::File->new("$updatef");
   while (my $ln = <$updatefh>)  {
      my (undef,$swip,$swname) = split " ", $ln;
      $ping_switch_hash->{$swip} = $swname;     
   }
}
elsif  ($command eq "swping")  {
   ## Get ALL switch entries from DNS -- we'll ping 'em
   my ($swip,$swname);
   my $res  = Net::DNS::Resolver->new;
   $res->nameservers($dns1,$dns2,$dns3);
   my @zone = $res->axfr("switch.$domain");
   foreach my $rr (@zone) {
      unless ($rr->type eq "A")  { next; }
      $swip   = $rr->address;
      my $full_name = $rr->name;
      ($swname) = split /\./, $full_name, 2;
      $ping_switch_hash->{$swip} = $swname;
   }
}
elsif  ($command eq "vgping")  {
   ## Get ALL vg entries from DNS -- we'll ping 'em
   my ($swip,$swname);
   my $res  = Net::DNS::Resolver->new;
   $res->nameservers($dns1,$dns2,$dns3);
   my @zone = $res->axfr("vg.$domain");
   foreach my $rr (@zone) {
      unless ($rr->type eq "A")  { next; }
      $swip   = $rr->address;
      my $full_name = $rr->name;
      ($swname) = split /\./, $full_name, 2;
      $ping_switch_hash->{$swip} = $swname;
   }
}
elsif  ($command eq "vgreload")  {
   ## Get pingable VGs
   my $query = "SELECT * from switch.vgping where ping = '1';" ;
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   my $sel_ary = $select_h->fetchall_arrayref;
   foreach my $rec (@$sel_ary)  {
      my ($swname,$swip,undef) = @$rec;
      $ping_switch_hash->{$swip} = $swname;
   }   
}
else  {   ## This is the real production run:
   ## Get pingable switches
   my $query = "SELECT * from switch.ping where ping = '1';" ;
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   my $sel_ary = $select_h->fetchall_arrayref;
   foreach my $rec (@$sel_ary)  {
      my ($swname,$swip,undef) = @$rec;
      $ping_switch_hash->{$swip} = $swname;
   }
}

my $switch_hash;
if ($bldg)  {
  my $bldgs;
  @$bldgs = split " ", $bldg;
  while (my($x,$y) = each(%$ping_switch_hash))  {
     foreach my $b (@$bldgs)  {
        if ($y =~ /\A$b/)   {  $switch_hash->{$x} = $y;  }
     }
  }
}
else  {  %$switch_hash = %$ping_switch_hash;  }

## if swchangeconfig, override %$switch_hash with swchangeconfig -sf info
if ($command eq "swchangeconfig")  {
   my $swf  = "$installpath/bin/$switchfile";
   my $swfh = IO::File->new("$swf");
   if ($swf !~ /all/i)  {   ## because if we want "all," we don't want to override the default %$switch_hash
      undef %$switch_hash;
      while (my $ln = <$swfh>)  {
         my ($swname,undef) = split " ", $ln;
         ## clean off the '.cfg' if fle references .cfg names:
         $swname =~ s/\.cfg//;
         $switch_hash->{$swname} = 1;  ## we don't have the IP here - no big deal - connect via swname
      }
   }

}

my $rtr_hash;
if ($command =~ /swmisc|swcdp|swmac/)  {
   my $query = "SELECT * from rtr.ping where ping = '1';" ;
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      foreach my $rec (@$sel_ary)  {
         my ($rname,$rip,undef) = @$rec;
         $rtr_hash->{$rip} = $rname;   ## FIX
      }   
      $switch_hash = { %$switch_hash, %$rtr_hash };
   }      
}
##
while (my($x,$y) = each(%$switch_hash))  {  print "$y\t$x\n";  }
##

if    ($command eq "swmac")          { swmac();     }
elsif ($command eq "swvlan")         { swvlan();    }
elsif ($command eq "swping")         { swping();    }
elsif ($command eq "vgping")         { vgping();    }  ## switch_hash loads only VGs
elsif ($command eq "vgreload")       { swreload();  }  ## switch_hash loads only VGs
elsif ($command eq "swcdp")          { swcdp();     }
elsif ($command eq "swconfig")       { swconfig();  }
elsif ($command eq "swcfgproc")      { swcfgproc(); }
## elsif ($command eq "swpsec")         { swpsec();    }
## swpsec    - calls script swpsec.pl checks port-security configuration 
elsif ($command eq "swmisc")         { swmisc();    }
elsif ($command eq "swchangeconfig") { swchangeconfig($cfgcmdfile); }
else  {
   print "\n * * *\nUnknown command \"$command\" sent to script!\n\n";
   help();
}

print "\n bye bye....\n";
$dbh->disconnect();

exit;

###############

sub swmac  {

   $SIG{CHLD} = 'IGNORE';

   my $i;
   foreach my $swip (keys %$switch_hash)  {
      my $swname = $switch_hash->{$swip};
      if ($swname =~ /vg224/)  { next; }
      my ($psck,$kill);
      my $hitline = "swmac.pl $swip $swname";
      @$psck = `ps ux | grep "$hitline" `;
      foreach my $ps (@$psck)  {
         if ($ps =~ /grep/)  {  next;  }   ## get rid of the self-referential line
         if ($ps =~ /$hitline/)  {  $kill++;  }  ## this shows it's already running
      }
      if ($kill == 0)  {                         ## it's not running, so let's run a new one
         unless ( fork() ) {    ## execute, don't wait for status
            exec ("$installpath/bin/swmac.pl", "$swip", "$swname", "&");
            exit (0); 
         }
      }    
      #else  { print "cannot process seekmacs.pl $swip $swname\n"; }
      $i++;
      if ($i == 152)  {
         sleep 23;
         $i = 0;
      }
   } ## foreach switch
   return;
}  ## swmac

#######################

sub swvlan  {

   $SIG{CHLD} = 'IGNORE';

   my $i;
   foreach my $swip (keys %$switch_hash)  {
      my $swname = $switch_hash->{$swip};
      if ($swname =~ /vg224/)  { next; }
      my ($psck,$kill);
      my $hitline = "swvlan.pl $swip $swname";
      @$psck = `ps ux | grep "$hitline" `;
      foreach my $ps (@$psck)  {
         if ($ps =~ /grep/)  {  next;  }   ## get rid of the self-referential line
         if ($ps =~ /$hitline/)  {  $kill++;  }  ## this shows it's already running
      }
      if ($kill == 0)  {                         ## it's not running, so let's run a new one
          unless ( fork() ) {    ## execute, don't wait for status
            exec ("$installpath/bin/swvlan.pl", "$swip", "$swname", "&");
            exit (0);
          }
      }
      $i++;
      if ($i == 152)  {
         sleep 23;
         $i = 0;
      }
   } ## foreach switch
}  ## swvlan

#######################

sub swmisc  {

   $SIG{CHLD} = 'IGNORE';

   my $i;
   foreach my $swip (keys %$switch_hash)  {
      my $swname = $switch_hash->{$swip};
      if ($swname =~ /vg224/)  { next; }
      ## none of these process correctly (routers, jupiters, oddballs), so let's skip them:
      if ($swname =~ /^\d{2}.out/)        {  next;  }
      if ($swname =~ /^\d{2}-core\.out/)  {  next;  }
      if ($swname =~ /^\d{2}-\d.out/)     {  next;  }
      if ($swname =~ /ex\d\d00.out/)      {  next;  }
      if ($swname =~ /qfx\d{4}.out/)      {  next;  }
      if ($swname =~ /rrb-370-las1/)      {  next;  }   ## HP ProCurve
      if ($swname =~ /rrb-370-las2/)      {  next;  }   ## HP ProCurve
      ##
      my ($psck,$kill);
      my $hitline = "swmisc.pl $swip $swname";
      @$psck = `ps ux | grep "$hitline" `;
      foreach my $ps (@$psck)  {
         if ($ps =~ /grep/)  {  next;  }   ## get rid of the self-referential line
         if ($ps =~ /$hitline/)  {  $kill++;  }  ## this shows it's already running
      }
      if ($kill == 0)  {                         ## it's not running, so let's run a new one
         unless ( fork() ) {    ## execute, don't wait for status
            exec ("$installpath/bin/swmisc.pl", "$swip", "$swname", "&");
            exit (0);
         }
      }
      #else  { print "cannot process seekmacs.pl $swip $swname\n"; }
      $i++;
      if ($i == 252)  {
         sleep 42;
         $i = 0;
      }
   } ## foreach switch
   return;
}  ## swmisc

#######################

sub swreload  {

  ## mostly used for reloading VGs; child process supports 'AT' option

  my $of  = "$installpath/data/swreload.out";
  my $ofh = IO::File->new(">$of");

  $SIG{CHLD} = 'IGNORE';

  foreach my $swip (keys %$switch_hash)  {
    my $swname = $switch_hash->{$swip};
    unless ( fork() ) {    ## execute, don't wait for status -- 3rd field is table name
      exec ("$installpath/bin/swreload.pl", "$swip", "$swname", "&");
      exit (0);
    }
  }
}  ## swreload

#######################

sub swping  {

  ## Empty switch.ping table
  my $query    = "DELETE from switch.ping;";    
  my $select_h = $dbh->prepare($query);
  $select_h->execute();
  $query = "INSERT INTO switch.ping (swname,swip,ping) VALUES(?,?,?)";
  my $select_h = $dbh->prepare($query);
  $select_h->execute("rundate","$start_time","0");

  $SIG{CHLD} = 'IGNORE';

  foreach my $swip (keys %$switch_hash)  {
    my $swname = $switch_hash->{$swip};
    unless ( fork() ) {    ## execute, don't wait for status -- 3rd field is table name
      exec ("$installpath/bin/swping.pl", "$swip", "$swname", "ping", "&");
      exit (0);
    }
  }
}  ## swping

#######################

sub vgping  {

  ## Empty switch.ping table
  my $query    = "DELETE from switch.vgping;";
  my $select_h = $dbh->prepare($query);
  $select_h->execute();
  ## insert rundate entry
  $query = "INSERT INTO switch.vgping (swname,swip,ping) VALUES(?,?,?)";
  my $select_h = $dbh->prepare($query);
  $select_h->execute("rundate","$start_time","0");

  $SIG{CHLD} = 'IGNORE';

  foreach my $swip (keys %$switch_hash)  {
    my $swname = $switch_hash->{$swip};
    unless ( fork() ) {    ## execute, don't wait for status -- 3rd field is table name
      exec ("$installpath/bin/swping.pl", "$swip", "$swname", "vgping", "&");
      exit (0);
    }
  }
}  ## vgping

#######################

sub swcdp  {
  
  my ($swname,$swip);

  my $pmf  = "$installpath/data/swcdpPhoneMoves.out";
  my $pmfh = IO::File->new(">$pmf");

  $SIG{CHLD} = 'IGNORE';

  my $i;
  foreach my $swip (keys %$switch_hash)  {
    $swname = $switch_hash->{$swip};
    if ($swname =~ /vg224/)  { next; }
    unless ( fork() ) {    ## execute, don't wait for status
      my $of  = "$installpath/forensic/switches/$swname.swcdp";
      my $ofh = IO::File->new(">$of");
      exec ("$installpath/bin/swcdp.pl", "$swip", "$swname", "&");
      exit (0); 
    }    
    $i++;
    if ($i == 252)  {
       sleep 23;
       #sleep 5;
       $i = 0;
    }
  } ## foreach switch
  return;

}  ## swcdp

#######################

sub swcfgproc  {


   $SIG{CHLD} = 'IGNORE';

   my $cfg_path = "$installpath/configs/switches";
   opendir(DIR, $cfg_path) || die "can't opendir $cfg_path: $!";
   my @dirlist = grep /\.cfg\z/ , readdir(DIR);
   my $i;
   foreach my $cfgfile (@dirlist)  {
      #print "$cfgfile\n";
      unless ( fork() ) {    ## execute, don't wait for status
        exec ("$installpath/bin/swcfgproc.pl", "$cfgfile", "&");
        exit (0);
      }
      $i++;
      if ($i == 252)  {
         sleep 23;
         $i = 0;
      }
   }
   return;
}

#######################

sub swconfig  {

  ## 2020-07-01 jackg -- now in use

  my ($swname,$swip);

  $SIG{CHLD} = 'IGNORE';

  my $i;
  foreach my $swip (keys %$switch_hash)  {
    $swname = $switch_hash->{$swip};
    if ($swname =~ /vg224/)  { next; }
    unless ( fork() ) {    ## execute, don't wait for status
      exec ("$installpath/bin/swconfig.pl", "$swip", "$swname", "&");
      exit (0);
    }
    $i++;
    if ($i == 252)  {
       sleep 23;
       $i = 0;
    }
  } ## foreach switch
  return;

}  ## swconfig

#######################

sub swchangeconfig  {

  my $cfgcmdfile = shift;

  print "command file: $cfgcmdfile\n";

#  $SIG{CHLD} = 'IGNORE';

  ## if we're running -sf <file>, the key is a switchname -- the code below follows this
  ## if we're running -sf all, the key is a switch IP, but it will still work fine
  foreach my $swname (keys %$switch_hash)  {
     print "$swname\n";
     unless ( fork() ) {    ## execute, don't wait for status -- 3rd field is table name
        exec ("$installpath/bin/swchangeconfig.pl", "$swname", "$cfgcmdfile", "&");
        exit (0);
     }
  }

}  ## swchangeconfig

#######################

sub help  {

print<<EOF;

swseeker.pl  

Syntax: swseeker.pl <command> [ options ]

commands:
  swmac     - calls script swmac.pl
  swvlan    - calls script swvlan.pl
  swping    - calls script swping.pl w/arg 'ping'    for switch.ping
  vgping    - calls script swping.pl w/arg 'vgping'  for switch.vgping
  vgreload  - calls script swreload.pl (child script supports 'AT')
  swcdp     - calls script swcdp.pl 
  swconfig  - calls script swconfig.pl                      
  swcfgproc - calls script swcfgproc.pl                      
  swmisc    - calls script swmisc.pl 
  swchangeconfig - calls swchangeconfig.pl, uses -cf <command file> and -sf <switch file> 
EOF

print<<EOF;


options:
  -b <building prefix> front-end of a switch name, which starts with a building,
                       but you're not limited to that. You can add more.
                   *** This allows PARTIAL RUNS for quick data ***   
EOF

}

#!/usr/bin/perl
## jackg@uic.edu 
##
## fw-PAconfig.pl - grab and save configs from Palo Alto firewalls
##

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use lib "$installpath/lib";
use SshPa;   
use IO::File;
use strict;

my ($date,$time)=date_time();
my $of  = "$installpath/forensic/firewalls/fw-PAconfig.out";
my $ofh = IO::File->new(">$of");

#print $ofh "installpath >$installpath< \n";
unshift @INC, "$installpath/lib";
my $inc = join " ", @INC;
#print $ofh "\@INC: $inc\n";

require "$installpath/lib/PaloAltos.pl";
use vars qw(%PaloAltos);

my $session;
foreach my $fwip (keys %PaloAltos)  {   
   my $fw = $PaloAltos{$fwip};
   my ($fwname,undef,undef,undef) = split /\./, $fw; 
   #print $ofh "processing $fwname\n";
   my $cfgf  = "$installpath/configs/firewalls/$fwname.cfg";
   my $cfgfh = IO::File->new(">$cfgf");
   $session = SshPa->new($fwip);
   my $conret = $session->connect;    # no enable on Pa
   my $cmdret = $session->command("set cli pager off");
   my $command = "show config running ";
   my $cmd_ret = $session->command($command);
   $session->close;  
   foreach my $cr (@$cmd_ret)  {
      chomp($cr);
      if ($command eq "$cr")  {  next;  }
      print $cfgfh "$cr\n";  
   }
   print "\n";
}

exit;

###################################################

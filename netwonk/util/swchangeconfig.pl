#!/usr/bin/perl
#jackg@uic.edu 

# swchangeconfig.pl - child process of swseeker.pl
#
# make changes on a switch config.                  
# commands to be added are in a file
#

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/util//;

use SshSwcon;
use IO::File;
my $outf  = "$installpath/data/swchangeconfig.log";
my $outfh = IO::File->new(">>$outf");

if (!defined @ARGV)  {  help();  exit;  }
if ( grep /-h/ , @ARGV )  {  help();  exit;  }

my $swname = $ARGV[0];
my $cmdf   = $ARGV[1];

my $date = `date`;
print $outfh "Start: $date\n";

my $cmdfh;   # file of commands 
if (-r $cmdf)  {
   $cmdfh = IO::File->new("$cmdf");
   print "found readable command file $cmdf\n";
   print "output printed to $installpath/data/swchangeconfig.log\n";
}
else  {
   print "No luck finding readable command file $cmdf\n";
   print $outfh "No luck finding readable command file $cmdf\n";
}

## Connect to switch
print "connecting to $swname:\n";
my $session = SshSwcon->new($swname);
my $state = $session->connect();
my $ena_ret;
if ($state ne "enabled")   {  $ena_ret = $session->enable();  }
$session->command("term len 0",0);
$session->command("conf t",0);

my $cmdfh = IO::File->new("$cmdf");
while (my $cmd = <$cmdfh>)  {
   chomp($cmd);
   $session->command("$cmd",0);
}
$session->command("end",0);
$session->command("wr",0);
print "\n";
print "\n";
$session->close;

$date = `date`;
print $outfh "End: $date\n";
print $outfh "========================================================\n";

exit;

###################

sub help  {

  print "\n\n";
  print "swchangeconfig.pl - child process of swseeker.pl, can run solo\n\n";
  print "Syntax:  swchangeconfig.pl  <switch name>   <command file>   \n\n";
  print "Command file is a series of lines *exactly* as they would be typed into a session.\n\n";
}

###################

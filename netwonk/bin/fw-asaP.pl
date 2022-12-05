#!/usr/bin/perl 
#jackg@uic.edu 

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use lib "$installpath/lib";
use Sshcon;
use Net::DNS;

require "$installpath/lib/contextmap.pl"; 

my $args;
@$args = @ARGV;
my $ahash = $args->[0];  ## name of a hash inside contextmap, holds $aip, $context
my $acmd  = $args->[1];  ## for running one command only

my $cmds;
if (($acmd eq "xlate") || ($acmd eq "arp"))  {  push @$cmds, $acmd;  }
else  {  @$cmds = ("xlate","arp");  }     ## when $acmd is left blank - common use

my ($aip,$aname,$context);
      
   no strict;   ## for the variable hash name %{"$ahash"}   :-P
while (my ($aip,$aname) = each(%{"$ahash"}) )  {
#print "$ahash: $aip $aname\n";
   use strict;  ## OK, that was it.  :-D
   my ($context,undef) = split /-/, $aname;
   foreach my $cmd (@$cmds)  {
      ## check if it's already running asaC.pl for this, otherwise run: proc_context $cmd  
      my ($psck,$kill);
      my $hitline = "asaC.pl $aip $context $cmd";
      @$psck = `ps ux | grep "$hitline" `;
      foreach my $ps (@$psck)  {
         if ($ps =~ /grep/)  {  next;  }   ## get rid of the self-referential line
         if ($ps =~ /$hitline/)  {  $kill++;  }  ## this shows it's already running
      }
      if ($kill == 0)  {                         ## it's not running, so we don't kill it
         print "Processing $context $cmd\n";
         proc_context($aip,$aname,$context,$cmd);
      }
      else  { print "Cannot process $context $cmd -> already running\n";  }
   }
}  ## while

exit;

########################

sub proc_context  {

   my $aip     = shift;
   my $aname   = shift;
   my $context = shift;
   my $cmd     = shift;

   $SIG{CHLD} = 'IGNORE';
   unless ( fork() )  { 
     exec ("$installpath/bin/fw-asaC.pl", "$aip", "$context", "$cmd", "&");
     exit (0);
   }

   return;
 
}  ## context

########################


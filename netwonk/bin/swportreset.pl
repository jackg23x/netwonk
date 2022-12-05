#!/usr/bin/perl
## jackg@uic.edu 
##
## swportreset.pl


use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use lib "$installpath/lib";
use SshSwcon;
use IO::File;

require "$installpath/lib/servers.pl";
my $logpath = nwlogpath();
my $of  = "$logpath/swportreset.log";
my $ofh = IO::File->new(">>$of");

my ($date,$time)=SshSwcon::date_time();
my $tstamp = "$date $time";

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

my $args;
@$args = @ARGV;

my $netid;
my $errorlines;  ## array ref 
my ($query,$table);
if ($args->[0] =~ /weekly/i)  {  $table = "switch.errdis";         }
elsif ($args->[0] =~ /Q/i)    {  $table = "network.swportresetQ";  }
elsif ($args->[0] =~ /p/i)    {  
   my $swname = $args->[1];
   if ($swname eq "")  {
      print "\n   syntax:  swportreset.pl p <switch_name> <port> [optional <netid>]\n";
      print "   ...no switch name supplied - exiting...\n\n";
      exit;
   }
   my $port   = $args->[2];
   if ($port eq "")  {
      print "\n   syntax:  swportreset.pl p <switch_name> <port> [optional <netid>]\n";
      print "   ...no port supplied for switch $swname - exiting...\n\n";
      exit;
   }
   $netid     = $args->[3]; 
   if ($netid eq "")  {  $netid = "console";  }
   print "\n console - single port reset process: $swname $port $netid $tstamp\n";
   process($swname,$port,$netid,$tstamp);
   exit;
}
else                   {  
   print <<EOF;

   swportreset.pl - automates switch port resets
   usage:
   swportreset.pl Q                                        ## process the network.swportresetQ table
   swportreset.pl weekly                                   ## process the switch.errdis table 
   swportreset.pl p <switchname> <port> [optional <netid>] ## reset a single port from the console 

EOF
   exit;
}
$query = "SELECT * FROM $table;";
print "$query\n";
my $select_h  = $dbh->prepare($query);
$select_h->execute();
if ($select_h->rows != 0) {
   my $sel_ary = $select_h->fetchall_arrayref;
   ## we have collected the entries, so let's clear the table 
   my $delete_h = $dbh->prepare("DELETE FROM $table;");
   $delete_h->execute();
   ## process the new entries
   foreach my $row (@$sel_ary)   {
      my ($swname,$port);
      if ($args->[0] eq "weekly")  {
         (undef,$swname,$port,undef,undef) = @$row; 
         $netid = "network";
      }
      else  {  ($swname,$port,$netid) = @$row;  }         
      print "\nprocess: $swname $port $netid $tstamp\n";
      process($swname,$port,$netid,$tstamp);
   }
}
else  {     ## empty table
   if ($args->[0] eq "weekly")  {  print " = no entries in switch.errdir table =\n";       }
   else                   {  print " = no entries in network.swportresetQ table =\n";  }
} 
print "\n";

if ($errorlines)  {  
   print $ofh "= $tstamp  swportreset.pl run\n";
   mail_it($errorlines,$netid);  
}

exit;

######################################################

sub process  {

   my $swname = shift;
   my $port   = shift;
   my $netid  = shift;
 
   ## Connect to switch

   require "$installpath/lib/core_routers.pl";
   my $routeripprefix = routeripprefix();
   my ($session,$swip);
   if ($swname =~ /\A30|40\z/)  {
      my $swip = "$routeripprefix.$swname";
      $session = SshSwcon->new($swip);
   }
   else  {  $session = SshSwcon->new($swname);  }
   my $state = $session->connect();
   if ($state eq "notconnected")   {
      print "*** cannot connect to $swname ***\n";
      my $insert_h = $dbh->prepare('INSERT into network.swportresetfail (swname,port,netid,tstamp,comment) VALUES(?,?,?,?,?)');
      $insert_h->execute($swname,$port,$netid,$tstamp,"noconnect");
      return; 
   }  
   my $ena_ret;
   if ($state ne "enabled")   {  $ena_ret = $session->enable();  }
   $session->command("term len 0",1);
   ## now down/up the port to fix it
   $session->command("conf t",1);
   my $retary = $session->command("interface $port",1);
     my $retstr = join " ", @$retary;
     print "\n interface return string >$retstr< \n";
     if ($retstr =~ /Invalid|Incomplete/i)  {
        $session->command("end",1);
        $session->close;
        my $insert_h = $dbh->prepare('INSERT into network.swportresetfail (swname,port,netid,tstamp,comment) VALUES(?,?,?,?,?)');
        $insert_h->execute($swname,$port,$netid,$tstamp,"invalid port identifier");
        return;
     }
   $session->command("shutdown",1);
   sleep(1);
   $session->command("no shutdown",1);
   $session->command("end",1);
   $session->close;
   sleep(1);
  
   ## check for successful port reset
   my ($leport,$l2,$lstatus,$lreason,$l5);   ## field lengths - defined in the headers data return only
   my $errlines = $session->command("show interface $port status err");
   foreach my $err (@$errlines)  {
      if ($err =~ /show/)      {  next;  }   ## the command reflection line
      if ($err =~ /Invalid/i)  {  next;  }   ## the command reflection line
      if ($err =~ /\s*--/)     {  next;  }   ## divider line
      if ($err =~ /\A\s*\z/)   {  next;  }   ## blank line
      if ($err eq "")          {  next;  }   ## blank line
      if ($err =~ /\#\s*\z/)   {  next;  }   ## if it ends in '#' it must be a return line
      my ($eport,$f2,$status,$reason,$f5);
      if ($err =~ /Port/)  {
         $err =~ s/-/_/g;
         $err =~ s/(\w)\s(\w)/$1_$2/g;  ## glues together any multi-word field, like Name, usually
         # analyze lengths in this header line:     Port  Name  Status  Reason   Err-disabled_Vlans
         # changed to \s* on 2021-09-20; it's greedy, should be fine, correct loss of last field
         ($eport,$f2,$status,$reason,$f5) = $err =~ m/(\w+\s*)/g;
         $leport=length($eport); $l2=length($f2); $lstatus=length($status); $lreason=length($reason); $l5=length($f5);
         if ($leport < 2)  {  next;  }   ## glitchy switch return
         if ($lreason == 0)  {  $lreason = 20;  }  ## kludge fix for weird short status switches
      }
      else  {
         ($eport,$f2,$status,$reason,$f5) = unpack("a$leport a$l2 a$lstatus a$lreason a$l5",$err);
         $eport   =~ s/\s+//g;
         $reason =~ s/\s+//g;
         $reason =~ s/^led//;  ## 6500 text return formatting kludge -  not worth fixing just for comrb! :)
         push @$errorlines, "$swname $port $status $reason $netid";
         if ($status =~ /err/)  {
            ## network.swportresetfail is a log of all failed portresets done here - as of 2022-02-11 (table init day)           
            my $insert_h = $dbh->prepare('INSERT into network.swportresetfail (swname,port,netid,tstamp,comment) VALUES(?,?,?,?,?)');
            $insert_h->execute($swname,$port,$netid,$tstamp,$reason);
         }
         else  {
            print "\nPORTRESETLOG $tstamp\n";
            ## network.swportresetlog is a log of all portresets done here - as of 2021-09-20 *successful* resets only.  
            my $insert_h = $dbh->prepare('INSERT into network.swportresetlog (swname,port,netid,tstamp) VALUES(?,?,?,?)');
            $insert_h->execute($swname,$port,$netid,$tstamp);
         }
      }
   }

} ## process 

##################################

sub mail_it  {

   my $errorlines = shift;
   my $netid      = shift; 

print "> $installpath < \n";

require "$installpath/lib/servers.pl";
my $user      = user();
my $admin     = admin();
my $voipadmin = voipadmin();
my $mailer    = scriptserver();
my $dbserver  = dbserver();
my $webserver = webserver();
my $domain    = dnssuffix();
my $netmgr    = netmgr();
my $neteng    = neteng();
open (SENDMAIL, "|/usr/lib/sendmail -oi -t -odq") or die "Can't fork for sendmail: $!\n";
print SENDMAIL "From: Portus Resetus <$user\@$mailer>\n";
if ($args->[0] eq "weekly") {  print SENDMAIL "To: netmgr <$netmgr\@$domain>, neteng <$neteng\@$domain>, admin <$admin\@$domain>\n";  }
else                        {  print SENDMAIL "To: $netid <$netid\@$mailer> <$admin\@$domain>\n";  }
print SENDMAIL "Subject: Process Run: swportreset.pl $args->[0] run\n\n";

if ($args->[0] eq "weekly")  {  print SENDMAIL "= $tstamp  swportreset.pl weekly run of table switch.errdis\n";  }
else                   {  print SENDMAIL "= $tstamp  swportreset.pl cyclic run of table network.swportresetQ\n";  } 
foreach my $eln (@$errorlines)  {
   my($swname,$port,$status,$reason,$netid) = split " ", $eln;
   printf $ofh "%-20s\t%-8s\t%-16s\t%-12s\t%12s\n",$swname,$port," After reset: ",$status,$reason;
   print SENDMAIL "$swname  $port  -  After reset:  $status  $reason\n";
}

print SENDMAIL "\n\n";
print SENDMAIL "$mailer:swportreset.pl\n";
print SENDMAIL "$webserver:errdis.cgi\n";
print SENDMAIL "$dbserver:network.swportresetQ\n";
print SENDMAIL "$dbserver:network.swportresetlog\n";
print SENDMAIL "$dbserver:switch.errdis\n\n";
print SENDMAIL "Yours in Network happiness,\n Portus Resetus\n"; 
close(SENDMAIL)  or warn "sendmail didn't close nicely";
print "mail_it completed\n";

}  ## mail_it

###################################################


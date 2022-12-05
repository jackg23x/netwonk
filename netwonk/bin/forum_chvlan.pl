#!/usr/bin/perl
## jackg@uic.edu 
##
## changes vlan assignment on specific switches
##
##
##

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use lib "$installpath/lib";
use SshSwcon;

my ($date,$time)=SshSwcon::date_time();
my $tstamp = "$date $time";

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

## Deal with parms:
if (!@ARGV)  {  help();  exit;  }
if ( grep /-h / , @ARGV )  {  help();  exit;  }

my @args = @ARGV;
my $arg1 = shift @args;    ## SHIFT #1

my ($swname,$port,$vlan,$netid);
if ($arg1 eq "Q")  {
   my $query = "SELECT * FROM network.forum_chvlanQ;";
   my $select_h = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows == 0) {
      print " = no entries in forum_chvlanQ table =\n";
      exit;
   }
   my $sw_hash;
   print "\n";
   ## we have collected the entries, so let's clear the table:
   my $sql_cmd  = "DELETE from network.forum_chvlanQ ";
   my $delete_h = $dbh->prepare($sql_cmd);
   $delete_h->execute();
   ## now process the entries we collected:
   ## switch_hash->{switch}->{newvlan} = @ports
   my $sel_ary = $select_h->fetchall_arrayref;
   foreach my $rec (@$sel_ary)  {
      ($swname,$port,$vlan,$netid) = @$rec;
      print "processing:  $swname  $port $vlan $netid\n";
   }
}
else  {
   $swname = $arg1;
   $port   = shift @args;
   $vlan   = shift @args;
   $netid  = "manual";
}

print "TEST: >$swname<  >$port<  >$vlan<  >$netid< ";

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
if ($state eq "notconnected")   {  return;  }
my $ena_ret;
if ($state ne "enabled")   {  $ena_ret = $session->enable();  }
$session->command("conf t");
$session->command("interface $port");
$session->command("switchport access vlan $vlan");
$session->command("end");
$session->command("write mem");
$session->close;

my $sql_cmd  = "INSERT INTO network.forum_chvlan (swname,port,vlan,netid,tstamp) VALUES (?,?,?,?,?)";
my $insert_h = $dbh->prepare($sql_cmd);
$insert_h->execute($swname,$port,$vlan,$netid,$tstamp);

my $update_h;  # update existing row in switch.vlan
$update_h = $dbh->prepare("UPDATE IGNORE switch.vlan SET vlan=? WHERE swname = \"$swname\" AND port = \"$port\" ;" );
$update_h->execute($vlan);

print "\n";
mail_it();

exit;

############################

sub mail_it  {

require "$installpath/lib/servers.pl";
my $user   = user();
my $admin  = admin();
my $mailer = scriptserver();
my $domain = dnssuffix();
open (SENDMAIL, "|/usr/lib/sendmail -oi -t -odq")
                or die "Can't fork for sendmail: $!\n";

print SENDMAIL <<"EOF";
From: Portus Alterus Forum <$user\@$mailer>
To: netadmin <$admin\@$domain>
EOF

## To: jackg <netgrp\@uic.edu> 
## EOF


print "TEST: $tstamp: $swname port $port to $vlan by $netid\n";

print SENDMAIL "$tstamp: $swname port $port to $vlan by $netid\n";
print SENDMAIL "\n";

print SENDMAIL <<"EOF";
Yours in Network Alterations,
Portus Alterus Forum

EOF

close(SENDMAIL)  or warn "sendmail didn't close nicely";

print "mail_it completed\n";

}  ## mail_it

###################################################

sub help {

  my $manual = shift;

if ($manual)  {
  print <<EOF;
  Manual process -> forum_chvlan.pl <switchname> <port> <new_vlan> 

EOF
}  ## if
else  {
  print <<EOF;

  forum_chvlan.pl

  Changes a the vlan assignment for a single port on a switch in
  the Forum.  

  syntax:
 
  Using table   -> forum_chvlan.pl Q  
        (uses world.cc network.forum_chvlanQ)

  Manual change -> forum_chvlan.pl <switchname> <port> <new_vlan>

EOF
print "\n";
}  ## else
}  ## help

####################################################


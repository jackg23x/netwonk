#!/usr/bin/perl
## jackg@uic.edu 
##

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/util//;

use lib "$installpath/lib";
use Sshcon;

use IO::File;
my $jf  = "$installpath/util/sctx-out";
my $jfh = IO::File->new(">$jf");

#my $ip = "10.100.39.132";   ## asa-stretch-w1
#my $ip = "10.100.39.149";   ## asa4140-west

require "$installpath/lib/contextmap.pl";
use vars qw( %dept4140 );

while (my ($ip,$asa) = each(%dept4140))  {
   print $jfh "$ip  $asa  ";  
   my ($session);
   $session = Sshcon->new($ip);
   my $conret = $session->connect;
   ## $session->enable(); # not needed
   my $out = $session->command("show checksum");
   # print $jfh "conret: >$conret<    out: >", @$out, "< \n"; 
   if ($out->[0] eq "")  {  print $jfh "NO  $conret\n";  }
   else  { print $jfh "YES  \n"; }
   $session->command("quit");
   $session->close;
}
exit;

######
######

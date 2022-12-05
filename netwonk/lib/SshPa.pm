package SshPa;
# Jack Gallagher     
#
#

use Exporter;
@ISA = ("Exporter");
@EXPORT = qw (
               date_time
             );

use strict;
use Socket;      # for the whole ntoa thing in 'sub new'
use Expect;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

## replace these subroutine invocations with your secure password apps:
require "$installpath/lib/PWtest.pl";
my $user = Pauser();
my $pswd = Papw();

my ($session,$self);
my $timeout = 10;  ## backup

######################################

sub new {

    my $class = shift;
    my $self;
    my $arg = shift || '';  ## ip/dn to connect to

    my $af_inet = "AF_INET";
    if ($arg =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {
       $self->{ip} = $arg;
       $self->{name} = gethostbyaddr(inet_aton($self->{ip}), $af_inet) || undef;
    }
    else {
       $self->{name} = lc $arg;
       my (undef,undef,undef,undef,@addrs) = gethostbyname($self->{name});
       $self->{ip} = (scalar @addrs) ? inet_ntoa($addrs[0]) : undef;
    }

    $self = bless {
                ip     => $self->{ip},
                name   => $self->{name},
            }, $class;

    return $self;
}

######################################

sub connect {

my $self    = shift;

my ($before,$match,$after,$command);

   ## try SSH first
   $session = new Expect;  ## $session is global to the module
   $session->raw_pty(1);  
   $command = "ssh $user\@$self->{ip}";
   $session->spawn($command)   or die "Cannot spawn $command: $!\n";
   sleep(9);
   $session->expect($timeout, "-re", ":\s*");
   $before = $session->before();
   $match  = $session->match();
   $after  = $session->after();
   #print "before connect =>$before<=\n\n";
   #print "match connect =>$match<=\n";
   #print "after connect =>$after<=\n\n";
   my $ret_code;
   $session->clear_accum(); ## get rid of any old data in the accumulator buffer
   $session->send_slow(0,"$pswd\n");  ## BTW, you definitely need the '\n' here
   #my @match_patterns = (">\s*","#\s*");
   my @match_patterns = (">\s*");
   $session->expect($timeout,"-re",@match_patterns);
   $before = $session->before();  #print "\nbefore exec =>$before<=\n";
   my $state;
   if ($before =~ /passive\)$/)  {  $state = "passive";  }  
   if ($before =~ /active\)$/)   {  $state = "active";   }  
   $match  = $session->match();   #print "match exec =>$match<=\n";
   $after  = $session->after();   #print "after exec =>$after <=\n\n";
   if ($match eq ">")  { return("connect $state"); }
   else                { $ret_code = "notconnected"; }
   if ($ret_code eq "notconnected")    {  return("notconnected");  }

   return;
}  ## connect

#######################################

sub command  {

  ## this runs any arbitrary command - WATCH IT!!!
  my $self = shift;
  my $arg  = shift;
  $timeout = shift || 10; 

  # print "\nARG = >$arg<     TIMEOUT = >$timeout<\n";
  # print "SELF = >", %$self, "\nARG = >$arg<\nTIMEOUT = >$timeout<\n";

  $session->clear_accum(); 
  $session->send_slow(0,"$arg\n");
  $session->expect($timeout, "-re", "#\\s*");
  my $match = $session->match;
  my $before = $session->before();
  $before =~ s/\cM//g;   ## Cisco line end
  ## $before =~ s/\r//g;
  my $output;
  @$output = split(/\n/, $before);

  return ($output);

}  ## command

#######################

sub close  {

   my $self = shift;
   my $session = $self->{ip};
   $session = Expect->close();

}  ## close

####################

sub date_time  {

   ## Returns string with Date and Time as:
   ##  "mm/dd/yy hh/mm/ss"
   my ($sec,$min,$hour,$mday,$mon,$year,undef,undef,undef) = localtime(time);
   $mon += 1;
   if ($mon  < 10) { $mon  = "0"."$mon"; }
   if ($mday < 10) { $mday = "0"."$mday"; }
   # Y2K fix:
   my $yr=1900+$year;
   my $date = "$yr-$mon-$mday";
   if ( $hour < 10 )  { $hour = "0"."$hour"; }
   if ( $min  < 10 )  { $min  = "0"."$min"; }
   if ( $sec  < 10 )  { $sec  = "0"."$sec"; }
   my $time = "$hour:$min:$sec";

   ## for this script, we split 'em!!
   return($date,$time);

}  ## date_time

###################

## The final return:

1;  # Because you MUST!


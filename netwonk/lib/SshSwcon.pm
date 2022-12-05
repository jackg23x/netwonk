package SshSwcon;
# Jack Gallagher

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
$installpath =~ s/\/util//;
#print "installpath >$installpath<\n";

## replace these subroutine invocations with your secure password apps:
require "$installpath/lib/PWtest.pl";
my $exe1 = swexe1();
my $ena1 = swena1();
my $exe2 = swexe2();
my $ena2 = swena2();

my @exes = ($exe1,$exe2);
my @enas = ($ena1,$ena2);

#### author local net kludge
my $exe3 = rtexe2();  push @exes,$exe3;
my $ena3 = rtena2();  push @enas,$ena3;
########## end kludge

my ($session,$self);
my $timeout = 10;  ## default/backup

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
   $session->clear_accum(); ## get rid of any old data in the accumulator buffer
   $session->raw_pty(1);  
   $command = "ssh netadmin\@$self->{ip}";
   $session->spawn($command)   or die "Cannot spawn $command: $!\n";
   ## sleep(9);
   $session->expect($timeout, "-re", ":\s*");
   $before = $session->before();
   $match  = $session->match();
   $after  = $session->after();
   # print "before connect =>$match<=\n";
   # print "match connect =>$match<=\n";
   # print "after connect =>$after<=\n\n";

   ## if SSH port is closed, try telnet 
   if ($after =~ /Connection refused|Connection closed/)  {
      print "Trying telnet\n";
      $session->close();
      $session = new Expect;
      $session->raw_pty(1);
      $command = "telnet $self->{ip} -l netadmin";  
      $session->spawn($command)   or die "Cannot spawn $command: $!\n";
      sleep(3); 
      $session->expect($timeout, "-re", ":\s*");
      $before = $session->before();
      print "telnet before connect =>$before<=\n";
      $match  = $session->match();
      print "telnet match connect =>$match<=\n";
      $after  = $session->after();
      print "telnet after connect =>$after<=\n\n";
      if ($before =~ /Username\z/i)  {
         $session->send_slow(0,"netadmin\n");  
      }
      $session->expect($timeout, "-re", ":\s*");
   }
   
   my $ret_code;
   foreach my $exe (@exes)  {
       print "sending exe >$exe<\n";
      $session->clear_accum(); ## get rid of any old data in the accumulator buffer
      $session->send_slow(0,"$exe\n");  ## BTW, you definitely need the '\n' here
      my @match_patterns = (">\\s*","#\\s*");    ## why the double '\\' ??
      #my @match_patterns = (">\s*","#\s*");
      $session->expect($timeout,"-re",@match_patterns);

      $before = $session->before();
      $match  = $session->match();
      $after  = $session->after();
      # print "\nbefore exec =>$before<=\n";
      # print "match exec =>$match<=\n";
      # print "after exec =>$after<=\n\n";
      if ($after =~ /Offending key/) { my ($date,$time) = date_time(); }
      ##if ($match =~ /#\s*\z/)   {
      if ($match eq "#")             { return("enabled"); }
      elsif ($before =~ /.*#\s*\z/)  { return("enabled"); }
      elsif ($match eq ">")          { return("connect"); }
      else                           { $ret_code = "notconnected"; }
   }  ## foreach
   if ($ret_code eq "notconnected")  {
      return("notconnected");
   }
                   ####return $session;
   return;
}  ## connect

#######################################

sub enable  {

my $self = shift;


my ($before,$match,$after);

   $session->send_slow(0," ena\n");
   $session->expect($timeout, "-re", ":");
   $before = $session->before();
   $match  = $session->match();
   $after  = $session->after();
   ###print "\nbefore sending \"enable\" =>$before<=\n";
   #print "match sending \"enable\"  =>$match<=\n";
   ###print "after sending \"enable\"  =>$after<=\n\n";

   foreach my $ena (@enas)  {
      #print "sending ena >$ena<\n";
      $session->send_slow(0,"$ena\n");
      $session->expect($timeout, "-re", "#");
      $before = $session->before();
      $match  = $session->match();
      $after  = $session->after();
      ###print "before enable send: >$before<\n";
      #print "match enable send: >$match<\n";
      ###print "after enable send: >$after<\n\n";
   
      if ($match eq "#")   {
         print "match = # ==> ena return(\"enabled\")\n";
         return("enabled");
      }
   }  ## foreach
   return;  ## enabled

}

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
  $session->expect($timeout, "-re", ">\\s*");
  my $match = $session->match;
  my $output = $session->before();
  $output =~ s/\cM//g;
  ## $output =~ s/\r//g;
  my @output = split(/\n/, $output);

  return (\@output);

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


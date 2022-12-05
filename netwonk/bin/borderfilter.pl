#!/usr/bin/perl
## jackg - Jack Gallagher
##
## borderfilter.pl
## script to filter/unfilter hosts and networks on border routers
## world database tables:
## - network.borderfilters 
## - network.borderfilterQ 
## - network.borderfilterlog 
## related web script:
## - netfire:/var/www/bluestem-cgi/borderfilter.cgi
##
##

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/bin//;

use lib "$installpath/lib";
use Sshcon;

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});
my ($insert_h,$update_h,$select_h,$delete_h);

## control switches
my $ex = 1;      ## switch to turn on/off execution of config line processing (37/47)
my $db = 1;      ## switch to turn on/off writing to database 
my $pr = 1;      ## switch to turn on/off informational printing
##

my ($date,$time) = date_time();
my $datefilt = "$date $time";

if ($pr) { print "===== borderfilter run: $datefilt\n"; }

## Deal with parms:
if (!@ARGV)  {  help();  exit;  }
if ( grep /-h/ , @ARGV )  {  help();  exit;  }
my $args;
@$args = @ARGV;

my $flags;                   ## array of args control flags
## check for print-only override
my $p0;
for (my $i = 0; $i <= $#$args; $i++ )  {
    if ($args->[$i] =~ /p0/)  {
       $p0 = 1; $pr = 1; $ex = 0; $db = 0;        ## print Only Override
       push @$flags, $args->[$i];
       splice @$args, $i, 1;      ## remove from @args
    }
}
if ($p0 == 0)  {                     ## that is, $p0 is not enabled above
   for (my $i = 0; $i <= $#$args; $i++ )  {
       if ($args->[$i] =~ /-ex0/)  {
          $ex = 0;                   ## turn router execution off
          push @$flags, $args->[$i];
          splice @$args, $i, 1;      ## remove from @args
       }
   }
   for (my $i = 0; $i <= $#$args; $i++ )  {
       if ($args->[$i] =~ /-db0/)  {
          $db = 0;                   ## turn database execution off
          push @$flags, $args->[$i];
          splice @$args, $i, 1;      ## remove from @args
       }
   }
   for (my $i = 0; $i <= $#$args; $i++ )  {
       if ($args->[$i] =~ /-pr0/)  {
          $pr = 0;                   ## turn printing off
          push @$flags, $args->[$i];
          splice @$args, $i, 1;      ## remove from @args
       }
   }
}
if ($pr) {
   print "borderfilter.pl ";
   foreach my $arg (@$args)    {  print "$arg ";   }   print "\n";
   foreach my $flag (@$flags)  {  print "$flag ";  }   print "\n";
   print "\$ex = $ex ::  \$db = $db :: \$pr = $pr \n";
}

my $filt_h;
my $parm    = $args->[0];    ## filter/unfilter/Q
my $address = $args->[1];    ## the address being filtered/unfiltered - blank when 'Q'
if ($address =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {    ##  console host filter
   $filt_h->{$address}->{"addrln"} = "host $address";
}  
elsif ($parm eq "Q")  {
   print "Processing borderfilterQ...\n";
}
elsif ($parm eq "s")  {
   if ($address eq "")  { print "*** No address entered.......exiting!\n";   exit;   }
   else                 { print "Current object-group network ipv4 border-host-filter:\n"; }
}
elsif ($address =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/)  {   ## console network filter
   $filt_h->{$address}->{"addrln"} = $address;
}
else  {
   print "Error in address formatting where \$address = \'$address\'   ...exiting\n\n";
   exit;
}
if ($parm =~ /^f/)  {
   $parm = "filter";   
   $filt_h->{$address}->{"operation"} = $parm;
   $filt_h->{$address}->{"datefilt"}  = $datefilt; 
   $filt_h->{$address}->{"netid"}     = "network";
   $filt_h->{$address}->{"comment"}   = "gregson console";
}
elsif ($parm =~ /^u/)  {
   $parm = "unfilter"; 
   $filt_h->{$address}->{"operation"} = $parm;
   $filt_h->{$address}->{"datefilt"}  = $datefilt; 
   $filt_h->{$address}->{"netid"}     = "network";
   $filt_h->{$address}->{"comment"}   = "gregson console";
}
elsif ($parm =~ /^Q/)  {
   my $query = "SELECT * FROM network.borderfilterQ ORDER by dateQ ASC; ";
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      foreach my $row (@$sel_ary)   {
         my ($address,$operation,undef,$netid,$comment) = @$row;
         if ($address =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)           {  $filt_h->{$address}->{"addrln"} = "host $address";  }   ## host filter
         if ($address =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/)  {  $filt_h->{$address}->{"addrln"} = $address;         }   ## network filter
         $filt_h->{$address}->{"operation"} = $operation;
         $filt_h->{$address}->{"datefilt"}  = $datefilt;
         $filt_h->{$address}->{"netid"}     = $netid;
         $filt_h->{$address}->{"comment"}   = $comment;
      }
   }
}
elsif ($parm eq "s")  {  print "Showing current borderfilters on router:\n";  }
else  {
   print "parameter \"$parm\" not found.\n";
   help();
   exit;
}  

## Console print check of filt_h
foreach my $a (keys %$filt_h)  {
   print "$a\n";  
}
foreach my $a (keys %$filt_h)  {
   foreach my $p (keys %{$filt_h->{$a}})  {  print "filt_h->$a->$p  ", $filt_h->{$a}->{$p}, "\n";  }
}

require "$installpath/lib/border_routers.pl";
use vars qw(%border_routers);
my $session;
my $all_filts_h;  ## filts by ip
my $all_log_h;   ## all log entries added to network.borderfilterlog UNUSED AS OF 2020-12-14
while (my($rip,$rname) = each(%border_routers)) {
   ## Connect
   $session = Sshcon->new($rip);
   my $state = $session->connect();
   if ($state eq "notconnected")  {
      print "CONNECT ERROR: $rname $rip - Session state = $state\n";
      exit;
   }
   if ($parm eq "s")  {  ## SHOW only
      $session->command("terminal length 0",0);
      $session->command("sh conf running-config object-group network ipv4 border-host-filter",1);
      next;     ## we only want to print the filter list for each router
   }
   my $ena_ret;
   if ($state ne "enabled")  { $ena_ret = $session->enable(); }  
   $session->command("terminal length 0");
   foreach my $addr (keys %$filt_h)  {
      my $addrln = $filt_h->{$addr}->{"addrln"};    ##  includes 'host' where needed 
      if ($ex)  {
         $session->command("conf t");
         $session->command("object-group network ipv4 border-host-filter");
         if ($filt_h->{$addr}->{"operation"} eq "filter")    {  $session->command("$addrln");     }
         if ($filt_h->{$addr}->{"operation"} eq "unfilter")  {  $session->command("no $addrln");  }
         $session->command("commit");  
         $session->command("end");
      }  
      ## check process success
      my $proc_ret = $session->command("show config running-config object-group network ipv4 border-host-filter | inc $addrln");
      my $addr_found;
      foreach my $procln (@$proc_ret)  {
         if ($procln =~ /^\s*$addrln/)  {  $addr_found = 1;  } 
      }
      ## vars for borderlog processing
      my $op = $filt_h->{$addr}->{"operation"};
      my $dt = $filt_h->{$addr}->{"datefilt"};
      my $nt = $filt_h->{$addr}->{"netid"};
      my $cm = $filt_h->{$addr}->{"comment"};
      $all_log_h->{"$addr $op $dt $nt $cm"} = 1;
      ## db process
      if ($filt_h->{$addr}->{"operation"} eq "filter")   {
         if ($addr_found == 1)  {
            if ($db)  {                 ## put data into borderfilterslog and borderfilters; clear Queue entry if needed
               ## $all_log_h->{"$addr $op $dt $nt $cm"} = 1;
               $select_h = $dbh->prepare("SELECT * FROM network.borderfilters WHERE address = \"$addr\" LIMIT 1;  ");
               $select_h->execute();
               if ($select_h->rows == 0) { 
                  $insert_h = $dbh->prepare('INSERT IGNORE into network.borderfilters (tstamp,address) VALUES(?,?)');
                  $insert_h->execute($datefilt,$addr);
               }
               $select_h->finish;  ## need this to avoid "disconnect invalidates" trouble with $dbh->disconnect below outer loop
               if ($parm eq "Q")  {
                  $delete_h = $dbh->prepare("DELETE FROM network.borderfilterQ WHERE address = \"$addr\" and operation = \"filter\"; ");
                  $delete_h->execute();
               }
            }
         }
         if ($addr_found == 0)  { 
            print "*** ERROR: No Return of filter success from 'show config' command.  filter $addr not processed to network.borderfilters, not removed from network.borderfilterQ\n";  
         }
      }
      if ($filt_h->{$addr}->{"operation"} eq "unfilter")   {
         if ($addr_found == 0)  {
            if ($db)  {                 ## put data into borderfilterslog, remove from borderfilters; clear entry from Queue if needed
               $addr =~ s/no //;
               # $insert_h = $dbh->prepare('INSERT IGNORE into network.borderfilterlog (address,operation,datefilt, netid,comment) VALUES (?,?,?,?,?)');
               # $insert_h->execute($addr,$filt_h->{$addr}->{"operation"},$filt_h->{$addr}->{"datefilt"},$filt_h->{$addr}->{"netid"},$filt_h->{$addr}->{"comment"});
               # printf "%-16s %-10s %-24s %-8s %-64s \n", $addr,$filt_h->{$addr}->{"operation"},$filt_h->{$addr}->{"datefilt"}, $filt_h->{$addr}->{"netid"},$filt_h->{$addr}->{"comment"};
               $delete_h = $dbh->prepare("DELETE FROM network.borderfilters WHERE address = \"$addr\"; ");
               $delete_h->execute();
               if ($parm eq "Q")  {
                  $delete_h = $dbh->prepare("DELETE FROM network.borderfilterQ WHERE address = \"$addr\" and operation = \"unfilter\"; ");
                  $delete_h->execute();
               }
            }
         }
         if ($addr_found == 1)  {
            print "*** ERROR: Filter Persistent on router from 'show config' command.  unfilter $addr not processed to network.borderfilters, not removed from network.borderfilterQ\n";
         }
      }
   }  ## foreach my addr
}

print "\n";
## filters only -- this avoids duplicates in borderfilterlog --- unfilters inserted above
foreach my $ln (keys %$all_log_h)  {
   my ($addr,$op,undef,undef,$nt,$cm) = split " ", $ln, 6;  ## undefs are the date and time - we'll use the global variable 'datefilt' -- '6' preserves comments
   $insert_h = $dbh->prepare('INSERT IGNORE into network.borderfilterlog (address,operation,datefilt,netid,comment) VALUES (?,?,?,?,?)');
   $insert_h->execute($addr,$op,$datefilt,$nt,$cm); 
   printf "%-16s %-10s %-24s %-8s %-64s \n", $addr,$op,$datefilt,$nt,$cm;
}

$dbh->disconnect();
$session->close();

exit;

##################

sub help  {

print<<EOF;

borderfilter.pl - filtering remote hosts or blocks from UIC access; or, process the borderfilterQ 

syntax:  ./borderfilter.pl  f <ip_address or ip_block>   Process filter from console
         ./borderfilter.pl  u <ip_address or ip_block>   Process unfilter from console
         ./borderfilter.pl  Q                            Process the filter queue
         ./borderfilter.pl  s                            Show the existing filters on the router


EOF

}

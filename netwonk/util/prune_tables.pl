#!/usr/bin/perl
## jackg@uic.edu
##
## prune_tables.pl
## clears out table entries older than a icertain number of days
## as rrefenced in the code
##
##

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/util//;

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

my $script_time = `date`;
my (undef,$M,$D,$T,undef,undef) = split " ", $script_time;
print "#############  prune_it.pl run: $M $D $T  #############\n";

my $limit = 5000000;  ## maximum records to delete at once
my ($table,$where);
my $tables;

## control switches
my $db = 1;      ## switch to turn on/off deleting database records
## my $pr = 1;      ## switch to turn on/off informational printing

require "$installpath/lib/servers.pl";
my $user      = user();
my $admin     = admin();
my $voipadmin = voipadmin();
my $mailer    = scriptserver();
my $domain    = dnssuffix();

my $args;
@$args = @ARGV;
if ($args->[0] eq "")        {  help();  exit;  } 
if ( grep /-h/ , @ARGV )     {  help();  exit;  }
if ( grep /help/ , @ARGV )   {  help();  exit;  }
## check for control variables
for (my $i = 0; $i <= $#$args; $i++ )  {
    if ($args->[$i] =~ /-db0/)  {
       $db = 0;                   ## turn database execution off
       print "No database deletions processed -- informational only\n";
       splice @$args, $i, 1;      ## remove from @args
    }
}
if (@ARGV[0] ne "all")  { 
   $table    = $ARGV[0];
   my $field = $ARGV[1];
   my $days  = $ARGV[2];
   my $where = "date($field) < subdate(curdate(),interval $days day)" ;
   prune_it($table,$where,$limit);
   exit;
}

## "database.table  date_field  number_of_days"
@$tables = (
            "switch.inline       tstamp 11",
            "network.macflap     tstamp 7" ,
            "network.nofree_dhcp tstamp 3" ,
            "fw.xlate            recent 33",
            "fw.arp              recent 33",
            "rtr.arp             recent 33",
            "router.arp          recent 33",
            "switch.mac          recent 33",
            "switch.noconnect    tstamp 7",
           );

my $mailarray;   ## mail text from successful deletes
foreach my $tab (@$tables)  {
   my ($table,$field,$days) = split " ", $tab;
   my $where = "date($field) < subdate(curdate(),interval $days day)" ;
   prune_it($table,$where,$limit);
}
mail_it($mailarray);


exit;

####################################################################

sub prune_it  {

   my $table = shift;
   my $where = shift;
   my $limit = shift;
 
   my $num;  ## number of records in delete request
   my $start_time = `date`;
   my (undef,$mon,$day,$startT,undef,undef) = split " ", $start_time;
   my $start = "$mon $day $startT";
   my $query = "SELECT count(*) FROM $table WHERE $where" ;
   ##print "query: $query\n"; 
   my $select_h  = $dbh->prepare($query);
   $select_h->execute();
   if ($select_h->rows != 0) {
      my $sel_ary = $select_h->fetchall_arrayref;
      $num = $sel_ary->[0]->[0];
      if ($num < $limit) {
         my $query = "DELETE FROM $table WHERE $where";
         my $delete_h = $dbh->prepare($query);
         my $next_time;
         if ($db)  {
            my $db_ret = $delete_h->execute();  
            if ($db_ret eq "0E0")  { $db_ret = 0; }
            $next_time = `date`;
            my (undef,$mon,$day,$endT,undef,undef,undef) = split " ", $next_time;
            my $end = "$mon $day $endT";
            print "*** Processing:  table = $table  records deleted = $db_ret  start = $start  end = $end\n";
            push @$mailarray, "Processing:  table = $table  records deleted = $db_ret  start = $start  end = $end";
            ##mail_it($table,$db_ret,$start,$end);
         }
         else  {
            $next_time = `date`;
            my (undef,$mon,$day,$endT,undef,undef,undef) = split " ", $next_time;
            my $end = "$mon $day $endT";
            print "No db processing:  table = $table  number of records = $num  start = $start  end = $end\n";
         }
      }
      else  {
         my $next_time = `date`;
         my (undef,$mon,$day,$endT,undef,undef,undef) = split " ", $next_time;
         my $end = "$mon $day $endT";
         if ($db)  {  mail_nope($table,$num,$start,$end);  }
         else  {  print "No db processing:  table = $table  number of records = $num(over limit)  start = $start  end = $end\n";  }
      }
   } 
   return;
}

#####################################################################

sub mail_it  {
 
  my $mailarray = shift;

open (SENDMAIL, "|/usr/lib/sendmail -oi -t -odq") or die "Can't fork for sendmail: $!\n";

print SENDMAIL <<"EOF";
From: Mr. Mandrake Root <$user\@$mailer>           
To: admin <$admin\@$domain>
Subject: database deletes from tables 

EOF

foreach my $m (@$mailarray)  { print SENDMAIL "$m\n"; }

print SENDMAIL <<"EOF";

Eat my shorts, man!

Later,
Manny Root

EOF

close(SENDMAIL)  or warn "sendmail didn't close nicely";
return;
}  ## mail_it

##########################################################################

sub mail_nope  {
 
  my $table = shift;
  my $num   = shift;
  my $start = shift;
  my $end   = shift;

open (SENDMAIL, "|/usr/lib/sendmail -oi -t -odq") or die "Can't fork for sendmail: $!\n"; 
print SENDMAIL <<"EOF";
From: Mr. Mandrake Root <$user\@$mailer>
To: admin <$admin\@$domain>
Subject: $num too large to prune from $table on world.cc

Started at   $start
Completed at $end

I would have pruned $num records from $table if I had been allowed to.
$table needs to be manually pruned.

Eat my shorts, man!

Later,
Manny Root

EOF

close(SENDMAIL)  or warn "sendmail didn't close nicely";
return;
}  ## mail_nope

#############################################################################

sub help  {

print<<EOF;

prune_it.pl -- prunes database tables by date intervals

To run the whole pruning facility on all listed tables:
   prune_it.pl all  [options]

To run a specific table:
   prune_it.pl  <database.table> <field> <days>  [options]
   where field = the timestampo field used for deletion limiting, i.e.  'tstamp', 'recent', etc.
         days  = number of days retained; all older records are deleted. Differs by table.

Options:
   -db0 = Do not process database deletions while running the script

EOF
return;
}

#############################################################################

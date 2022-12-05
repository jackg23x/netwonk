#!/usr/bin/perl
#jackg@uic.edu

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/util//;

use IO::File;
my $of  = "./mysql_desc_all.out";
my $ofh = IO::File->new(">$of");

use DBI;
require "$installpath/lib/dbipw.pl";
my ($h,$u,$p) = dbigrabit();
my $dbh = DBI->connect("DBI:mysql:host=$h",$u,$p,{RaiseError => 1});

my @DBs = (
           "arp",
           "asa",
           "network",
           "router",
           "rtr",
           "switch",
          );

my $query;
foreach my $db (@DBs)  {
   print $ofh "##########\n$db\n\n";
   $query = "SHOW TABLES IN $db";
   my $db_h = $dbh->prepare($query) ;
   $db_h->execute();
   my $db_ary = $db_h->fetchall_arrayref;
   foreach my $row (@$db_ary)  {
      foreach my $table (@$row)  {
         my ($field,$type,$key,$index,$primary);
         print $ofh "= $table:\n";
         $query = "DESCRIBE $db.$table";
         my $tbl_h = $dbh->prepare($query) ;
         $tbl_h->execute();
         my $tbl_ary = $tbl_h->fetchall_arrayref;
         my $createln = "CREATE TABLE $db.$table ("; 
         foreach my $row (@$tbl_ary)  {
            my $default;
            #foreach my $col (@$row)  {
            #   if ($col eq "")  { $col = "*"; }
            #   print $ofh "$col ";
            #}
            #print $ofh "\n";
            $field   = $row->[0];
            $type    = $row->[1];
            $key     = $row->[3];
            $default = $row->[4];
            if ($default)  {  $createln .= "$field $type NOT NULL DEFAULT $default, ";  }
            else           {  $createln .= "$field $type NOT NULL, ";  }
            if ($key eq "MUL")  {
               push @$index, $field;
            }
            if ($key eq "PRI")  {
               push @$primary, $field;
            }
         }
         if ($primary)  {
            #$createln .= ", primary key(";
            $createln .= "primary key(";
            foreach my $pri (@$primary)  {
               $createln .= "$pri,";
            }              
            $createln =~ s/,$/) /;  ## remove extra "," and close primary grouping
         }
         $createln =~ s/, $//;
         $createln .= ");";
         print $ofh "$createln\n";
         foreach my $in (@$index)  {
            print $ofh "ALTER TABLE $db.$table ADD INDEX ($in);\n";
         }
      }
      print $ofh "\n";
   }
}
print "output printed to ./mysql_desc_all.out\n";

exit:

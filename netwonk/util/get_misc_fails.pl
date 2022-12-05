#!/usr/bin/perl
#jackg@uic.edu
#
# get_misc_fails.pl - goes through ./forensic/switches/*.swmisc and identifies switches that fiailed 
# process by the small size of the output file.  Successes have file sizes over 1000 bytes.
#  

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/util//;
use lib "$installpath/lib";

use IO::File;
my $path = "$installpath/util";
my $of  = "$path/misc-fails.script";
my $ofh = IO::File->new(">$of");

my $args;
@$args = @ARGV;

print $ofh "#!/bin/sh\n";
my $datapath = "$installpath/forensic/switches";
my @ll = `ls -l $datapath/*.swmisc`;
foreach my $ln (@ll)  {
   chomp $ln;
   my (undef,undef,undef,undef,$size,undef,undef,undef,$fn) = split " ", $ln;
   $fn =~ s/$datapath\///;
   if ($fn =~ /^\d{2}.out/)     {  next;  }  
   if ($fn =~ /^\d{2}-core\.out/)  {  next;  }  
   if ($fn =~ /^\d{2}-\d.out/)     {  next;  }  
   if ($fn =~ /ex\d\d00.out/)      {  next;  }
   if ($fn =~ /qfx\d{4}.out/)      {  next;  }
   #if ($fn =~ /lectern/)           {  next;  }
   if ($args->[0])  {  
      my $str = $args->[1];
      if ($fn =~ /$str/)     {  next;  }  
   }
   if ($size < 1000)  {
      my $grepln = `grep swmisc.pl $datapath/$fn`;
      chomp $grepln;
      my (undef,$swip,$swname) = split " ", $grepln;
      if (($swname ne "") && ($swip ne ""))  {
         print "./swmisc.pl $swip $swname &\n";
         print $ofh "./swmisc.pl $swip $swname &\n";
      }
   }
}
print "Output prints to misc-fails.script\n";   
exit;


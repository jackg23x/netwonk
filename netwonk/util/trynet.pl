#!/usr/bin/perl


use strict;


my $args;
@$args = @ARGV;

my $subnet = $args->[0];
my ($ipnum,$mask) = split /\//, $subnet;
my ($a,$b,$c,$d)  = split /\./, $ipnum;

my ($netnum,$increment);
if ($mask == 24)  {
   $netnum = "$a.$b.$c.0";
   $increment = "256";
}
if ($mask > 24)  { 
   $increment = 2**(32-$mask);
   my $num;
   while ($num < $d)  {  $num = $num + $increment;  }
   $netnum = "$a.$b.$c.$num";
}
if ($mask > 16 && $mask < 24)  {
   my $increment = 2**(24-$mask);
   my $num;
   until ($num > $c)  {  $num = $num + $increment;  }
   $netnum = "$a.$b.$num.0";
}

print<<EOF;
subnet: $subnet  -  netnum: $netnum  
EOF

exit;

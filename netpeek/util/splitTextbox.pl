#!/usr/bin/perl
# jackg - Jack Gallagher
#
# whitespace test

use strict;

my $line = "123  234  345  456  567  678  789  890  901  012  asd  sdf ";

my $qwe;
my $morphs;

my @items = split ' ', $line;                                                                                                                 
                                                                                                                                           
while (@$qwe = splice @items, 0, 3) {                                                                                                    
   # print "line: ", join(' ', @$qwe), "\n";                                                                                              
   push @$morphs, join(' ', @$qwe);
}   


foreach my $m (@$morphs)  {
   print "group: $m\n";
}

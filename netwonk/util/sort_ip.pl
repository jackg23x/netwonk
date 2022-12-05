#!/usr/bin/perl
# jackg@uic.edu
use IO::File;
use strict;

my $args;
@$args = @ARGV;

if (!defined @ARGV)  {  help();  exit;  }
if ( grep /-h/ , @ARGV )  {  help();  exit;  }

my $inf  = $args->[0];
my $infh = IO::File->new($inf);

### do the hash to array thing and fix the code below....


my $ips;      ## array of IPs
my $ipct_h;   ## ip counter hash
my $iphash;   ## hash of lines

while (my $ln = <$infh>)  {
   if ( $ln =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/ )  {
      my $ip = $1; 
      ## push @$ips, $ip;
      $ipct_h->{$ip} = 1;
      chomp $ln;
      $iphash->{$ip} = $ln;
   }
}
foreach my $ip (keys %$ipct_h)  {
   push @$ips, $ip;
}
$ips = sort_by_ip($ips);
foreach my $i (@$ips)  {
   #print "$i ", $iphash->{$i}, "\n";
   print $iphash->{$i}, "\n";
}

######################################

sub sort_by_ip  {

my $iplist = shift;   ## array ref

## here's the mapping transform for IP number sorting:
    @$iplist =
        map {$_->[0]}
        sort { ($a->[1] <=>$b->[1])
                    || ($a->[2] <=>$b->[2])
                    || ($a->[3] <=>$b->[3])
                    || ($a->[4] <=>$b->[4]) }
        map {[$_, split( '[ \.]', $_) ]} @$iplist;

return ($iplist);

}  ## sort_by_ip

###########################################

sub help  {

print <<EOF;

sort_ip.pl 

syntax:  sort_ip.pl <file_of_lines_w_ip>

EOF

}

#!/usr/bin/perl
## Modified by pauln from  oringal asaconconfig written by  
## jackg@uic.edu 
## 
## contextmap_creator.pl - connect to each ASA, get all the context names and create the file
##                         contextmap.pl used by other scripts to access ip and ASA hostname 
##                         info for making sessions and creating db table entries
##

use strict;

use FindBin qw($Bin);
use lib "$FindBin::Bin/../lib";
my $installpath = $Bin;
$installpath =~ s/\/$//;
$installpath =~ s/\/util//;
use lib "$installpath/lib";
use Sshcon;
my($date,$time) = Sshcon::date_time();
my $tstamp = "$date $time";

if ( grep /-h|help/ , @ARGV )  {  help();  exit;  }

use IO::File;
my $of  = "$installpath/util/contextmap.pl.NEW";
my $ofh = IO::File->new(">$of");
my $rf  = "$installpath/util/asa-failover-status.out";
my $rfh = IO::File->new(">$rf");

my $asas;     ## hash of ASAs

use Net::DNS;
require "$installpath/lib/servers.pl";
my $dns1 = dns1();
my $dns2 = dns2();
my $dns3 = dns3();
my $domain = dnssuffix();
my $fwzone = fwzone();
my $res  = Net::DNS::Resolver->new;
$res->nameservers($dns1,$dns2,$dns3);
$res->tcp_timeout(10);
my @zone = $res->axfr("$fwzone.$domain");
if (@zone)  {
   foreach my $rr (@zone) {
     unless ($rr->type eq "A")  { next; }
     my $aip   = $rr->address;
     my $aname = $rr->name;
#     $asas->{$aname} = $aip;
     $asas->{$aip}->{"fdqn"} = $aname;
     ## ditch the fdqn suffix:  
     $aname =~ s/\.$fwzone\.$domain//;
     ############################## Start LOCAL TWEAK section
     ## author local kludge to ditch two zombie machines:
        if ($aname =~ /asa-wireless-w1/)  { next; }
        if ($aname =~ /asa-wireless-e1/)  { next; }
     ## author local tweaks to eliminate duplicate entries due to standby units
     ## these lines insure failover pairs show up in the same hashes:
     $aname =~ s/-east//;
     $aname =~ s/-west//;
     $aname =~ s/-e1//;
     $aname =~ s/-w1//;
     $aname =~ s/-standby//;
     $aname =~ s/-//g;
     ############################# End LOCAL TWEAK section
     $asas->{$aip}->{"aname"} = $aname;
   }
}
else  { print 'Zone transfer failed: ', $res->errorstring, "\n"; }

## Begin printing output file
print $ofh "#!/usr/bin/perl\n#\n### DO NOT EDIT - this file generated by context_creator.pl into contextmap.pl.NEW \n";
print $ofh "### and then copied manually to ../lib/contextmap.pl\n#\n#\n\n"; 

my $failoverary;
my $anamehash;
foreach my $aip (%$asas)  {
   my $contexts; ## hash of contexts
   my ($contextname,$failover);
   $contexts = proc_contexts($aip);
   foreach my $ip (keys %$contexts) { 
      $contextname = $contexts->{$ip}->{"context"};
      $failover    = $contexts->{$ip}->{"failover"};
      if ($failover eq "Active")  {
         my $aname = $asas->{$aip}->{"aname"}; 
         push @{$anamehash->{$aname}}, "$ip $contextname";
      }
      my $fdqn = $asas->{$aip}->{"fdqn"};
      push @$failoverary, "$fdqn $aip $contextname $ip $failover";
   }
}  ## while...%$asaa

##my $group_array;  ## context groups
## Print hash for each asa (in ip order) into contextmap.NEW
my $gatewayip      = scriptgateway();  ## gateway of script server network (../lib/servers.pl)
my $gatewaycontext = scriptcontext();  ## context of script server network (../lib/servers.pl)
foreach my $aname (keys %$anamehash)  {
   my $asaary = sort_by_ip(\@{$anamehash->{$aname}});
   if ($aname ne "")  {
      print $ofh "\%$aname = (   \n";
      foreach my $ln (@$asaary)  { 
         my($ip,$contextname) = split " ", $ln;
         if ($contextname eq $gatewaycontext)  { $ip = $gatewayip; }
         print $ofh "     '$ip'=>'$contextname', \n";
      }
      print $ofh ");  ## \%$aname\n";
      print $ofh "\n";
   }
}

## Print %context_group hash
print $ofh "%context_group = (\n";
foreach my $aname (keys %$anamehash)  {
   if ($aname ne "")  { print $ofh "'$aname'=>'1',\n" }
}
print $ofh ");  ## %context_group\n\n";

## Print the failover status report to file
if ($failoverary)  {  @$failoverary = sort @$failoverary;  }
foreach my $fln (@$failoverary)  {
   my($fdqn,$aip,$contextname,$ip,$failover) = split " ", $fln;
   printf $rfh "%-20s %-16s %-8s on %-24s\n",$contextname,$ip,$failover,$fdqn;
}

print "exiting...\n";
exit; 

#########################################################

sub proc_contexts  {

   my $aip   = shift;
   
   ## It originates in the admin context, do a 'changeto sys' for complete list (includes 'admin').
   ## From sys you can see the other contexts, which are under that one. 
   my $session = Sshcon->new($aip);
   my $state = $session->connect;
   my $ena_ret;
   if ($state ne "enabled")  { $ena_ret = $session->enable(); }
   $session->command("term pager 0",1);
   $session->command("changeto sys",2);
   my $context_list = $session->command("show context",2);
   my $contexts; # hash ref
   foreach my $cln (@$context_list)  {
      if ($cln =~ /Routed/)  {
         my($ctname,undef,undef,undef,undef) = split " ", $cln;
         if ($ctname=~ /\*admin/)  {  next;  }
         $session->command("changeto context $ctname",1);
         ## get the failover state first
         my $failover;
         my $fret = $session->command("show failover | inc This context",1);
         foreach my $fln (@$fret)  {
            if ($fln =~ /This context:/)  {  
               (undef,undef,$failover) = split " ", $fln;
               ## print $ofh "fln: $fln => $failover\n";
            }
         }
         if ($failover ne "Active")  {  next;  }
         my $ret = $session->command("show route | grep 0.0.0.0 0.0.0.0",2);
         my ($ip,$int,$portchan);
         foreach my $ln (@$ret)  {
            my(undef,undef,undef,undef,undef,$ipg,$vlan) = split " ", $ln;
            $ipg =~ s/,//;
            if ($ipg =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)  {  $int = $vlan;  }
         }  
         my $intary = $session->command("show interface $int summary",1);  
         foreach my $ln (@$intary)  {
            if ($ln =~ /Interface Port-channel/)  {
               (undef,$portchan,undef,undef) = split " ", $ln;
               $portchan =~ s/Port-channel//i;
            }  
         }
         my $pcary = $session->command("show run int port-chan $portchan",1);  
         foreach my $ln (@$pcary)  {
            if ($ln =~ /ip address/)  {
               my(undef,undef,$ip,undef) = split " ", $ln;
               $ip =~ s/,//;
               if ($ip =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)  {
                  $contexts->{$ip}->{"context"}  = $ctname; 
                  $contexts->{$ip}->{"failover"} = $failover;
                  ## print $ofh "context: $ctname :: ip: $ip\n";
               }
            }
         }
      }
   } 
   return($contexts);
 
}  ## get_config

##############################################################################

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

##############################################################################

sub help  {

print " \n";
print <<EOF;
 contextmap_creator.pl - connect to each ASA, get all the context names and create the file
                         contextmap.pl.NEW, later copied manually to replace contextmap.pl 
                         used by other scripts to access ip and ASA hostname 
                         info for making sessions and creating db table entries
EOF
print "\n\n";
}

##############################################################################

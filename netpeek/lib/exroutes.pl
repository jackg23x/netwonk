#!/usr/bin/perl
## by jackg@uic.edu
#

################################################
sub exmessages {    ## custom messages for the header of iproutes.cgi

my $exmessages;  ## array ref
push @$exmessages, "<tr bgcolor=#FF0000><td><b>10.64.0.0/11</b></td><td><b>belongs to UXS</b></td></tr>";
push @$exmessages, "<tr bgcolor=#FF0000><td><b>10.160.0.0/11</b></td><td><b>belongs to UXS</b></td></tr>";
push @$exmessages, "<tr bgcolor=#FF0000><td><b>10.192.0.0/10</b></td><td><b>belongs to UXUC</b></td></tr>";
return($exmessages);
}  ## exmmessages

#################################################
sub exroutes  {
#
# externally managed partner organization routes manually entered so that they show up in iproutes.cgi

my ($route, $mask, $rtr, $first, $last);

# UXS
$route = "10.64.0.0"; $mask = "/11" ; $rtr = "UXS" ; $first = "10.64.0.1" ; $last = "10.95.255.255";
$iproute->{"$route$mask $rtr unknown"} = "red $route $mask $rtr $first $last unknown EXT UXS";
# UXS
$route = "10.160.0.0"; $mask = "/11" ; $rtr = "UXS" ; $first = "10.160.0.1" ; $last = "10.191.255.255";
$iproute->{"$route$mask $rtr unknown"} = "red $route $mask $rtr $first $last unknown EXT UXS";
# UXUC
$route = "10.192.0.0"; $mask = "/10" ; $rtr = "UXUC" ; $first = "10.192.0.1" ; $last = "10.255.255.255";
$iproute->{"$route$mask $rtr unknown"} = "red $route $mask $rtr $first $last unknown EXT UXUC";

# COM private space in BGRX 205
$route = "10.10.10.0"; $mask = "/24" ; $rtr = "COM" ; $first = "10.10.10.1" ; $last = "10.10.10.255";
$iproute->{"$route$mask $rtr unknown"} = "red $route $mask $rtr $first $last COM BGRX 205";
# COM private space in BGRX 205
$route = "10.10.30.0"; $mask = "/24" ; $rtr = "COM" ; $first = "10.10.30.1" ; $last = "10.10.30.255";
$iproute->{"$route$mask $rtr unknown"} = "red $route $mask $rtr $first $last COM BGRX 205";
## COM private space in BGRX 205
$route = "10.10.50.0"; $mask = "/24" ; $rtr = "COM" ; $first = "10.10.50.1" ; $last = "10.10.50.255";
$iproute->{"$route$mask $rtr unknown"} = "red $route $mask $rtr $first $last COM BGRX 205";
## COM private space in BGRX 205
$route = "10.10.70.0"; $mask = "/24" ; $rtr = "COM" ; $first = "10.10.70.1" ; $last = "10.10.70.255";
$iproute->{"$route$mask $rtr unknown"} = "red $route $mask $rtr $first $last COM BGRX 205";
## COM private space in BGRX 205
$route = "10.10.90.0"; $mask = "/24" ; $rtr = "COM" ; $first = "10.10.90.1" ; $last = "10.10.90.255";
$iproute->{"$route$mask $rtr unknown"} = "red $route $mask $rtr $first $last COM BGRX 205";
## COM private space in BGRX 205
$route = "10.105.102.0"; $mask = "/24" ; $rtr = "COM" ; $first = "10.105.102.1" ; $last = "10.105.102.255";
$iproute->{"$route$mask $rtr unknown"} = "red $route $mask $rtr $first $last COM BGRX 205";
## COM private space in BGRX 205
$route = "172.16.1.0"; $mask = "/24" ; $rtr = "COM" ; $first = "172.16.1.1" ; $last = "172.16.1.255";
$iproute->{"$route$mask $rtr unknown"} = "red $route $mask $rtr $first $last COM BGRX 205";
## COM private space in BGRX 205
$route = "172.16.10.0"; $mask = "/24" ; $rtr = "COM" ; $first = "172.16.10.1" ; $last = "172.16.10.255";
$iproute->{"$route$mask $rtr unknown"} = "red $route $mask $rtr $first $last COM BGRX 205";
## COM private space in BGRX 205
$route = "172.16.40.0"; $mask = "/24" ; $rtr = "COM" ; $first = "172.16.40.1" ; $last = "172.16.40.255";
$iproute->{"$route$mask $rtr unknown"} = "red $route $mask $rtr $first $last COM BGRX 205";
## NPI AVI private space in NPI basement
$route = "10.150.150.0"; $mask = "/23" ; $rtr = "npi-avi" ; $first = "10.150.150.1" ; $last = "10.150.151.255";
$iproute->{"$route$mask $rtr unknown"} = "red $route $mask $rtr $first $last NPI Basement AV";
## all of 10.3.0.0/16 to DSCC b/c microsoft leaks reals to AD.
$route = "10.3.0.0"; $mask = "/16" ; $rtr = "DSCC" ; $first = "10.3.0.1" ; $last = "10.3.255.254";
$iproute->{"$route$mask $rtr unknown"} = "red $route $mask $rtr $first $last DSCC IL statewide";
## all of 172.30.0.0/16 to UXH cloulds
$route = "172.30.0.0"; $mask = "/16" ; $rtr = "UXH" ; $first = "172.30.0.1" ; $last = "172.30.255.254";
$iproute->{"$route$mask $rtr unknown"} = "red $route $mask $rtr $first $last UXH Clouds";

return($iproute);

}  ## exroutes

1; ## because you MUST!!!
#############################################

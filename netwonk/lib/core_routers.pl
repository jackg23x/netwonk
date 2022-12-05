#!/usr/bin/perl
## Jack Gallagher 
### core_routers.pl
## require listing of core routers, and separately, the routers on which macfilters are applied         
## 
##  
## 

%core_routers = (
   "<ip#1>" => "<hostname#1>",
   "<ip#2>" => "<hostname#2>",
);  ## %core_routers

%macfilter_routers = (
   "<hostname#1>" => "<ip#1>",
   "<hostname#2>" => "<ip#2>",
);  ## %macfilter_routers

## routeripprefix is the ip without the host octet - example:
sub routeripprefix { return ('192.168.0.1'); }

1; ## because you MUST!!!


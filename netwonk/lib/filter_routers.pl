#!/usr/bin/perl
## jackg@uic.edu
## filter_routers.pl
## require listing of filter routers         
## these are the routers that maintain mac filters system-wide
## 

%filter_routers = (
   # Fill in ip/simple_hostname pairs as needed:
   "ip#1" => "hostname#1",
   "ip#2" => "hostname#2",
);  ## %filter_routers

## These are arbitrary routine names used in macfilter.pl, tied to routers - you may change or expand as needed
## *** the ip#1 here must match the ip#1 above, same with ip#2...
sub router37   { return ('<ip#1>'); }
sub router47   { return ('<ip#2>'); }

1; ## because you MUST!!!


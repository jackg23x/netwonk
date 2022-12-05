#####################################################
#
# Given an old style octet mask, returns a slash mask
#
#####################################################

sub re_mask   {

   my $mask = shift @_;

   if ($mask eq "255.255.128.0")   { $mask = "/17"; }
   if ($mask eq "255.255.192.0")   { $mask = "/18"; }
   if ($mask eq "255.255.224.0")   { $mask = "/19"; }
   if ($mask eq "255.255.240.0")   { $mask = "/20"; }
   if ($mask eq "255.255.248.0")   { $mask = "/21"; }
   if ($mask eq "255.255.252.0")   { $mask = "/22"; }
   if ($mask eq "255.255.254.0")   { $mask = "/23"; }
   if ($mask eq "255.255.255.0")   { $mask = "/24"; }
   if ($mask eq "255.255.255.128") { $mask = "/25"; }
   if ($mask eq "255.255.255.192") { $mask = "/26"; }
   if ($mask eq "255.255.255.224") { $mask = "/27"; }
   if ($mask eq "255.255.255.240") { $mask = "/28"; }
   if ($mask eq "255.255.255.248") { $mask = "/29"; }
   if ($mask eq "255.255.255.252") { $mask = "/30"; }
   if ($mask eq "255.255.255.255") { $mask = "/32"; }
   return($mask);
}
1;


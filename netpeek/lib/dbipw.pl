#!/usr/bin/perl
#jackg@uic.edu
### pw function for DBI connects in scripts
### shows support for two servers - only used for conversions and upgrades, likely not needed
### *** replace action with secure password call where possible

sub dbigrabit {
   my $parm = shift;
   ## machine generated passwords must be in single quotes due to oddball characters
   if ($parm eq "server1")  { return ("<server_FQDN>","<userID>",'<password - single quotes>'); }
   else                     { return ("<server_FQDN>","<userID>",'<password - single quotes>'); }
}

1; ## because you MUST!!!


#!/usr/bin/perl
# Jack Gallagher   
### TEMPORARY password function for DBI connects in scripts - use your local secure code to feed this

sub dbigrabit {
  ## relpace return below with a call to secure password fonction:
  return ("mysql_server.myplace.org","mysql_user","mysql_password");
}

1; ## because you MUST!!!


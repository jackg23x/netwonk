#!/usr/bin/perl
##jackg
#### utility function for various info kickback to scripts
#
### ALL DATA HERE ARE EXAMPLES -- Input real data

sub scriptserver { return ('ego.cc.fake.edu'); }
sub dbserver     { return ('wold.cc.fake.edu'); }
sub webserver    { return ('fire.cc.fake.edu'); }
sub siteurl      { return ('www.fake.edu'); }
sub weburl       { return ('network.fake.edu'); }
sub webcgi       { return ('network.fake.edu/<directory>'); }       ## web location of netpeek 
sub weblocation  { return ('network.fake.edu/<directory>'); }       ## web location of netpeek
sub dns1         { return ('fake-dns1.fake.edu'); }
sub dns2         { return ('fake-dns2.fake.edu'); }
sub dns3         { return ('fake-dns3.fake.edu'); }
sub dnssuffix    { return ('fake.edu'); }
sub asazone      { return ('asa'); }                 ##  subdomain
 
## userIDs of admins for email
sub user         { return ('root');   }
sub admin        { return ('jake');  }
sub voipadmin    { return ('wull');  }
sub netmgr       { return ('pauline');  }
sub neteng       { return ('jxm');    }
sub network      { return ('network');}

## public IP block(s) allocated to network/AS
sub ipprefix1    { return ('126.222'); }
sub ipprefix2    { return ('130.190'); }
sub ipprefix3    { return ('192.52.252'); }

sub dhcp1        { return ('126.222.111.224'); }
sub dhcp2        { return ('192.52.252.222');  }
sub dhcp1name    { return ('dhcp.cc.fake.edu'); }
sub dhcp2name    { return ('dhcp-2.cc.fake.edu');  }
sub dhcpconfpath { return ('<path of primary dhcp config>'); }

sub ntpserver1   { return ('126.222.2.33'); }
sub ntpserver2   { return ('126.222.2.37'); }

sub mntpath      { return ("/mnt/<path of mounted drive>"); }      # backup path, mounted drive, etc.

sub deptdata     { return ('/var/www/data/reachhash.pl'); }        # for custom local use - likely not needed

sub changevlans  { my $vlans;                                      # for user access to ./netpeek/chvlan.cgi - likely not needed
                   @$vlans = (21,171,191,587);                     # for user access to ./netpeek/chvlan.cgi - likely not needed 
                   return ($vlans);
                 }

1; ## because you MUST!!!


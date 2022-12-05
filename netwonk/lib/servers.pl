#!/usr/bin/perl
##  Jack Gallagher
### utility function for various info kickback to scripts
##
##  These are merely examples - FILL ALL THESE IN:

sub scriptserver { return ('<FQDN of script server>'); }
sub dbserver     { return ('<FQDN of database server>'); }
sub webserver    { return ('<FQDN of web server>'); }
sub dns1         { return ('<FQDN of DNS1>'); }
sub dns2         { return ('<FQDN of DNS2>'); } # if needed
sub dns3         { return ('<FQDN of DNS3>'); } # if needed
sub dnssuffix    { return ('<myplace.org>'); }  # suffix of local FQDN tags      
## what DNS zone are your ASA firewalls in? Example if they're found in 'asa.myplace.org' -- then use this: 
sub fwzone       { return ('asa'); }

## userIDs of various admins and lists:
sub admin        { return ('<userID1>');  }
sub voipadmin    { return ('<userID2>');  }
sub user         { return ('root or ?');   }
sub netmgr       { return ('<userID3>');  }
sub neteng       { return ('<userID4>');    }
sub network      { return ('<userID5>');}

## examples:
sub ipprefix1    { return ('10.200'); }
sub ipprefix2    { return ('10.50'); }
sub ipprefix3    { return ('192.168.128'); }

sub dhcp1        { return ('192.168.100.50');  }
sub dhcp1name    { return ('dhcp1.myplace.org'); }
sub dhcp2        { return ('192.168.200.23');  }
sub dhcp2name    { return ('dhcp2.myplace.org');  }
sub dhcpconfpath { return ('<local or mounted directory path of dhcp configs, i.e. /mnt/dhcp >'); }

sub ntpserver1   { return ('<ntp1 ip>'); }
sub ntpserver2   { return ('<ntp2 ip'); }

sub scriptcontext { return ('<name of context>'); }  ## the ASA context your script server is running in - if any
sub scriptgateway { return ('<ip gateway>'); }  ## the gateway of that context, as scriptserver is *inside* that network

### These are examples -- CHECK and FILL OUT:
sub nwlogpath    { return ("/var/log/netwonk"); }       # netwonk log path
sub dhcpcfgpath  { return ("/mnt/dhcp"); }              # dhcp config directory
sub dhcpcfgpath2 { return ("/mnt/dhcp/conf"); }         # dhcp secondary directory - separate config files
sub dhcpcfgfile1 { return ("/mnt/dhcp/dhcpd.conf"); }   # main, single dhcp config file
sub mntpath      { return ("/mnt/backup"); }            # backup path, mounted drive, etc.
sub crontab      { return ("/etc/crontab or ???"); }    # location of crontab for netwonk

1; ## because you MUST!!!

# netwonk
 the netwonk network monitor and netpeek web code

Netwonk is a network monitoring package for Cisco equipment. 
It also supports some Palo Alto firewalls, and can be extended to other hardware.  
It is written in Perl for linux/unix.
The netwonk project includes a collection of scripts, the Netpeek web package, 
and configuration for all databases and tables on an integrated mariadb/mysql server.
It also includes code necessary for a syslog-ng server sending needed DHCP and macflap data to the database server.
A normal netwonk installation consist of separate script, web and database servers (plus code added to syslog server).  
This works nicely with a trio of VMs running scripts, web and database.  
In a small installation, all three functionalities could work on one server, though that has not been tested.

Please Read the files Contents and Install in the netwonk directory.
Please Read the files AA_Contents and AA_Install in the netpeek subdirectory.

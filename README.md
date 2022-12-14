# netwonk
the netwonk network-security data monitor with netpeek web code -

Netwonk is a network security data package for admins running Cisco equipment. 
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

= Screenshot examples from netpeek web displays 

netpeek front page
![netpeek front page](https://user-images.githubusercontent.com/119876971/208184020-bffe8e7b-b43a-4d91-bc49-717f3427f9b6.jpg)

netpeek multi-ip search,
where text can be typed in or pasted in from documents, problems logs, etc.
![netpeek multi-ip search](https://user-images.githubusercontent.com/119876971/208487134-be29af0a-1b6a-404d-8d2c-b15cb21f0b4c.jpg)

netpeek multi-mac search,
where text can be typed in or pasted in from documents, problems logs, etc.
![netpeek multi-mac search](https://user-images.githubusercontent.com/119876971/208185141-44d63e73-82da-4406-a7e6-8869085f2d47.jpg)

netpeek vlan overview
![netpeek vlan overview](https://user-images.githubusercontent.com/119876971/210597210-bf035363-73af-461b-847b-f09335036433.jpg)

netpeek vlan ip-based search
![netpeek vlan ip-based search](https://user-images.githubusercontent.com/119876971/208185430-5836167e-ca9d-4fb4-81bc-f82321047451.jpg)

netpeek vlan mac-based search
![netpeek vlan mac-based search](https://user-images.githubusercontent.com/119876971/208185511-dfc47f9c-1875-43c7-89c1-a0d0648222ae.jpg)

switchmeister (sw.cgi) multi-switch search
![sw cgi multiswitch search](https://user-images.githubusercontent.com/119876971/208185598-22e287f8-2a67-4187-912d-6b86aa6117ae.jpg)

error-disabled switch ports
![errdis](https://user-images.githubusercontent.com/119876971/208185909-3b921508-9fda-440a-97fa-effe0c38399b.jpg)

borderfilter front page
![borderfilter front page](https://user-images.githubusercontent.com/119876971/208186016-dbc80193-180b-4e9d-ba50-e92653fc5c81.jpg)

borderfilter last 20 display
![borderfilter last 20](https://user-images.githubusercontent.com/119876971/208186107-1b867ea7-40d9-4eef-a319-2ef9c7a31e61.jpg)

macfilter front page
![macfilter front page](https://user-images.githubusercontent.com/119876971/208186171-771923e2-38e3-43fa-b648-b43f3c99f265.jpg)

macfilter last 75 filters
![macfilter last 75](https://user-images.githubusercontent.com/119876971/210597054-556b639c-b957-451e-9e30-999be19e6f10.jpg)

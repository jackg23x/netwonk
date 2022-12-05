#!/usr/bin/perl
## Jack Gallagher  
### pw function for PaloAlto connects in scripts
###
### *** Please replace calls with local secure password routines ***
##

## Supports the existence of old and new passwords on the network simultaneously

sub rtexe1 { return ('<router_exe1>'); }
sub rtena1 { return ('<router_ena1>'); }
sub rtexe2 { return ('<router_exe2>'); }
sub rtena2 { return ('<router_ena2>'); }
sub swexe1 { return ('<switch_exe1>'); }
sub swena1 { return ('<switch_ena1>'); }
sub swexe2 { return ('<switch_exe2>'); }
sub swena2 { return ('<switch_ena2>'); }
sub Pauser { return ('<admin_user>'); }
sub Papw   { return ('<admin_password>'); }

1; ## because you MUST!!!


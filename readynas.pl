#-----------------------------------------------------------------------------
# NETGEAR ReadyNAS Communications Library for Perl
# by Lee Thompson <thompsonl@logh.net>
#-----------------------------------------------------------------------------
# L O A D E R
#-----------------------------------------------------------------------------
# This library is for getting status information from Netgear ReadyNAS units  
# for use in status page generation, reports and other alerts.  It is provided
# free of charge and without warranty.
#-----------------------------------------------------------------------------
# NOTE: If none or only some of your ReadyNAS units are detected, try 
# lengthening the socket and socket error timeouts.
#-----------------------------------------------------------------------------

#-----------------------------
sub loadReadyNASLibrary{
	$method = uc shift;
	my $retval = 0;

	if ($method eq "SNMP") {
		$retval = 1;
		require "readynas-snmp.pl";
	}

	if ($method eq "UNICAST") {
		$retval = 1;
		require "readynas-unicast.pl";
	}
	
	if ($method eq "MULTICAST") {
		$retval = 1;
		require "readynas-multicast.pl";
	}
	
	if ($method eq "HYBRID") {
		$retval = 1;
		require "readynas-hybrid.pl";
	}
		
	return $retval;
}

1;


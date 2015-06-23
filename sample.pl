#-------------------------------------------------------------
# Sample script for the ReadyNAS Perl library
#-------------------------------------------------------------

#-------------------------------------------------------------
# Load the library 
#-------------------------------------------------------------

require 'readynas.pl';			# Loader
loadReadyNASLibrary("HYBRID");		# Select Library to Use
					# SNMP = SNMP 
					# MULTICAST = UPNP
					# UNICAST = UPNP
					# HYBRID = UNICAST/SNMP

	#--------------------------------------------------#
	# You can alternately use the libraries directly.  #
	#						   #
	# e.g. require 'readynas-unicast.pl';		   #
	#--------------------------------------------------#


#-------------------------------------------------------------
# Set Options
#-------------------------------------------------------------

setOptionRequireUniqueHosts(1);	 # Filter duplicate hostnames (0=off, 1=on)
setOptionVerbose(0);		 # Verbose Messages (0=off, 1=on)
setOptionDebug(0);		 # Debug Messages (0=off, 1=on)
setOptionDebugFile("console");	 # Output to CONSOLE
setOptionDumpPackets(0);	 # Write packets to disk (UPNP Only)
setOptionDumpBadPacketsOnly(0);	 # Write ONLY bad packets to disk (UPNP Only)
setSocketTimeout(1);		 # Set Socket Timeout (Seconds)
setSocketErrorTimeout(0);	 # Set Socket Error Timeout (Seconds) (MULTICAST ONLY)
setCommunity("public")	;	 # Set SNMP Community (SNMP Only)

#-------------------------------------------------------------
# ReadyNAS Units to Scan
#-------------------------------------------------------------

setBroadcastAddress("192.168.0.255");		

	#------------------------------------------------------------#
	# Look for units in the subnet (UPNP only)		     #
	#							     #
	# * If not set, defaults to 255.255.255.255 which will only  #
	#   work with UPNP MULTICAST.				     #
	#							     #
	# * If using UPNP to detect units, do NOT specify any units  #
	#   below.						     #
	#							     #
	# * If using SNMP you MUST specify each unit below.          #
	#   (No discovery is available)				     #
	#------------------------------------------------------------#
						
# addUnit("192.168.0.1");			
# addUnit("192.168.0.2");			
# addUnit("192.168.0.3"); 			
# addUnit("192.168.0.4"); 			
# addUnit("192.168.0.5"); 			

	#------------------------------------------------------------#
	# Add NETGEAR ReadyNAS unit at IP address to the list to     #
	# gather information from.                                   #
	#------------------------------------------------------------#
	
#-------------------------------------------------------------
# Display Banner
#-------------------------------------------------------------

print "NETGEAR ReadyNAS Status\n";
print "Using " . getLibraryTitle() . " v" . getLibraryVersion() . "\n\n";

print "Please Wait...\n";

#-------------------------------------------------------------
# Gather ReadyNAS Data
#-------------------------------------------------------------

loadReadyNASData();		# if for some reason you want the packets for your
				# own purposes, simply assign a variable.
				# (UNICAST and MULTICAST libraries only.)

if (getBytesRead() < 1) {
	print "No Data Received.\n";
	exit(1);
}
	
#-------------------------------------------------------------
# Get a list of IP addresses of Units we now have data on
#-------------------------------------------------------------

$units = getUnitAddresses();	# Get a list of ReadyNAS units addresses (sorted by IP)
$unitcount = getUnitCount();	# Get a count of ReadyNAS units

print "Received Data for $unitcount Unit(s)\n";

#-------------------------------------------------------------
# Process the Data
#-------------------------------------------------------------

my $i = 0;

for ( split /\|/, $units ) {
	/\|/;
	if ($_ ne "") {
		$i++;

		#----------------------------------------
		# parse the UDP data record for each unit
		#----------------------------------------

		$macindex = parseReadyNASData(getUnitData($_));

		#----------------------------------------
		# display the parsed data for each unit
		#----------------------------------------

		print "Unit #$i:\n";
		print "      Model: $unit{$macindex}{models}{0}\n";
		print "         OS: $unit{$macindex}{os}{0}\n";
		print "       Host: $unit{$macindex}{hostname}{0}\n";
		print "         IP: $unit{$macindex}{ipaddr}{0}\n";
		print "        MAC: $unit{$macindex}{mac}{0}\n";
		print "    Cooling: $unit{$macindex}{fan}{0}\n";
		print "System Temp: $unit{$macindex}{tmps}{0}\n";
		print "        UPS: $unit{$macindex}{ups}{0}\n";
		print "    Volumes: $unit{$macindex}{volumes}{0}\n";
		print "      Disks: $unit{$macindex}{disks}{0}\n";
		print "     Uptime: $unit{$macindex}{system}{uptime}{0}\n";
		print "     Memory: $unit{$macindex}{system}{memory}{0}\n";
		print "  Processes: $unit{$macindex}{system}{processes}{0}\n";
		print "      uname: $unit{$macindex}{system}{uname}{0}\n";
		print "       Boot: $unit{$macindex}{boot}{0}\n";
		print "------------\n";
	}
}

exit(0);




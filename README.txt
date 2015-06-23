NETGEAR ReadyNAS Communications Library for Perl 
by Lee Thompson <thompsonl@logh.net>
******************************************************************************
Documentation
******************************************************************************

There are four versions of this library:
	* UPNP Unicast		readynas-unicast.pl
	* UPNP Multicast	readynas-multicast.pl
	* SNMP			readynas-snmp.pl
	* HYBRID		readynas-hybrid.pl

There is a fifth file, that is an optional loader (see the LOADER section
for instructions) called "readynas.pl".

This library is for getting status information from NETGEAR ReadyNAS units  
for use in status page generation, reports and other alerts.  It is provided
free of charge and without warranty.

NOTE: If none or only some of your ReadyNAS units are detected, try 
lengthening the socket and socket error timeouts.

There are some data elements not available by SNMP.  These are:
	* Boot Status (such as BOOT or UPDATE)
	* Operating System Timestamp
	* Operating System Name
	* Operating System Version is in the old-style notation
	* UPS Status
	* Model 

Also please note that discovery is not available with SNMP, each 
unit to monitor will need to be explicitly defined with an addUnit call.
If no addUnit calls are made, it will default to loopback (127.0.0.1).

******************************************************************************
Prequisites:
******************************************************************************

These are Perl scripts and assume you have Perl installed.   If not, that will
be your first step.   Perl is available for virtually every operating system.

You may need to install additional Perl libraries before using the scripts.

These prequisites vary depending which version of the library you wish to
use:

	MultiCast: "IO::Socket::Multicast" and "IO::Select" Perl modules.
	Unicast:   "Socket" which should be already included with your Perl.
	SNMP:	   "NET::SNMP" Perl module.
	Hybrid:	   "Socket" and "NET::SNMP"

In addition, for SNMP, you will need to ensure that the SNMP service is 
enabled on your ReadyNAS unit.   This can be done in FrontView under 
Alerts/SNMP.   Be sure the IP address of the machine running the script is
in the allow list and that the SNMP Community matches.   
(The default community is "public".)

******************************************************************************
Running Scripts Directly on NETGEAR ReadyNAS
******************************************************************************

If you wish to run the scripts *directly* on a NETGEAR ReadyNAS you may need
to install a library with apt-get.    The multicast version does *not* work
properly on the sparc models (600/NV/NV+).   The unicast version should work
without any libraries needing to be installed and is probably your best bet
although auto-detection is not available (at least on the sparc models).

For Multicast on ReadyNAS x86 models: 
	# apt-get install libio-socket-multicast-perl

For SNMP on ReadyNAS models:
	# apt-get install libnet-snmp-perl

******************************************************************************
Known Issues:
******************************************************************************

* The UPNP multicast version does not work directly on the ReadyNAS sparc 
  (NV/NV+) models, the following error is returned: 
  "perl: relocation error: /usr/lib/perl5/auto/IO/Interface/Interface.so: 
   undefined symbol: Perl_Gthr_key_ptr"

* The UPNP unicast version works on ReadyNAS sparc (NV/NV+) but broadcast 
  (.255) addresses do not work as expected.

* The UPS, Operating System and Model fields are not reported on the SNMP 
  version (unfortunately, they aren't included in the MIB).


******************************************************************************
Error Handling:
******************************************************************************

Error handling is rather minimal at the moment and is now the focus of
the project.


******************************************************************************
Loader:
******************************************************************************

There is an optional loader you can use called 'readynas.pl'.  It has a
single function and that is to load one of the other library files.

The function is loadReadyNASLibrary and takes a string as an argument.
That string can be "SNMP", "MULTICAST" or "UNICAST".  
It is not case-sensitive.  

The function does return a value, if there was a match it returns a 1, 
otherwise it returns a 0.

Example:

require 'readynas.pl';	
loadReadyNASLibrary("SNMP");

Again, this particular library and function call are completely optional.

******************************************************************************
Common Usage:
******************************************************************************

The following code will load the library, auto-discover (UPNP Multicast) any
units on the network and then display summary information on the console.

	require "readynas-multicast.pl"; # Use readynas-multicast UPNP library
	loadReadyNASData();
	$units = getUnitAddresses();
	$unitcount = getUnitCount();
	$i=0;
	for ( split /\|/, $units ) {
		/\|/;
		$i++;
		$macindex = parseReadyNASData(getUnitData($_));
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
		print "       Boot: $unit{$macindex}{boot}{0}\n";
		print "------------\n";
	}

For more details and examples please take a look at "sample.pl" and
"sample_webstats.pl".

******************************************************************************
Data Structure:
******************************************************************************

$unit{MAC_INDEX}{ITEM}{INSTANCE}

Items:
	models			Model Data		(Not available with SNMP)
	os			OS Data
	hostname		Hostname
	ipaddr			IP Address
	mac			MAC Address
	fan			Fan Data
 	tmps			Temperature Data
	ups			UPS Data		(Not available with SNMP)
	volumes			Volumes Data
	disks			Disks Data
	system			System Data Tree	(SNMP Only)
	uptime			System Uptime		(SNMP Only)
	memory			System Memory 		(SNMP Only)
	processes		System Process Count	(SNMP Only)
	uname			System Uname		(SNMP Only)
	boot			Boot Status 		(Not available with SNMP)

A MAC_INDEX is a MAC Address without spaces or colons.

An INSTANCE of 0 is a total or summary.

For example:

$unit{000DA2011817}{volumes}{0} will contain information about the active 
volume on the ReadyNAS with the MAC address of "00:0D:A2:01:18:17".

******************************************************************************
External Option Calls:
******************************************************************************

addUnit(IP Address)				
	Scan this specific ReadyNAS unit.   
	Please note that adding an IP directly will effectively shut off 
        any discovery/auto-detection.

setOptionRequireUniqueHosts(0..1)
	Require HOSTNAMEs to be unique 
	(in addition to IP and MAC addresses)
	
setOptionVerbose(0..1)			
	Show VERBOSE messages

setOptionDebug(0..1)				
	Show DEBUG messages.   This is useful for tracking down problems.

setOptionDebugFile("console" or pathname)	
	Output to console or file.  Default is 'console'.

setOptionDumpBadPacketsOnly(0..1)		
	Dump bad packets ONLY (UPNP only)

setOptionDumpPackets(0..1)			
	Dump network packets (UPNP only)

setDumpPath(pathname)				
	Set path for dump files.  Defaults to current directory.
	NOTE: Has no effect when using SNMP.

setBroadcastAddress(IP Address)		
	Set broadcast address.  (Default is 255.255.255.255).  
	NOTE: Has no effect when using SNMP.

setDestinationAddress(IP Address)
	Scan this specific ReadyNAS unit.
	Please note that adding an IP directly will effectively shut off 
        any discovery/auto-detection.
	NOTE: This is the original call now replaced by "addUnit".

setSocketBufferSize(bytes)			
	Set socket buffer size (bytes).  Recommend not changing this.  
	Default is 16K (16384).   
	NOTE: Has no effect when using SNMP.

setInfrantCID(DWORD)				
	Set client ID for request.  
	NOTE: Has no effect when using SNMP.

setInfrantSID(DWORD)				
	Set server ID for request.
	WARNING: Changing this will result in the ReadyNAS ignoring you!
	NOTE: Has no effect when using SNMP.

setSrcPort(WORD)				
	Set source port for request.  31000 is the default.
	NOTE: Has no effect when using SNMP.

setDstPort(WORD)
	Set destination port for request. 22081 is the default for
	MULTICAST and UNICAST.  161 is the default for SNMP.
	Recommend not changing this as the ReadyNAS may not respond.

setDstSNMPPort(WORD)
	Set destination port for SNMP request. 161 is the default.
	Recommend not changing this as the ReadyNAS may not respond.

setSocketTimeout(Seconds)			
	Set socket timeout (seconds), default is 15 seconds for MULTICAST
	and SNMP, default is 10 seconds for UNICAST.

setSocketErrorTimeout(Seconds)		
	Set socket error timeout (seconds) (Multicast Only). Default is 2
	seconds.
	NOTE: Has no effect when using SNMP.

setCommunity(string)				
	Set the SNMP Community (SNMP Only).  Default is "public".
	NOTE: Has no effect when using UPNP.
	
******************************************************************************
External Function Calls:
******************************************************************************

loadReadyNASLibrary(string)
	Loads the appropriate library based upon the contents of 'string'.  
	Valid values are "SNMP", "MULTICAST" and "UNICAST".  It is not
	case-sensitive.    
	(Used with the LOADER library only.  
	The other libraries have a dummy call that always returns 1).
	
loadReadyNASData(void) 
	Uses UPNP to discover units and loads internal structures.  
	(Optionally returns the entire raw data block, except for the 
	SNMP version of the library.)
	
getBytesRead(void) 
	Returns an integer with the byte count of data read over
	the network.

getUnitAddresses(void) 
	Returns a sorted, | delimited list of IP addresses of
	ReadyNAS units that information is available on.

getUnitMACs(void) 
	Returns a sorted, | delimited list of MAC addresses (in
	mac_index format) of ReadyNAS units that information is
	available on.

getUnitHosts(void) 
	Returns a sorted, | delimited list of hostnames of
	ReadyNAS units that information is available on.

getUnitCount(void) 
	Returns a count of the number of ReadyNAS units that 
	information is available on.

getUnitData(IP Address) 
	Returns the raw data packet for the IP address given.  
	NOTE: SNMP version this returns the IP address passed in.

getLibraryVersion(void) 
	Returns a string with the version number of the library.
	e.g. "200904300056"

getLibraryTitle(void) 
	Returns a string with the title of the library.
	e.g. "UPNP-MULTICAST NETGEAR ReadyNAS Perl Communications Library"

parseReadyNASData(raw_packet) 
	Returns a macindex of the raw_packet (or IP with the SNMP version)

getUnitIP(mac_index)
	Returns the IP address of the unit

getUnitMAC(IP Address)
	Returns the macindex of the unit

getLastError(void)
	Returns the most recent error text
	(NOTE: This isn't really implemented yet but will be as more
	error checking and recovery is added.)

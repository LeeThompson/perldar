#-------------------------------------------------------------
# Sample script for the ReadyNAS Perl library
#-------------------------------------------------------------

use POSIX qw( strftime getcwd );
use Time::Local;

#-------------------------------------------------------------
# Load the library 
#-------------------------------------------------------------

require 'readynas.pl';			# Loader
loadReadyNASLibrary("MULTICAST");	# Select Library to Use
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
setOptionDumpPackets(0);	 # Write packets to disk
setOptionDumpBadPacketsOnly(0);	 # Write ONLY bad packets to disk
setSocketTimeout(1);	 	 # Set Socket Timeout (Seconds)
# setSocketErrorTimeout(30);	 # Set Socket Error Timeout (Seconds) (MULTICAST ONLY)
# setCommunity("public"); 	 # Set SNMP Community (SNMP Only)

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

	#------------------------------------------------------------#
	# Add NETGEAR ReadyNAS unit at IP address to the list to     #
	# gather information from.                                   #
	#------------------------------------------------------------#

#-------------------------------------------------------------
# Full pathname to the stats file
#-------------------------------------------------------------

$fname = "nas.html";

my $_VERSION = "201003141246";

#-------------------------------------------------------------
# Gather ReadyNAS Data
#-------------------------------------------------------------

loadReadyNASData();

if (getBytesRead() < 1) {
	exit(1);
}

#-------------------------------------------------------------
# Get a list of IP addresses of Units we now have data on
#-------------------------------------------------------------
	
$units = getUnitAddresses();
$unitcount = getUnitCount();

if ($unitcount > 0) {
	
}else{
	exit(1);
}

$now = strftime( "%Y-%m-%d", localtime ) . " " . strftime( "%H:%M:%S", localtime );

#-------------------------------------------------------------
# Build Web Page
#-------------------------------------------------------------

open(HOUTPUT,">$fname");

print HOUTPUT "<html><head>\n";
print HOUTPUT "<meta http-equiv=\"Pragma\" content=\"no-cache\">\n";
print HOUTPUT "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\">\n";
print HOUTPUT "<meta http-equiv=\"refresh\" content=\"60\">\n";
print HOUTPUT "<TITLE>NETGEAR ReadyNAS Status Page</TITLE>\n";
print HOUTPUT "<head>\n";
print HOUTPUT "<BODY bgcolor=\#FFFFFF text=\#000000 vlink=\#0000A0 alink=\#0000FF link=\#0000D0>\n";
print HOUTPUT "<H1><font face=\"Tahoma\">NETGEAR ReadyNAS Server Status</h1><p></font>\n";
print HOUTPUT "Generated at $now<p>";
print HOUTPUT "<table border=1>\n";
print HOUTPUT "<tr><td>Server Information<td>Temperatures</tr>\n";


my $i = 0;

for ( split /\|/, $units ) {
	/\|/;
	if ($_ ne "") {
		$i++;
		$macindex = parseReadyNASData(getUnitData($_));
		$nasindex{$_} = $macindex;

		print HOUTPUT "<tr>";
		print HOUTPUT "<td><font face=\"Tahoma\">";
		print HOUTPUT "<a href=http://" . lc getAdminAddress($unit{$macindex}{ipaddr}{0}) . "/admin>";
		print HOUTPUT "$unit{$macindex}{hostname}{0}";
		print HOUTPUT "</a>";
		print HOUTPUT "<br>$unit{$macindex}{models}{0}";
		print HOUTPUT "<hr>";
		print HOUTPUT "<small>";
		print HOUTPUT "O/S: $unit{$macindex}{os}{0}";
		print HOUTPUT "<br>MAC: $unit{$macindex}{mac}{0}";
		print HOUTPUT "<br>TCP: $unit{$macindex}{ipaddr}{0}";
		print HOUTPUT "<br>FAN: $unit{$macindex}{fan}{0}";
		print HOUTPUT "<br>BOOT: $unit{$macindex}{boot}{0}";
		print HOUTPUT "<br>MEM: $unit{$macindex}{system}{memory}{0}\n";
		print HOUTPUT "<br>SYS: $unit{$macindex}{system}{processes}{0}\n";
		print HOUTPUT "<br>UPT: $unit{$macindex}{system}{uptime}{0}\n";
		print HOUTPUT "<p>$unit{$macindex}{volumes}{0}";
		print HOUTPUT "</small>";
		if ($unit{$macindex}{tmps}{0} ne "N/A") 
		{
			print HOUTPUT "<td><font face=\"Tahoma\">"; 
			my $temp_c =  substr($unit{$macindex}{tmps}{1}{desc},0,2);
			my $font_color = "";

			if ($temp_c < 61) {
				$font_color = "\#FF0000";
			}	
			if ($temp_c < 56) {
				$font_color = "\#900000";
			}
			if ($temp_c < 51) {
				$font_color = "\#400000";
			}
			if ($temp_c < 41) {
				$font_color = "\#004000";
			}
			if ($temp_c < 31) {
				$font_color = "\#000040";
			}	
			if ($temp_c < 21) {
				$font_color = "\#000090";
			}
			if ($temp_c < 11) {
				$font_color = "\#0000FF";
			}
			print HOUTPUT "<font color=$font_color>";
			print HOUTPUT "<br>0: $unit{$macindex}{tmps}{1}{desc} System Core";
			print HOUTPUT "</font>";
		}else{
			print HOUTPUT "<td><font face=\"Tahoma\">"; 
			print HOUTPUT "<br>N/A";
			print HOUTPUT "</font>";
		}
		
		if ($unit{$macindex}{disks}{0} ne "N/A") {
			for ( $instance = 1; $instance < ($unit{$macindex}{disks}{0}{records} + 1); $instance++) {
				print HOUTPUT "<br>";
	
				my $temp_c =  substr($unit{$macindex}{disks}{$instance}{tmps},0,2);
				my $font_color = "";
	
				if ($temp_c < 61) {
					$font_color = "\#FF0000";
				}	
				if ($temp_c < 56) {
					$font_color = "\#900000";
				}
				if ($temp_c < 51) {
					$font_color = "\#400000";
				}
				if ($temp_c < 41) {
					$font_color = "\#004000";
				}
				if ($temp_c < 31) {
					$font_color = "\#000040";
				}
				if ($temp_c < 21) {
					$font_color = "\#000090";
				}
				if ($temp_c < 11) {
					$font_color = "\#0000FF";
				}
				print HOUTPUT "<font color=$font_color>";
				print HOUTPUT "$unit{$macindex}{disks}{$instance}{channel}: ";
				print HOUTPUT "$unit{$macindex}{disks}{$instance}{tmps} ";
				print HOUTPUT "$unit{$macindex}{disks}{$instance}{model} ";
				if (uc $unit{$macindex}{disks}{$instance}{errors} eq "NONE") {
					print HOUTPUT "(" . uc $unit{$macindex}{disks}{$instance}{status} . ")";
				}else{
					print HOUTPUT "(" . uc $unit{$macindex}{disks}{$instance}{status} . ";" . $unit{$macindex}{disks}{$instance}{errors} . ")";
				}
	
				print HOUTPUT "</font>";
			}
		}
 		print HOUTPUT "</tr>\n";
	}
}

print HOUTPUT "</table>\n";
print HOUTPUT "<p><small>sample_webstats.pl v$_VERSION (" . getLibraryTitle() . " v" . getLibraryVersion() . ")\n";
print HOUTPUT "</body><html>\n";

close HOUTPUT;

exit(0);


#-------------------------------------------------------------
sub getAdminAddress{
	my $ipaddr = shift;
	my $dnsname= "";
	
	if ($dnsname eq "") {
		((my $host, my $aliases, my $addrtype, my $len, my @addrlist) = gethostbyaddr(inet_aton($ipaddr), AF_INET));
		$dnsname = $host;
	}

	if ($dnsname eq "") {
		$dnsname = gethostbyaddr(inet_aton($ipaddr),AF_INET);
	}

	if ($dnsname eq "") {
		$dnsname = $unit{$macindex}{hostname}{0};
	}
	
	if ($dnsname eq "") {
		$dnsname = $ipaddr;
	}

	return $dnsname;
}

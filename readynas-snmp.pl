#-----------------------------------------------------------------------------
# NETGEAR ReadyNAS Communications Library for Perl
# by Lee Thompson <thompsonl@logh.net>
#-----------------------------------------------------------------------------
# SNMP VERSION
#-----------------------------------------------------------------------------
# This library is for getting status information from Netgear ReadyNAS units  
# for use in status page generation, reports and other alerts.  It is provided
# free of charge and without warranty.
#-----------------------------------------------------------------------------
# NOTE: If none or only some of your ReadyNAS units are detected, try 
# lengthening the socket and socket error timeouts.
#-----------------------------------------------------------------------------

#-------------------------------------------
# Program Start
#-------------------------------------------

$_VERSION		 = "201003141246";
$_PROGRAM_SID            = 0xffffffff;
$_PROGRAM_TITLE		 = "SNMP NETGEAR ReadyNAS Perl Communications Library";

#-------------------------------------------
# Load Socket Libraries
#-------------------------------------------

use Net::SNMP;

#-------------------------------------------
# Defaults
#-------------------------------------------

$_DEFAULT_DST_ADDR	       	= "127.0.0.1";
$_DEFAULT_DST_PORT		= 161;
$_DEFAULT_COMMUNITY		= "public";

$_DEFAULT_OPT_DEBUG_FILE 	= "console";
$_DEFAULT_OPT_DEBUG	 	= 0;
$_DEFAULT_OPT_VERBOSE    	= 0;
$_DEFAULT_OPT_UNIQUE_HOSTS	= 0;

$_DEFAULT_SOCKET_TIMEOUT	= 15;

$_OUTPUT_VERBOSE 		= 1;
$_OUTPUT_DEBUG   		= 2;
$_OUTPUT_TRACE	 		= 3;

#-------------------------------------------
# Module Variables
#-------------------------------------------

my $dst_address			= $_DEFAULT_DST_ADDR;
my $dst_port			= $_DEFAULT_DST_PORT;
my $dst_community		= $_DEFAULT_COMMUNITY;

my $socket_timeout       	= $_DEFAULT_SOCKET_TIMEOUT;

my $option_unique_hosts 	= $_DEFAULT_OPT_UNIQUE_HOSTS;
my $option_verbose      	= $_DEFAULT_OPT_VERBOSE;
my $option_debug       		= $_DEFAULT_OPT_DEBUG;
my $option_debug_file   	= $_DEFAULT_OPT_DEBUG_FILE;

my $unit_data			= "";
my $unit_count 		 	= 0;
my $unit_list		 	= "";
my $unit_macs		 	= "";
my $unit_host			= "";
my $query_list		 	= "";
my $query_count	        	= 0;
my $mac_table 		 	= "";
my $ip_table		 	= "";

my $bytes_read			= 0;

my $last_error		 	= "";

#------------------------------------------------------------
# Primary Calls
#------------------------------------------------------------

#------------------------------------------------------------
sub loadReadyNASData{
	my $add_record = 0;
	my $reject_reason = "";
	my $mac_address = "";
        my $hostname = "";
	my $count = 0;
	my $address = "";

	identifyProgram();

	if (getQueryUnitCount() == 0) {
		addUnit(getDestinationAddress());
	}

	writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","Querying " . getQueryUnitCount() . " Unit(s)");
	writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","Address List: " . getQueryUnitAddresses());

	if (getQueryUnitCount()) {
		my $address_list = getQueryUnitAddresses();

		for ( split /\|/, $address_list ) {
			/\|/;
			$address = $_;
			$add_record = 0;
			$reject_reason = "";
			$mac_address = "";
			$hostname = "";

			writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","$count: Processing $address");

			if ($address ne "") {
				if (deviceIsReadyNAS($address)) {
					setDestinationAddress($address);
					$mac_address = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.2.1.2.2.1.6.2");
					$mac_address = substr(uc $mac_address,2);

					$hostname = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.2.1.1.5.0");

					if (alreadyInList($address,$unit_list)) {
						$reject_reason = "IP Already Present";
					}else{
						if ($mac_address ne "") {
							if (alreadyInList($mac_address,$unit_macs)) {
								$reject_reason = "MAC Already Present";
							}else{
								if (getOptionRequireUniqueHosts()) {
									if (alreadyInList($hostname,$unit_host)) {
										$reject_reason = "HOSTNAME Already Present";
									}else{
										$add_record = 1;
									}
								}else{
									$add_record = 1;
								}
							}
						}else{
							$reject_reason = "MAC Address was null!";
						}
					}

				}else{
					$reject_reason = "Device not ReadyNAS!";
				}
			}else{
				$reject_reason = "IP Address was null!";
			}

			if ($add_record) {
				if (gatherData($address)) {
					writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","$count: Found Data Record");
					writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","$count: Adding Data Block to Array");
					writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","$count: Adding $address to Unit List");
					$unit_list .= "|$address";
					$unit_macs .= "|$mac_address";
					$unit_host .= "|$hostname";
					$unit_count++;
					$count++;
					$ip_table{$address} = $mac_address;
					$mac_table{$mac_address} = $address;
				}else{
					writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","$count: Fatal Error. " . getLastError());
				}
			}else{
				writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","$count: $reject_reason");
			}

		}
	}else{
		writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","Error: No units to process!");
		$last_error = "No units to process!";
		return;
	}

	writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","Read " . getBytesRead() . " bytes");
	
	return;
}

#------------------------------------------------------------
sub identifyProgram{
	writeLog($_OUTPUT_VERBOSE,"identifyProgram","$_PROGRAM_TITLE v$_VERSION");

	writeLog($_OUTPUT_VERBOSE,"identifyProgram","       Verbose: " . getOptionVerbose());
	writeLog($_OUTPUT_VERBOSE,"identifyProgram","    Debug Mode: " . getOptionDebug());
	writeLog($_OUTPUT_VERBOSE,"identifyProgram","        Output: " . getOptionDebugFile());

	return 1;
}

#------------------------------------------------------------
# External Calls - Compatiblity
#------------------------------------------------------------

#------------------------------------------------------------
sub parseReadyNASData{
	# This function works a bit differently than the
	# original but is here for compatiblity purposes.
	#
	# Pass in an IP address and it will return the MAC
	# address (in 'macindex' format) of the unit.  
	#----------------------------------------------------

	my $ip_addr = shift;
	my $mac_addr = "";

	$mac_addr = $unit_data{$ip_addr};

	return $mac_addr;
}


#------------------------------------------------------------
sub getUnitData{
	# This function works a bit differently than the
	# original but is here for compatiblity purposes.
	#
	# in the original library the IP address was passed
	# in and the raw UDP packet was returned.
	# 
	# In this case, it simply returns the IP address 
	# since the raw packets aren't used in this version.
	#----------------------------------------------------

	my $ip_addr = shift;

	return $ip_addr;
}

#------------------------------------------------------------
# SNMP Functions
#------------------------------------------------------------

#------------------------------------------------------------
sub getSNMPData{
	my $hostname = shift;
	my $community = shift;
	my $port = shift;
	my $mib = shift;

	my $data = "";

	writeLog($_OUTPUT_DEBUG,"getSNMPData","hostname=$hostname");
	writeLog($_OUTPUT_DEBUG,"getSNMPData","community=$community");
	writeLog($_OUTPUT_DEBUG,"getSNMPData","port=$port");
	writeLog($_OUTPUT_DEBUG,"getSNMPData","mib=$mib");

	writeLog($_OUTPUT_DEBUG,"getSNMPData","Initializing SNMP Session");

  	my ($session, $error) = Net::SNMP->session(
    	      -version   => 'snmpv2c',
	      -hostname  => $hostname,
      	      -community => $community,
      	      -port      => $port,
	      -timeout   => getSocketTimeout()
   	);

	my $sysObject = $mib;

	writeLog($_OUTPUT_DEBUG,"getSNMPData","Requesting Data");

	my $result = $session->get_request(
		-varbindlist => [$sysObject]
	);

	if (!defined($result)) {
		$last_error = $session->error;
		$data = "";
		writeLog($_OUTPUT_DEBUG,"getSNMPData","SNMP Error: " . getLastError());
	}else{
		$data = $result->{$sysObject};
		writeLog($_OUTPUT_DEBUG,"getSNMPData","SNMP Returned: $data");
	}

	writeLog($_OUTPUT_DEBUG,"getSNMPData","Closing Session");

	$session->close;

	writeLog($_OUTPUT_DEBUG,"getSNMPData","Exiting");
	
	$bytes_read = $bytes_read + length($data);

	return $data;
}

#------------------------------------------------------------
# External Calls
#------------------------------------------------------------

#-----------------------------
sub getUnitMACs{
	my $sorted_list;
	my @units = split(/\|/, $unit_macs );

	@units = sort(@units);
	$sorted_list = join("|",@units);
	
	return $sorted_list;
}

#-----------------------------
sub getUnitHosts{
	my $sorted_list;
	my @units = split(/\|/, $unit_host );

	@units = sort(@units);
	$sorted_list = join("|",@units);
	
	return $sorted_list;
}

#-----------------------------
sub getUnitAddresses{
	my $sorted_list;
	my @units = split(/\|/, $unit_list );

	@units = sort(@units);
	$sorted_list = join("|",@units);
	
	return $sorted_list;
}

#-----------------------------
sub getOptionRequireUniqueHosts{
	return $option_unique_hosts;
}

#-----------------------------
sub setOptionRequireUniqueHosts{
	$option_unique_hosts = shift;
	return 1;
}

#-----------------------------
sub setSocketErrorTimeout{
	return 1;
}

#-----------------------------
sub setInfrantCID{
	return 1;
}

#-----------------------------
sub setInfrantSID{
	return 1;
}

#-----------------------------
sub setSocketBufferSize{
	return 1;
}

#-----------------------------
sub getBytesRead{
	return $bytes_read;
}

#-----------------------------
sub getUnitCount{
	return $unit_count;
}

#-----------------------------
sub getLastError{
	return $last_error;
}

#-----------------------------
sub getLibraryVersion{
	return $_VERSION;
}

#-----------------------------
sub getLibraryTitle{
	return $_PROGRAM_TITLE;
}

#-----------------------------
sub getCommunity{
	return $dst_community;
}

#-----------------------------
sub getDestinationAddress{
	return $dst_address;
}

#-----------------------------
sub getDstPort{
	return $dst_port;
}

#-----------------------------
sub getDstSNMPPort{
	return getDstPort();
}

#-----------------------------
sub setDstSNMPPort{
	setDstPort(shift);
	return 1;
}

#-----------------------------
sub getOptionVerbose{
	return $option_verbose;
}

#-----------------------------
sub getOptionDebug{
	return $option_debug;
}

#-----------------------------
sub getOptionDebugFile{
	return $option_debug_file;
}

#-----------------------------
sub getUnitCount{
	return $unit_count;
}

#-----------------------------
sub setDestinationAddress{
	$dst_address = shift;
	return 1;
}

#-----------------------------
sub setDstPort{
	$dst_port = int shift;
	return 1;
}

#-----------------------------
sub setCommunity{
	$dst_community = shift;
	return 1;
}

#-----------------------------
sub setDumpPath{
	return 1;
}

#-----------------------------
sub setSrcPort{
	return 1;
}

#-----------------------------
sub setOptionDumpPackets{
	return 1;
}

#-----------------------------
sub setOptionDumpBadPacketsOnly{
	return 1;
}

#-----------------------------
sub setBroadcastAddress{
	return 1;
}

#-----------------------------
sub getBroadcastAddress{
	return;
}

#-----------------------------
sub setOptionDebugFile{
	$option_debug_file = shift;
	return 1;
}

#-----------------------------
sub setSocketTimeout{
	$socket_timeout = int shift;
	return 1;
}

#-----------------------------
sub setOptionVerbose{
	$option_verbose = int shift;
	return 1;
}

#-----------------------------
sub setOptionDebug{
	$option_debug = int shift;
	return 1;
}

#-----------------------------
sub getQueryUnitAddresses{
	my $sorted_list;
	my @units = split(/\|/, $query_list );

	@units = sort(@units);
	$sorted_list = join("|",@units);
	
	return $sorted_list;
}

#-----------------------------
sub getQueryUnitCount{
	return $query_count;
}

#----------------------------------------------------------------------
sub addUnit{
	my $address = shift;
	my $retval = 0;

	if ($address ne "") {
		if (alreadyInList($address,$query_list)) {
			writeLog($_OUTPUT_VERBOSE,"addUnit","Already Present");
			$retval = 2;	
		}else{
			writeLog($_OUTPUT_VERBOSE,"addUnit","Adding $address to Unit List");
			$query_list .= "|$address";
			$query_count++;
			$retval = 1;
		}
	}else{
		writeLog($_OUTPUT_VERBOSE,"addUnit","Address was null!");
	}

	return;
}

#-----------------------------
sub getUnitIP{
	my $mac_address = shift;
	my $ip_address = $mac_table{$mac_address};
	return $ip_address;
}

#-----------------------------
sub getUnitMAC{
	my $ip_address = shift;
	my $mac_address = $ip_table{$ip_address};
	return $mac_address;
}

#------------------------------------------------------------
# Internal Calls
#------------------------------------------------------------

#-----------------------------
sub getSocketTimeout{
	return $socket_timeout;
}

#-----------------------------
sub getLastOctet{
	my $ipaddr = shift;
	(my $a,my $b,my $c,my $d) =  ( split /\./, $ipaddr, 4);
	return $d;
}

#-----------------------------
sub getNumericAddress{
	my $ipaddr = shift;
	my $numaddr = 0;
	(my $a,my $b,my $c,my $d) =  ( split /\./, $ipaddr, 4);
	$numaddr = ($a * 16777216) + ($b * 65536) + ($c * 256) + $d;
	return $numaddr;
}

#----------------------------------------------------------------------
sub getMACIndex {
	my $tempvar = shift;
	
	$tempvar =~ s/\://g;

	return $tempvar;
}

#----------------------------------------------------------------------
sub addCommaString{
	my $original = shift;
	my $new = shift;
	my $flag_end = int shift;
	my $updated_string = "";

	if (length($original) < 1) {
		$updated_string = $new;
	}else{
		$updated_string = "$original, $new";
	}

	if ($flag_end) {
		$updated_string .= ".";
	}

	return $updated_string;
}
#----------------------------------------------------------------------
sub trimString {
	my $tempvar = shift;

    	$tempvar =~ s/^\s+//;
    	$tempvar =~ s/\s+$//;

	return $tempvar;
}
#----------------------------------------------------------------------
sub alreadyInList {
	my $searchfor = shift;
	my $templist = shift;

	my $retcode = 0;

	for ( split /\|/, $templist ) {
		/\|/;
		if ($_ eq $searchfor) {
			$retcode = 1;
		}
	}

	return $retcode;
}

#------------------------------------------------------------

#-----------------------------
sub deviceIsReadyNAS{
	my $address = shift;
	my $is_readynas = 0;
	my $old_address = getDestinationAddress();

	#-----------------------------------------------#
	# Determine if it's a readyNAS unit or not.	#	
	# Right now the best way appears to be to check	#
	# the OS version property.			#
	#-----------------------------------------------#

	setDestinationAddress($address);
	my $os_ver = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.1.0");
	setDestinationAddress($old_address);

	if ($os_ver eq "noSuchObject") {
		$is_readynas = 0;
	}else{
		$is_readynas = 1;
	}

	return $is_readynas;
}

#------------------------------------------------------------
sub gatherData{
	#------------------------------------------------------------------------------
	# This is really ugly and cheesy code and I apologize to anyone reading this.
	#
	# The problem is 1.3.6.1.4.1.4526.18.3.1.1 doesn't return the number of
	# instances so this has to kinda blindly stumble through and figure it out.
	#
	# Chances are I will rewrite this entire function at some point.
	#
	#------------------------------------------------------------------------------

	my $address = shift;

	my $macindex = "";
	my $retval = 0;

	setDestinationAddress($address);
	my $ipaddr = $address;

	#----------------------------
	# Do SNMP Calls
	#----------------------------
	
	my $mac_addr = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.2.1.2.2.1.6.2");
	my $hostname = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.2.1.1.5.0");
	my $uptime = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.2.1.1.3.0");
	my $os_ver = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.1.0");
	my $sys_fan = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.4.1.2.1");
	my $sys_status = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.5.1.3.1");
	my $sys_temp = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.5.1.2.1");
	my $volume_name = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.7.1.2.1");
	my $volume_raid = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.7.1.3.1");
	my $volume_status = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.7.1.4.1");
	my $volume_size = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.7.1.5.1");
	my $volume_free = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.7.1.6.1");
	my $disks_channel_1 = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.3.1.2.1");
	my $disks_channel_2 = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.3.1.2.2");
	my $disks_channel_3 = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.3.1.2.3");
	my $disks_channel_4 = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.3.1.2.4");
	my $disks_model_1 = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.3.1.3.1");
	my $disks_model_2 = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.3.1.3.2");
	my $disks_model_3 = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.3.1.3.3");
	my $disks_model_4 = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.3.1.3.4");
	my $disks_state_1 = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.3.1.4.1");
	my $disks_state_2 = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.3.1.4.2");
	my $disks_state_3 = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.3.1.4.3");
	my $disks_state_4 = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.3.1.4.4");
	my $disks_temps_1 = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.3.1.5.1");
	my $disks_temps_2 = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.3.1.5.2");
	my $disks_temps_3 = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.3.1.5.3");
	my $disks_temps_4 = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.4.1.4526.18.3.1.5.4");
	my $sys_processes = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.2.1.25.1.6.0");
	my $sys_memory = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.2.1.25.2.2.0");
	my $sys_uname = getSNMPData(getDestinationAddress(),getCommunity(),getDstPort(),"1.3.6.1.2.1.1.1.0");

	#---------------------------------
	# Process & Calculate Data
	#---------------------------------

	$mac_addr = substr(uc $mac_addr,2);
	$macindex = $mac_addr;
	my $mac_address = substr($macindex,0,2) . ":" . substr($macindex,2,2) . ":" . substr($macindex,4,2) . ":" . substr($macindex,6,2) . ":" . substr($macindex,8,2) . ":" . substr($macindex,10,2);

	my $volume_used = int ($volume_size - $volume_free);
	my $volume_used_percent = int (($volume_used / $volume_size) * 100);

	if ($disks_model_1 eq "noSuchInstance") {
		$disks_model_1 = "N/A";
	}
	if ($disks_model_2 eq "noSuchInstance") {
		$disks_model_2 = "N/A";
	}
	if ($disks_model_3 eq "noSuchInstance") {
		$disks_model_3 = "N/A";
	}
	if ($disks_model_4 eq "noSuchInstance") {
		$disks_model_4 = "N/A";
	}

	$disks_state_1 = uc $disks_state_1;
	$disks_state_2 = uc $disks_state_2;
	$disks_state_3 = uc $disks_state_3;
	$disks_state_4 = uc $disks_state_4;

	my $disks_errors_1 = "";
	my $disks_errors_2 = "";
	my $disks_errors_3 = "";
	my $disks_errors_4 = "";

	my $disks_count = 0;
	if ($disks_model_1 ne "N/A") {
		$disks_count++;
	}
	if ($disks_model_2 ne "N/A") {
		$disks_count++;
	}
	if ($disks_model_3 ne "N/A") {
		$disks_count++;
	}
	if ($disks_model_4 ne "N/A") {
		$disks_count++;
	}

	($disks_temps_1,my $disks_errors_1) = split(/;/,$disks_temps_1,2);
	($disks_temps_2,my $disks_errors_2) = split(/;/,$disks_temps_2,2);
	($disks_temps_3,my $disks_errors_3) = split(/;/,$disks_temps_3,2);
	($disks_temps_4,my $disks_errors_4) = split(/;/,$disks_temps_4,2);

	if ($disks_temps_1 eq "") {
		$disks_temps_1 = "N/A";
	}
	if ($disks_temps_2 eq "") {
		$disks_temps_2 = "N/A";
	}
	if ($disks_temps_3 eq "") {
		$disks_temps_3 = "N/A";
	}
	if ($disks_temps_4 eq "") {
		$disks_temps_4 = "N/A";
	}
	if ($disks_errors_1 eq "") {
		$disks_errors_1 = "None";
	}
	if ($disks_errors_2 eq "") {
		$disks_errors_2 = "None";
	}
	if ($disks_errors_3 eq "") {
		$disks_errors_3 = "None";
	}
	if ($disks_errors_4 eq "") {
		$disks_errors_4 = "None";
	}

 	$sys_fan .= "RPM";

	if ($volume_status eq "ok") {
		$volume_status_original = $volume_status;
		$volume_status = "Redundant";
	}

	my $volume_desc = "$volume_name:$volume_raid, $volume_status. $volume_used MB ($volume_used_percent%) of " . int ($volume_size/1024) . " GB used";
	my $model_desc = "ReadyNAS";
	my $os_name = "RAIDiator";

	#---------------------------------
	# Verify MAC Address
	#---------------------------------

	if (length($mac_address) != 17) {
		return;
	}

	#---------------------------------
	# Update Tables
	#---------------------------------

	writeLog($_OUTPUT_DEBUG,"gatherData","Data Valid");
	writeLog($_OUTPUT_DEBUG,"gatherData","Using $macindex as Index");
	writeLog($_OUTPUT_DEBUG,"gatherData","Adding $macindex to address table for $address");

	$unit_data{$ipaddr} = $macindex;

	$ip_table{$ipaddr} = $macindex;
	$mac_table{$macindex} = $ipaddr;

	#----------------------------
	# Build Array
	#----------------------------

	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Building Arrays");
	writeLog($_OUTPUT_VERBOSE,"gatherData","$macindex: Adding MAC");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/mac/1/desc=$mac_address");

	$unit{$macindex}{mac}{1}{desc} =  trimString($mac_address);
	$unit{$macindex}{mac}{0} = $unit{$macindex}{mac}{1}{desc};
	$unit{$macindex}{mac}{0}{records} = 1;

	writeLog($_OUTPUT_VERBOSE,"gatherData","$macindex: Adding HOST");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/hostname/1/desc=$hostname");

	$unit{$macindex}{hostname}{1}{desc} = trimString($hostname);
	$unit{$macindex}{hostname}{0} = $unit{$macindex}{hostname}{1}{desc};
	$unit{$macindex}{hostname}{0}{records} = 1;

	writeLog($_OUTPUT_VERBOSE,"gatherData","$macindex: Adding IP Address");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/ipaddr/1/desc=$ipaddr");

	$unit{$macindex}{ipaddr}{1}{desc} = trimString($ipaddr);
	$unit{$macindex}{ipaddr}{0} = $unit{$macindex}{ipaddr}{1}{desc};
	$unit{$macindex}{ipaddr}{0}{records} = 1;

	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/1/channel=" . trimString($disks_channel_1));
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/1/model=" . trimString($disks_model_1));
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/1/tmps=" . trimString($disks_temps_1));
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/1/errors=" . trimString($disks_errors_1));
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/1/status=" . trimString($disks_state_1));

	$unit{$macindex}{disks}{1}{channel} = trimString($disks_channel_1);
	$unit{$macindex}{disks}{1}{model} = trimString($disks_model_1);
	$unit{$macindex}{disks}{1}{tmps} = trimString($disks_temps_1);
	$unit{$macindex}{disks}{1}{errors} = trimString($disks_errors_1);
	$unit{$macindex}{disks}{1}{status} = trimString($disks_state_1);

	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/2/channel=" . trimString($disks_channel_2));
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/2/model=" . trimString($disks_model_2));
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/2/tmps=" . trimString($disks_temps_2));
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/2/errors=" . trimString($disks_errors_2));
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/2/status=" . trimString($disks_state_2));

	$unit{$macindex}{disks}{2}{channel} = trimString($disks_channel_2);
	$unit{$macindex}{disks}{2}{model} = trimString($disks_model_2);
	$unit{$macindex}{disks}{2}{tmps} = trimString($disks_temps_2);
	$unit{$macindex}{disks}{2}{errors} = trimString($disks_errors_2);
	$unit{$macindex}{disks}{2}{status} = trimString($disks_state_2);

	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/3/channel=" . trimString($disks_channel_3));
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/3/model=" . trimString($disks_model_3));
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/3/tmps=" . trimString($disks_temps_3));
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/3/errors=" . trimString($disks_errors_3));
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/3/status=" . trimString($disks_state_3));

	$unit{$macindex}{disks}{3}{channel} = trimString($disks_channel_3);
	$unit{$macindex}{disks}{3}{model} = trimString($disks_model_3);
	$unit{$macindex}{disks}{3}{tmps} = trimString($disks_temps_3);
	$unit{$macindex}{disks}{3}{errors} = trimString($disks_errors_3);
	$unit{$macindex}{disks}{3}{status} = trimString($disks_state_3);

	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/4/channel=" . trimString($disks_channel_4));
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/4/model=" . trimString($disks_model_4));
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/4/tmps=" . trimString($disks_temps_4));
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/4/errors=" . trimString($disks_errors_4));
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/disks/4/status=" . trimString($disks_state_4));

	$unit{$macindex}{disks}{4}{channel} = trimString($disks_channel_4);
	$unit{$macindex}{disks}{4}{model} = trimString($disks_model_4);
	$unit{$macindex}{disks}{4}{tmps} = trimString($disks_temps_4);
	$unit{$macindex}{disks}{4}{errors} = trimString($disks_errors_4);
	$unit{$macindex}{disks}{4}{status} = trimString($disks_state_4);
	$unit{$macindex}{disks}{0}{records} = $disks_count;

	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/tmps/1/desc=" . trimString($sys_temp));
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/tmps/1/status=" . trimString($sys_status));
	$unit{$macindex}{tmps}{1}{desc} = $sys_temp;
	$unit{$macindex}{tmps}{1}{status} = $sys_status;
	$unit{$macindex}{tmps}{0}{records} = 1;

	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/ups/1/desc=N/A");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/ups/1/status=");
	$unit{$macindex}{ups}{1}{status} = "NOT_AVAILABLE";
	$unit{$macindex}{ups}{1}{desc} = "N/A";
	$unit{$macindex}{ups}{0}{records} = 1;

	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/volumes/1/desc=$volume_desc");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/volumes/1/status=$volume_status_original");
	$unit{$macindex}{volumes}{1}{desc} = $volume_desc;
	$unit{$macindex}{volumes}{1}{status} = $volume_status_original; 
	$unit{$macindex}{volumes}{0}{records} = 1;

	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/fan/1/desc=$sys_fan");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/fan/1/status=$sys_status");
	$unit{$macindex}{fan}{1}{desc} = $sys_fan;
	$unit{$macindex}{fan}{1}{status} = $sys_status;
	$unit{$macindex}{fan}{0}{records} = 1;

	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/models/1/desc=$model_desc");
	$unit{$macindex}{models}{1}{desc} = $model_desc;
	$unit{$macindex}{models}{0}{records} = 1;

	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/system/uptime/0=$uptime");
	$unit{$macindex}{system}{uptime}{0} = $uptime;
	$unit{$macindex}{system}{0}{records} = 1;

	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/system/memory/0=$sys_memory");
	$unit{$macindex}{system}{memory}{0} = $sys_memory;
	$unit{$macindex}{system}{0}{records}++;

	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/system/processes/0=$sys_processes");
	$unit{$macindex}{system}{processes}{0} = $sys_processes;
	$unit{$macindex}{system}{0}{records}++;

	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/system/uname/0=$sys_uname");
	$unit{$macindex}{system}{uname}{0} = $sys_uname;
	$unit{$macindex}{system}{0}{records}++;

	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/os/1/name=$os_name");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/os/1/timestamp=0");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/os/1/version=$os_ver");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Adding $macindex/os/1/date=");
	$unit{$macindex}{os}{1}{date} = "";
	$unit{$macindex}{os}{1}{timestamp} = 0;
	$unit{$macindex}{os}{1}{name} = $os_name;
	$unit{$macindex}{os}{0}{records} = 1;
	$unit{$macindex}{os}{1}{version} = $os_ver;

	writeLog($_OUTPUT_VERBOSE,"gatherData","$macindex: Generating Summaries");

	$unit{$macindex}{tmps}{0} = "$unit{$macindex}{tmps}{1}{desc} (" . uc $unit{$macindex}{tmps}{1}{status} . ")";
	$unit{$macindex}{ups}{0} = "$unit{$macindex}{ups}{1}{desc} (" . uc $unit{$macindex}{ups}{1}{status} . ")";
	$unit{$macindex}{volumes}{0} = "$unit{$macindex}{volumes}{1}{desc} (" . uc $unit{$macindex}{volumes}{1}{status} . ")";
	$unit{$macindex}{fan}{0} = "$unit{$macindex}{fan}{1}{desc} (" . uc $unit{$macindex}{fan}{1}{status} . ")";
	$unit{$macindex}{models}{0}{desc} = $unit{$macindex}{models}{1}{desc};
	$unit{$macindex}{models}{0} = $unit{$macindex}{models}{0}{desc};
	$unit{$macindex}{boot}{0} = "N/A";
	
	my $j = int $unit{$macindex}{disks}{0}{records};
	writeLog($_OUTPUT_VERBOSE,"gatherData","$macindex: Building Disk List ( $j Records )");

	$unit{$macindex}{disks}{0}{status} = "";
	$unit{$macindex}{disks}{0}{desc} = "";
	$unit{$macindex}{disks}{0} = "";

	for (my $i = 1; $i < ($j + 1); $i++) {
		$unit{$macindex}{disks}{0}{status} .=  uc $unit{$macindex}{disks}{$i}{status};
		$unit{$macindex}{disks}{0}{desc} .=  $unit{$macindex}{disks}{$i}{desc};
		if (uc $unit{$macindex}{disks}{$i}{errors} eq "NONE") {
			$unit{$macindex}{disks}{0} .= "$unit{$macindex}{disks}{$i}{channel}: " . uc $unit{$macindex}{disks}{$i}{tmps} . " (" . uc $unit{$macindex}{disks}{$i}{status} . ")";
		}else{
			$unit{$macindex}{disks}{0} .= "$unit{$macindex}{disks}{$i}{channel}: " . uc $unit{$macindex}{disks}{$i}{tmps} . " (" . uc $unit{$macindex}{disks}{$i}{status} . ";" . $unit{$macindex}{disks}{$i}{errors} . ")";
		}

		if ($i != $j) {
			$unit{$macindex}{disks}{0}{status} .= "; ";
		 	$unit{$macindex}{disks}{0}{desc} .= "; ";
		 	$unit{$macindex}{disks}{0} .= "; ";
		}
	}
	$unit{$macindex}{disks}{0}{records} = $j;

	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex:    TMPS summary is $unit{$macindex}{tmps}{0}");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex:     UPS summary is $unit{$macindex}{ups}{0}");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: VOLUMES summary is $unit{$macindex}{volumes}{0}");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex:     FAN summary is $unit{$macindex}{fan}{0}");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex:  MODELS summary is $unit{$macindex}{models}{0}");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex:   DISKS summary is $unit{$macindex}{disks}{0}");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex:  UPTIME summary is $unit{$macindex}{system}{uptime}{0}");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex:  MEMORY summary is $unit{$macindex}{system}{memory}{0}");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: PROCESS summary is $unit{$macindex}{system}{processes}{0}");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex:   UNAME summary is $unit{$macindex}{system}{uname}{0}");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex:    BOOT summary is $unit{$macindex}{boot}{0}");
			
	writeLog($_OUTPUT_VERBOSE,"gatherData","$macindex: Processing System Status");


	writeLog($_OUTPUT_VERBOSE,"gatherData","$macindex: Generating System Summary");

	$unit{$macindex}{os}{0} = "$unit{$macindex}{os}{1}{name} v$unit{$macindex}{os}{1}{version}";

	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex:      OS summary is $unit{$macindex}{os}{0}");
	writeLog($_OUTPUT_DEBUG,"gatherData","$macindex: Arrays Completed");

	$retval = 1;

	return $retval;
}

#------------------------------------------------------------
# Debug
#------------------------------------------------------------

#------------------------------------------------------------
sub dumpFile{
	my $filename = shift;
	my $data = shift;
	my $opt_append = int shift;

	my $filemode = ">";

	my $retcode = 0;

	if ($opt_append) {
		$filemode .= ">";
	}
	if (open(HDUMP,"$filemode$filename")) {
		binmode HDUMP;
		print HDUMP $data;
		close HDUMP;
		$retcode = 0;
	}else{
		$retcode = 1;
	}
	return $retcode;
	
}

#------------------------------------------------------------
sub writeLog{
	my $opt_verbose = getOptionVerbose();
	my $opt_debug = getOptionDebug();
	my $opt_debug_file = getOptionDebugFile();
	my $opt_level = int shift;
	my $opt_module = shift;
	my $opt_message = shift;
	my $stdout = 0;
	my $out_msg = "";

	if ($opt_verbose < 1) {
		return;
	}

	if (uc $opt_debug_file eq "CONSOLE") {
		$stdout = 1;	
	}else{
	}

	if ($opt_level > 1) {
		if ($opt_debug) {
			$out_msg = $opt_module . "::" . $opt_message;
		}else{
			return;
		}
	}else{
		$out_msg = $opt_module . "::" . $opt_message;
	}

	if ($stdout) {
		print $out_msg . "\n";
	}else{
		open("HDEBUG",">>$opt_debug_file");
		print HDEBUG $out_msg . "\n";
		close HDEBUG;
	}

	return;
}


#----------------------------------------------------------------------
sub loadReadyNASLibrary{
	return 1;
}

1;


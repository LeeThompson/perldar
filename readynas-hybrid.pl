#-----------------------------------------------------------------------------
# NETGEAR ReadyNAS Communications Library for Perl
# by Lee Thompson <thompsonl@logh.net>
#-----------------------------------------------------------------------------
# UNICAST/SNMP (HYBRID) VERSION
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
$_PROGRAM_TITLE		 = "HYBRID NETGEAR ReadyNAS Perl Communications Library";

#-------------------------------------------
# Load Socket Libraries
#-------------------------------------------

use Socket;
use Net::SNMP;

#-------------------------------------------
# Defaults
#-------------------------------------------

$_DEFAULT_SRC_PORT       	= 31000;
$_DEFAULT_SNMP_PORT		= 161;
$_DEFAULT_COMMUNITY		= "public";
$_DEFAULT_DST_PORT       	= 22081;
$_DEFAULT_DST_ADDR       	= "255.255.255.255";
$_DEFAULT_SRC_ADDR		= "0.0.0.0";
$_DEFAULT_CID		 	= generateCID();
$_DEFAULT_SID		 	= generateSID();
$_DEFAULT_CHECKSUM	 	= 0;
$_DEFAULT_VERSION	 	= 1;
$_DEFAULT_DATASIZE	 	= 28;
$_DEFAULT_OFFSET	 	= 0;
$_DEFAULT_FLAGS	 	 	= 0;

$_DEFAULT_OPT_DEBUG_FILE 	= "console";
$_DEFAULT_OPT_DEBUG	 	= 0;
$_DEFAULT_OPT_VERBOSE    	= 0;
$_DEFAULT_OPT_DUMP_PACKETS 	= 0;
$_DEFAULT_OPT_BAD_PACKETS_ONLY  = 0;
$_DEFAULT_OPT_UNIQUE_HOSTS	= 0;

$_DEFAULT_SOCKET_TIMEOUT	= 10.0;
$_DEFAULT_SOCKET_ERROR_TIMEOUT 	= 2;
$_DEFAULT_SOCKET_BUFFER_SIZE	= 16384;
$_DEFAULT_SOCKET_FLAGS		= 0;

$_DEFAULT_DUMP_PATH 	 	= "./";

$_OUTPUT_VERBOSE 		= 1;
$_OUTPUT_DEBUG   		= 2;
$_OUTPUT_TRACE	 		= 3;

#-------------------------------------------
# Module Variables
#-------------------------------------------

my $dst_port             = $_DEFAULT_DST_PORT;
my $dst_snmp_port        = $_DEFAULT_SNMP_PORT;
my $dst_community	 = $_DEFAULT_COMMUNITY;
my $src_port             = $_DEFAULT_SRC_PORT;
my $src_address          = $_DEFAULT_SRC_ADDR;
my $dst_address		 = $_DEFAULT_DST_ADDR;
my $broadcast            = $_DEFAULT_DST_ADDR;
my $socket_buffer_size	 = $_DEFAULT_SOCKET_BUFFER_SIZE;

my $dump_path		 = $_DEFAULT_DUMP_PATH;

my $ioproxy_cid          = $_DEFAULT_CID;			
my $ioproxy_sid          = $_DEFAULT_SID;				
my $ioproxy_checksum     = $_DEFAULT_CHECKSUM;			
my $ioproxy_version      = $_DEFAULT_VERSION;			
my $ioproxy_datasize     = $_DEFAULT_DATASIZE;			
my $ioproxy_offset       = $_DEFAULT_OFFSET;			
my $ioproxy_flags        = $_DEFAULT_FLAGS;			

my $socket_timeout       = $_DEFAULT_SOCKET_TIMEOUT;
my $socket_error_timeout = $_DEFAULT_SOCKET_ERROR_TIMEOUT;
my $socket_flags	 = $_DEFAULT_SOCKET_FLAGS;

my $option_unique_hosts  = $_DEFAULT_OPT_UNIQUE_HOSTS;
my $option_verbose       = $_DEFAULT_OPT_VERBOSE;
my $option_debug         = $_DEFAULT_OPT_DEBUG;
my $option_debug_file    = $_DEFAULT_OPT_DEBUG_FILE;
my $option_dump_packets	 = $_DEFAULT_OPT_DUMP_PACKETS;
my $option_bad_packets   = $_DEFAULT_OPT_BAD_PACKETS_ONLY;

my @unit_data		 = "";
my $unit_count 		 = 0;
my $unit_list		 = 0;
my $unit_macs		 = "";
my $unit_host		 = "";
my $mac_table 		 = "";
my $ip_table		 = "";
my $query_list		 = "";
my $query_count	         = 0;
my $bytes_read 		 = 0;
my $bytes_sent 		 = 0;

my $debug_buffer	 = "";

my $sock                 = "";
my $iosock               = "";

my $debug_counter	 = 0;

my $last_error		 = "";


#------------------------------------------------------------
# Primary Calls
#------------------------------------------------------------

sub loadReadyNASData{
	my $packet = "";
	my $datarecord = "";
	my $group_datarecord = "";

	identifyProgram();

	if (getQueryUnitCount() == 0) {

		#----------------------------------------------
		# Determine what the default address should be.
		# If destination is explicitly set, use it
		# otherwise use the broadcast address.
		#----------------------------------------------

		my $destination_addr = getDestinationAddress();
		my $broadcast_addr = getBroadcastAddress();
		my $default_addr = "";

		if ($destination_addr ne $_DEFAULT_DST_ADDR) {
			$default_addr = $destination_addr;
		}else{
			$default_addr = $broadcast_addr;
		}
		addUnit($default_addr);
	}

	writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","Querying " . getQueryUnitCount() . " Unit(s)");
	writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","Address List: " . getQueryUnitAddresses());

	if (getQueryUnitCount()) {
		my $address_list = getQueryUnitAddresses();

		for ( split /\|/, $address_list ) {
			/\|/;
			if ($_ ne "") {
				writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","Processing Address: $_");

				setDestinationAddress($_);
				writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","Building Packet");

				$packet = createPacket(getInfrantCID(),getInfrantSID(),getInfrantFlags(),getInfrantOffset());
		
				writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","Opening Socket");
		
				$sock = createUDPSocket();

				writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","Sending Packet");
	
				sendUDPPacket($sock,$packet,getDestinationAddress(),getDstPort());

				writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","Sent " . getBytesSent() . " bytes to " . getDestinationAddress() . ":" . getDstPort());
				writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","Receiving Packets");

				$datarecord = receiveUDPPackets($sock,$iosock);

				if (getBytesRead() < 1) {
					writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","Warning! No data received!");
				}

				writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","$unit_count units processed");
			
				$group_datarecord .= $datarecord;

			}
		}
	}else{
		writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","Error: No units to process!");
		return;
	}

	writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","Read " . getBytesRead() . " bytes");
	writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","Processing Data");

	$unit_count = processReadyNASData($group_datarecord);

	writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","Returning " . length($group_datarecord) . " bytes");
	writeLog($_OUTPUT_VERBOSE,"loadReadyNASData","Exit(" . length($group_datarecord) . ")");

	return $group_datarecord;

}

#------------------------------------------------------------
sub identifyProgram{
	writeLog($_OUTPUT_VERBOSE,"identifyProgram",getLibraryTitle() . " v" . getLibraryVersion());

	writeLog($_OUTPUT_VERBOSE,"identifyProgram","       Verbose: " . getOptionVerbose());
	writeLog($_OUTPUT_VERBOSE,"identifyProgram","    Debug Mode: " . getOptionDebug());
	writeLog($_OUTPUT_VERBOSE,"identifyProgram","        Output: " . getOptionDebugFile());
	writeLog($_OUTPUT_VERBOSE,"identifyProgram","Socket Timeout: " . getSocketTimeout());
	writeLog($_OUTPUT_VERBOSE,"identifyProgram"," Error Timeout: " . getSocketErrorTimeout());

	return 1;
}

#------------------------------------------------------------
sub processReadyNASData{
	my $data = shift;
	my $address = "";
	my $raw = "";
	my $packet_checksum = 0;
	my $computed_checksum = 0;
	my $debug_data = $data;
	my $mac_address = "";
        my $hostname = "";
	my $add_record = 0;
	my $reject_reason = "";

	$unit_list = "";
	$unit_macs = "";
	$unit_host = "";

	writeLog($_OUTPUT_VERBOSE,"processReadyNASData","Start");

	writeLog($_OUTPUT_VERBOSE,"processReadyNASData","Processing Data Stream");

	my $count = 0;

	for ( split /\|/, $data ) {
		/\|/;
		if ($_ ne "") {
			($address,$raw) = split(/=/,$_,2);
			$computed_checksum = computeChecksum(substr($raw,4),0,length(substr($raw,4)));
			$packet_checksum = getUnsignedDWORD(substr($raw,0,4));
			$add_record = 0;
			$reject_reason = "";

			#--------------------------------------#
			# Validate Data			       #
			#--------------------------------------#
			# * Packet Checksum must be correct    #
			# 				       #
			# * Peer address must not be null      #
			#                                      #
			# * Peer address must not already be   # 
			#   in data block		       #	 
			#                                      #
			# * MAC address must not already be in #
			#   data block			       #	
			#                                      #
			# * Hostname must not already be in    #
			#   data block (optional) 	       # 		 
			#--------------------------------------#

			writeLog($_OUTPUT_DEBUG,"processReadyNASData","Validating Packet");
			
			if ($packet_checksum == $computed_checksum) {
				if ($address ne "") {
					if (deviceIsReadyNAS($address)) {
						if (length($raw) > 28) {
							($mac_address,$hostname,my $junk) = split(/\x09/,substr($raw,28),3);
						}
	
						if (length($mac_address) == 17) {
								$mac_address = getMACIndex($mac_address);
							}else{
								$mac_address = "";
								$hostname = "";
						}

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
					}
				}else{
					$reject_reason = "IP Address was null!";
				}


			}else{
				$reject_reason = "Invalid Packet!";
			}

			#--------------------------------------#
			# If record passed our tests, add it   #
			# otherwise, explain why.	       #
			#--------------------------------------#

			if ($add_record) {
				writeLog($_OUTPUT_VERBOSE,"processReadyNASData","$count: Found Data Record");
				$count++;
				writeLog($_OUTPUT_VERBOSE,"processReadyNASData","$count: Adding Data Block to Array");
				writeLog($_OUTPUT_VERBOSE,"processReadyNASData","$count: Adding $address to Unit List");
				$unit_data[getLastOctet($address)] = $raw;
				$unit_list .= "|$address";
				$unit_macs .= "|$mac_address";
				$unit_host .= "|$hostname";
				$ip_table{$address} = $mac_address;
				$mac_table{$mac_address} = $address;
			}else{
				writeLog($_OUTPUT_VERBOSE,"processReadyNASData","$count: $reject_reason");
			}

		}
	}

	writeLog($_OUTPUT_VERBOSE,"processReadyNASData","Counted $count Units");
	writeLog($_OUTPUT_VERBOSE,"processReadyNASData","Exit");

	return $count;

}

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
sub parseReadyNASData{
	my $datarecord = shift;
	my $counter = 0;
	
	writeLog($_OUTPUT_VERBOSE,"parseReadyNASData","Start");

	my $mac_address = "";
	my $hostname = "";
	my $ipaddr = "";
	my $system_fans = "";
	my $system_temps = "";
	my $system_ups = "";
	my $system_volumes = "";
	my $system_disks = "";
	my $system_models = "";
	my $system_os = "";
	my $record_number = 0;
	my $record_data = "";
	my $field_data = "";
	my $parsed_data = "";
	my $system_status = "";

	my $invalid_packet = 0;
	my $invalid_reason = "";
	my $dump_filename = "";

	my $packet_checksum = "";
	my $packet_version = "";
	my $packet_flags = "";
	my $packet_cid = "";
	my $packet_sid = "";
	my $packet_size = "";
	my $packet_offset = "";
	my $computed_checksum = 0;

	my $debug_datarecord = $datarecord;

	if ($datarecord eq "") {
		writeLog($_OUTPUT_VERBOSE,"parseReadyNASData","No Data Passed In");
		return 1;
	}

	$invalid_reason .= "Dump File|" . getLibraryVersion() . "|". length($datarecord) . "|";

	writeLog($_OUTPUT_DEBUG,"parseReadyNASData","Data Record is " . length($datarecord) . " bytes");
	writeLog($_OUTPUT_VERBOSE,"parseReadyNASData","Processing Outer Layer");

	# Parse the header, the checksums have been tested twice already and the
	# other fields have already been tested once by this point so we're just
	# going to skip over this information.    Obviously if you want to do
	# another round of checks, it can be done here.

	$computed_checksum = computeChecksum(substr($datarecord,4),0,length(substr($datarecord,4)));
	$packet_checksum = getUnsignedDWORD(substr($datarecord,0,4));
	$packet_version = getUnsignedDWORD(substr($datarecord,4,4));
	$packet_flags = getUnsignedDWORD(substr($datarecord,8,4));
	$packet_cid = getUnsignedDWORD(substr($datarecord,12,4));
	$packet_sid = getUnsignedDWORD(substr($datarecord,16,4));
	$packet_size = getUnsignedDWORD(substr($datarecord,20,4));
	$packet_offset = getUnsignedDWORD(substr($datarecord,24,4));

	# Parse the data record, load parsed information into the $unit array.

	$datarecord = substr($datarecord,28);		

	# Split into sections

	writeLog($_OUTPUT_DEBUG,"parseReadyNASData","Processing Sections");

	(my $mac_address,my $hostname,my $ipaddr,my $field_data,my $system_status,my $unknown_value) = split(/\x09/,$datarecord,6);
	
	chop $system_status;

	writeLog($_OUTPUT_DEBUG,"parseReadyNASData","  mac_address: $mac_address");
	writeLog($_OUTPUT_DEBUG,"parseReadyNASData","     hostname: $hostname");
	writeLog($_OUTPUT_DEBUG,"parseReadyNASData","       ipaddr: $ipaddr");
	writeLog($_OUTPUT_DEBUG,"parseReadyNASData","   field_data: $field_data (" . length($field_data) . " bytes)");
	writeLog($_OUTPUT_DEBUG,"parseReadyNASData","system_status: $system_status (" . length($system_status) . " bytes)");
	writeLog($_OUTPUT_DEBUG,"parseReadyNASData","unknown_value: $unknown_value (" . length($unknown_value) . " bytes)");

	my $macindex = "";

	writeLog($_OUTPUT_DEBUG,"parseReadyNASData","Checking Data");

	# Check Data

	if (length($mac_address) != 17) {
		$invalid_packet = 1;
		$invalid_reason .= "MAC Address Not 17 Characters|";
	}

	if (length($hostname) > 64) {
		$invalid_packet = 1;
		$invalid_reason .= "Hostname More Than 64 Characters|";
	}

	if (length($ipaddr) < 8) {
		$invalid_packet = 1;
		$invalid_reason .= "IP Address Less Than 8 Characters|";
	}
	if (length($ipaddr) > 16) {
		$invalid_packet = 1;
		$invalid_reason .= "IP Address Greater Than 16 Characters|";
	}

	if ($invalid_packet) {
		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","Data Invalid ($invalid_reason)");
		if (getOptionDumpPackets()) {
			if (getOptionDumpBadPacketsOnly()) {
				$debug_counter++;

				$dump_filename = getDumpPath() . "parsedump_" . time . "_" . $debug_counter;
				dumpFile($dump_filename . ".bin",$datarecord,0);		# trimmed data
				dumpFile($dump_filename . ".txt",$invalid_reason,0);		# reason for dump
				dumpFile($dump_filename . ".raw",$debug_datarecord,0);		# original raw data
				dumpFile($dump_filename . ".inf","Dump File:\npacket_checksum: $packet_checksum\npacket_version: $packet_version\npacket_flags: $packet_flags\npacket_cid: $packet_cid\npacket_sid: $packet_sid\npacket_size: $packet_size\npacket_offset: $packet_offset\n",0);
			}
		}
	}else{
		$macindex = getMACIndex($mac_address);
		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","Data Valid");
		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","Using $macindex as Index");
		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Building Arrays");

		writeLog($_OUTPUT_VERBOSE,"parseReadyNASData","$macindex: Adding MAC");
		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Adding $macindex/mac/1/desc=$mac_address");

		$unit{$macindex}{mac}{1}{desc} = trimString($mac_address);
		$unit{$macindex}{mac}{0} = $unit{$macindex}{mac}{1}{desc};
		$unit{$macindex}{mac}{0}{records} = 1;

		writeLog($_OUTPUT_VERBOSE,"parseReadyNASData","$macindex: Adding HOST");
		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Adding $macindex/hostname/1/desc=$hostname");

		$unit{$macindex}{hostname}{1}{desc} = trimString($hostname);
		$unit{$macindex}{hostname}{0} = $unit{$macindex}{hostname}{1}{desc};
		$unit{$macindex}{hostname}{0}{records} = 1;

		writeLog($_OUTPUT_VERBOSE,"parseReadyNASData","$macindex: Adding IP Address");
		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Adding $macindex/ipaddr/1/desc=$ipaddr");

		$unit{$macindex}{ipaddr}{1}{desc} = trimString($ipaddr);
		$unit{$macindex}{ipaddr}{0} = $unit{$macindex}{ipaddr}{1}{desc};
		$unit{$macindex}{ipaddr}{0}{records} = 1;

		$unit{$macindex}{boot}{0} = "";
		$unit{$macindex}{boot}{0}{expand} = "";
		$unit{$macindex}{boot}{0}{fscheck} = "";

		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Gathering SNMP Data");
		
		my $uptime = getSNMPData(trimString($ipaddr),getCommunity(),getDstSNMPPort(),"1.3.6.1.2.1.1.3.0");
		my $sys_processes = getSNMPData(trimString($ipaddr),getCommunity(),getDstSNMPPort(),"1.3.6.1.2.1.25.1.6.0");
		my $sys_memory = getSNMPData(trimString($ipaddr),getCommunity(),getDstSNMPPort(),"1.3.6.1.2.1.25.2.2.0");
		my $sys_uname = getSNMPData(trimString($ipaddr),getCommunity(),getDstSNMPPort(),"1.3.6.1.2.1.1.1.0");

		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Adding $macindex/system/uptime/0=$uptime");
		$unit{$macindex}{system}{uptime}{0} = $uptime;
		$unit{$macindex}{system}{0}{records} = 1;

		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Adding $macindex/system/memory/0=$sys_memory");
		$unit{$macindex}{system}{memory}{0} = $sys_memory;
		$unit{$macindex}{system}{0}{records}++;

		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Adding $macindex/system/processes/0=$sys_processes");
		$unit{$macindex}{system}{processes}{0} = $sys_processes;
		$unit{$macindex}{system}{0}{records}++;

		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Adding $macindex/system/uname/0=$sys_uname");
		$unit{$macindex}{system}{uname}{0} = $sys_uname;
		$unit{$macindex}{system}{0}{records}++;

		if (length($field_data) > 0 ) {
			writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Parsing Field Data");
		}else{
			writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Warning! No Field Data");
		}

		$counter = 0;
		foreach (split /\n/, $field_data) {
			/\n/;
			writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Parsing: $_");
			if ($_ ne "") {
				(my $category,my $instance,my $item_string) = split(/\!\!/,$_,3);

				# Rename some categories

				if ($category eq "temp") {
					$category = "tmps";
				}
				if ($category eq "disk") {
					$category = "disks";
				}
				if ($category eq "model") {
					$category = "models";
				}
				if ($category eq "volume") {
					$category = "volumes";
				}

				if ($category eq "Boot") {
					$category = "boot";
				}

				if ($instance eq "0") {
					$instance = "1";
				}

				writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex:    Category: $category");
				writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex:    Instance: $instance");
				writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Item String: $item_string");

				if ($category ne "") {
					if ($unit{$macindex}{$category}{0}{records} eq "") {
						$unit{$macindex}{$category}{0}{records} = 0;
					}


					if ($instance eq "FS_CHECK") {
						$instance = "";
						$unit{$macindex}{$category}{0}{fscheck} = $item_string;
					}

					if ($instance eq "EXPAND") {
						$instance = "";
						$unit{$macindex}{$category}{0}{expand} = $item_string;
					}

					if ($instance ne "") {
						if ($unit{$macindex}{$category}{0}{records} < $instance) {
							if ($instance eq "0") {
								$unit{$macindex}{$category}{0}{records} = 1;
							}else{
								$unit{$macindex}{$category}{0}{records} = int $instance;
							}
						}else{
							if ($unit{$macindex}{$category}{0}{records} == 0) {
								if ($instance eq "0") {
									$unit{$macindex}{$category}{0}{records} = 1;
								}
							}
						}
					}
				}

				if ($unit{$macindex}{$category}{0}{records} ne "") {
					writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: $category has $unit{$macindex}{$category}{0}{records} instance(s)");
				}

				if ($item_string ne "") {
					foreach (split /\:\:/, $item_string) {
						/\:\:/;
						if ($_ ne "") {
							if ($instance ne "") {
								(my $item_name,my $item_text) = split(/=/,$_,2);
				
								# Rename Items

								if ($item_name eq "descr") {
									$item_name = "desc";
								}

								writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Adding $macindex/$category/$instance/$item_name=$item_text");
								$unit{$macindex}{$category}{$instance}{$item_name} = $item_text;

								# Additional Processing

								if ($category eq "disks") {
									if ($item_name eq "desc") {
										writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Expanding Disks");

										# Break out disks with additional fields
	
										(my $tempchannel,my $tempstring) = split(/:/,$item_text,2);
										(my $tempjunk,my $channel) = split(/\ /,$tempchannel,2);
										(my $drivemodel,my $drivetemp) = split(/,/,$tempstring,2);
					 					($drivetemp,my $diskerrors) = split(/;/,$drivetemp,2);
										
										if ($drivetemp eq "") {
											$drivetemp = "N/A";
										}
										if ($diskerrors eq "") {
											$diskerrors = "None";
										}
										$unit{$macindex}{disks}{$instance}{channel} = trimString($channel);
										$unit{$macindex}{disks}{$instance}{model} = trimString($drivemodel);
										$unit{$macindex}{disks}{$instance}{tmps} = trimString($drivetemp);
										$unit{$macindex}{disks}{$instance}{errors} = trimString($diskerrors);
										writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Adding $macindex/$category/$instance/channel=" . trimString($channel));
										writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Adding $macindex/$category/$instance/model=" . trimString($drivemodel));
										writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Adding $macindex/$category/$instance/tmps=" . trimString($drivetemp));
										writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Adding $macindex/$category/$instance/errors=" . trimString($diskerrors));
									}

								}
							}
						}
					}
				}
			}
		}

		# Summaries

		writeLog($_OUTPUT_VERBOSE,"parseReadyNASData","$macindex: Generating Summaries");

		if (length($field_data) > 0) {
			$unit{$macindex}{tmps}{0} = "$unit{$macindex}{tmps}{1}{desc} (" . uc $unit{$macindex}{tmps}{1}{status} . ")";
			$unit{$macindex}{ups}{0} = "$unit{$macindex}{ups}{1}{desc} (" . uc $unit{$macindex}{ups}{1}{status} . ")";
			$unit{$macindex}{volumes}{0} = "$unit{$macindex}{volumes}{1}{desc} (" . uc $unit{$macindex}{volumes}{1}{status} . ")";
			$unit{$macindex}{fan}{0} = "$unit{$macindex}{fan}{1}{desc} (" . uc $unit{$macindex}{fan}{1}{status} . ")";
			$unit{$macindex}{models}{0}{desc} = $unit{$macindex}{models}{1}{desc};
			$unit{$macindex}{models}{0} = $unit{$macindex}{models}{0}{desc};
		
			if ($unit{$macindex}{boot}{0}{fscheck}) {
				$unit{$macindex}{boot}{0} = "File System Check, " . $unit{$macindex}{boot}{0}{fscheck};
			}

			if ($unit{$macindex}{boot}{0}{expand}) {
				$unit{$macindex}{boot}{0} = "Expanding, " . $unit{$macindex}{boot}{0}{expand};
			}

			if ($unit{$macindex}{boot}{0}) {
			}else{
				$unit{$macindex}{boot}{0} = "Normal";
			}

	
			my $j = int $unit{$macindex}{disks}{0}{records};
			writeLog($_OUTPUT_VERBOSE,"parseReadyNASData","$macindex: Building Disk List ( $j Records )");

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
		}else{
			$unit{$macindex}{disks}{0}{status} = "N/A";
			$unit{$macindex}{disks}{0}{desc} = "N/A";
			$unit{$macindex}{disks}{0} = "N/A";
			$unit{$macindex}{tmps}{0} = "N/A";
			$unit{$macindex}{ups}{0} = "N/A";
			$unit{$macindex}{volumes}{0} = "N/A";
			$unit{$macindex}{fan}{0} = "N/A";
			$unit{$macindex}{models}{0}{desc} = "N/A";
			$unit{$macindex}{models}{0} = "N/A";
			$unit{$macindex}{boot}{0} = "N/A";
		}

		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex:    TMPS summary is $unit{$macindex}{tmps}{0}");
		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex:     UPS summary is $unit{$macindex}{ups}{0}");
		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: VOLUMES summary is $unit{$macindex}{volumes}{0}");
		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex:     FAN summary is $unit{$macindex}{fan}{0}");
		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex:  MODELS summary is $unit{$macindex}{models}{0}");
		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex:   DISKS summary is $unit{$macindex}{disks}{0}");
		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex:  UPTIME summary is $unit{$macindex}{system}{uptime}{0}");
		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex:  MEMORY summary is $unit{$macindex}{system}{memory}{0}");
		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: PROCESS summary is $unit{$macindex}{system}{processes}{0}");
		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex:   UNAME summary is $unit{$macindex}{system}{uname}{0}");
		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex:    BOOT summary is $unit{$macindex}{boot}{0}");
			
		if (length($system_status) > 0) {
			writeLog($_OUTPUT_VERBOSE,"parseReadyNASData","$macindex: Processing System Status");

			(my $category,my $item_string) = split(/\!\!/,$system_status,2);
			writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex:    category: $category");
			writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: item_string: $item_string");

			if ($category ne "RAIDiator") {
				(my $sys_status,my $junk) = split(/\n/,$category,2);
				writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: sys_status: $sys_status");
				writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex:       junk: $junk");

				$unit{$macindex}{os}{1}{timestamp} = 0;
				$unit{$macindex}{os}{1}{version} = 0;
				$unit{$macindex}{os}{1}{name} = "";
				$unit{$macindex}{os}{0} = $sys_status;
				$unit{$macindex}{os}{0}{records} = 1;
			}else{
				$unit{$macindex}{os}{1}{name} = $category;
				writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Adding $macindex/os/1/name=$category");
				$unit{$macindex}{os}{0}{records} = 1;
				(my $os_ver,my $os_time) = split(/,/,$item_string,2);
				foreach (split /,/, $item_string) {
					/,/;
					(my $item_name,my $item_text) = split(/=/,$_,2);
					if ($item_name eq "time") {
						$item_name = "timestamp";
					}
					$unit{$macindex}{os}{1}{$item_name} = $item_text;
					writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Adding $macindex/os/1/$item_name=$item_text");
				}
			
			}
		}else{
				writeLog($_OUTPUT_VERBOSE,"parseReadyNASData","$macindex: System Status is Not Available");

				$unit{$macindex}{os}{1}{timestamp} = 0;
				$unit{$macindex}{os}{1}{version} = 0;
				$unit{$macindex}{os}{1}{name} = "";
				$unit{$macindex}{os}{0} = "N/A";
				$unit{$macindex}{os}{0}{records} = 1;
		}
			
		writeLog($_OUTPUT_VERBOSE,"parseReadyNASData","$macindex: Generating System Summary");

		if ($unit{$macindex}{os}{1}{timestamp} > 0) {
			$unit{$macindex}{os}{1}{date} = localtime($unit{$macindex}{os}{1}{timestamp});
			$unit{$macindex}{os}{0} = "$unit{$macindex}{os}{1}{name} v$unit{$macindex}{os}{1}{version} ($unit{$macindex}{os}{1}{date})";
		}else{
			$unit{$macindex}{os}{1}{date} = "";
		}

		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex:      OS summary is $unit{$macindex}{os}{0}");




		writeLog($_OUTPUT_DEBUG,"parseReadyNASData","$macindex: Arrays Completed");

	}

	writeLog($_OUTPUT_VERBOSE,"parseReadyNASData","Exit(0)");

	return $macindex;
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




#------------------------------------------------------------
# Packet Functions
#------------------------------------------------------------

#-----------------------------
sub createPacket{
	my $cid = int shift;
	my $sid = int shift;
	my $flags = int shift;
	my $offset = int shift;

	writeLog($_OUTPUT_DEBUG,"createPacket","Start");

	writeLog($_OUTPUT_DEBUG,"createPacket","Gathering Data");

	my $packet = "";
	my $version = getInfrantVersion();
	my $datasize = getInfrantDatasize();
	my $checksum = getInfrantChecksum();

	writeLog($_OUTPUT_DEBUG,"createPacket","First Pass");

	writeLog($_OUTPUT_DEBUG,"createPacket","    Checksum: $checksum");
	writeLog($_OUTPUT_DEBUG,"createPacket","     Version: $version");
	writeLog($_OUTPUT_DEBUG,"createPacket","       Flags: $flags");
	writeLog($_OUTPUT_DEBUG,"createPacket","   Client ID: $cid");
	writeLog($_OUTPUT_DEBUG,"createPacket","   Server ID: $sid");
	writeLog($_OUTPUT_DEBUG,"createPacket","   Data Size: $datasize");
	writeLog($_OUTPUT_DEBUG,"createPacket","      Offset: $offset");

	#-----------------------------------
	# First Pass we Build the Packet 
	#-----------------------------------

	$packet = "";
	$packet .= pack("N",$checksum);		# Checksum Rolling 8-bit checksum of the header fields other than the checksum and the data.
	$packet .= pack("N",$version);		# iproxy protocol version. Used to identify incompatible versions
	$packet .= pack("N",$flags);		# Flags to specify special packets. (default is 0)
	$packet .= pack("N",$cid);		# Client Id: Unique identifier of the client.
	$packet .= pack("N",$sid);		# Server Id: Unique identifier of the server.
	$packet .= pack("N",$datasize);		# Length: Total length of the packet including the header and data.
	$packet .= pack("N",$offset);		# Offset: Offset. Incremented by the length of the data for each successive packet.

	#-----------------------------------
	# Compute Datasize and Checksum
	#-----------------------------------

	$datasize = length($packet);
	$checksum = computeChecksum(substr($packet,4),0,length(substr($packet,4)));

	writeLog($_OUTPUT_DEBUG,"createPacket","Second Pass");

	#-----------------------------------
	# Build the Final Packet
	#-----------------------------------

	$packet = "";
	$packet .= pack("N",$checksum);
	$packet .= pack("N",$version);
	$packet .= pack("N",$flags);
	$packet .= pack("N",$cid);
	$packet .= pack("N",$sid);
	$packet .= pack("N",$datasize);	
	$packet .= pack("N",$offset);

	setInfrantChecksum($checksum);
	setInfrantDatasize($datasize);

	writeLog($_OUTPUT_DEBUG,"createPacket","    Checksum: $checksum");
	writeLog($_OUTPUT_DEBUG,"createPacket","     Version: $version");
	writeLog($_OUTPUT_DEBUG,"createPacket","       Flags: $flags");
	writeLog($_OUTPUT_DEBUG,"createPacket","   Client ID: $cid");
	writeLog($_OUTPUT_DEBUG,"createPacket","   Server ID: $sid");
	writeLog($_OUTPUT_DEBUG,"createPacket","   Data Size: $datasize");
	writeLog($_OUTPUT_DEBUG,"createPacket","      Offset: $offset");

	writeLog($_OUTPUT_DEBUG,"createPacket","Exit");

	return $packet;
}

#-----------------------------
sub computeChecksum{
	my $bytearray = shift;
	my $i = int shift;
	my $j = int shift;
	my $l = 0;

	writeLog($_OUTPUT_DEBUG,"computeChecksum","Start");

	if (length($bytearray) < 1) {
		writeLog($_OUTPUT_DEBUG,"computeChecksum","No Data to Process");
		return -1;
	}

	if ($j < 1) {
		$j = length($bytearray);
	}

	writeLog($_OUTPUT_DEBUG,"computeChecksum","Calculating Checksum");

	for($k = $i; $k < $j; $k++) {
		$l += getUnsignedByte(substr($bytearray,$k,1));
	}
	
	writeLog($_OUTPUT_DEBUG,"computeChecksum","Exit");

	return $l;
}

#-----------------------------
sub getUnsignedByte{
	my $byte0 = shift;
	my $i = unpack("C",$byte0);
	return $i;
}

#-----------------------------
sub getUnsignedDWORD{
	my $dword0 = shift;
	my $i = unpack("N",$dword0);
	return $i;
}

#------------------------------------------------------------
# Sockets
#------------------------------------------------------------

#-----------------------------
sub createUDPSocket{
	writeLog($_OUTPUT_DEBUG,"createUDPSocket","Creating UDP Socket");
	my $paddr = sockaddr_in(getSrcPort(), inet_aton(getSourceAddress()));
	my $proto = getprotobyname('udp');
	my $sock = socket(SOCKET, PF_INET, SOCK_DGRAM, $proto);
	writeLog($_OUTPUT_DEBUG,"createUDPSocket","Binding UDP Socket");
	bind(SOCKET, $paddr);
	return $sock;
}

#-----------------------------
sub sendUDPPacket{
	my $sock = shift;
	my $packet = shift;
	my $address = shift;
	my $port = shift;

	writeLog($_OUTPUT_DEBUG,"sendUDPPacket","Sending " . length($packet) . " bytes using UDP to $address:$port");

	my $nas_iaddr = inet_aton($address);
	my $nas_paddr = sockaddr_in($port, $nas_iaddr);

	$bytes_sent += length($packet);

	return send(SOCKET,$packet,getSocketFlags(),$nas_paddr);
}

#-----------------------------
sub receiveUDPPackets{
	my $sock = shift;
	my $iosock = shift;
	my $datarecords = "";
	my $shandle = "";
	my $data = "";
	my $address = "";
	my $packet_size = "";
	my $packet_checksum = "";
	my $packet_version = "";
	my $packet_flags = "";
	my $packet_cid = "";
	my $packet_sid = "";
	my $packet_offset = "";
	my $discard_reason = "";
	my $computed_checksum = 0;
	my $flag_discard_packet = 0;
	my $invalid_packet = 0;
	my @ready = "";
	
	writeLog($_OUTPUT_DEBUG,"receiveUDPPackets","Start");

	writeLog($_OUTPUT_DEBUG,"receiveUDPPackets","Checking Socket for Data");

	writeLog($_OUTPUT_DEBUG,"receiveUDPPackets","Timeout is " . getSocketTimeout() . " seconds");

	my $rin = "";
	my $rout = "";
	vec($rin, fileno(SOCKET), 1) = 1;

	while (select($rout = $rin, undef, undef, getSocketTimeout())) {
		writeLog($_OUTPUT_DEBUG,"receiveUDPPackets","Data Pending, Reading Socket");
		$flag_discard_packet = 0;
		$invalid_packet = 0;
		$discard_reason = "";

		($address,$data) = readSocket();

		if (length($data) > 27) {
			$computed_checksum = computeChecksum(substr($data,4),0,length(substr($data,4)));

			$packet_checksum = getUnsignedDWORD(substr($data,0,4));
			$packet_version = getUnsignedDWORD(substr($data,4,4));
			$packet_flags = getUnsignedDWORD(substr($data,8,4));
			$packet_cid = getUnsignedDWORD(substr($data,12,4));
			$packet_sid = getUnsignedDWORD(substr($data,16,4));
			$packet_size = getUnsignedDWORD(substr($data,20,4));
			$packet_offset = getUnsignedDWORD(substr($data,24,4));
		}else{
			$flag_discard_packet = 1;
			$discard_reason = addCommaString($discard_reason,"Null Packet");
			$address = "0.0.0.0";
			$data = "";
			$computed_checksum = 0xFFFFFFFF;
			$packet_checksum = 0;
			$packet_version = 0;
			$packet_cid = 0;
			$packet_sid = 0;
			$packet_size = 0;
			$packet_offset = 0;
		}

		if ($packet_checksum == $computed_checksum) {

			# Packet itself is valid, validate each field
			# and eliminate if required.

			if ($packet_flags == 1) {
				$flag_discard_packet = 1;
				$discard_reason = addCommaString($discard_reason,"Ignoring Response Packet");
			}else{
			}

			if ($packet_cid == getInfrantCID()) {
			}else{
				$flag_discard_packet = 1;
				$discard_reason = addCommaString($discard_reason,"Client ID Mismatch");
			}

			if ($packet_sid == getInfrantSID()) {
			}else{
				$flag_discard_packet = 1;
				$discard_reason = addCommaString($discard_reason,"Server ID Mismatch");
			}

			if ($packet_size == length($data)) {
			}else{
				$flag_discard_packet = 1;
				$discard_reason = addCommaString($discard_reason,"Incorrect Size");
			}

			if ($packet_version == getInfrantVersion()) {
			}else{
				$flag_discard_packet = 1;
				$discard_reason = addCommaString($discard_reason,"Version Mismatch");
			}

			if ($packet_offset) {
				# NOT USED or at least, always zero
			}
		}else{
			# checksum is invalid, discard

			$flag_discard_packet = 1;
			$invalid_packet = 1;
			$discard_reason = addCommaString($discard_reason,"Bad Checksum");
		}
				
		if ($flag_discard_packet) {
			writeLog($_OUTPUT_DEBUG,"receiveUDPPackets","Ignoring Packet for $address.  Reason(s): $discard_reason");
		}else{
			writeLog($_OUTPUT_DEBUG,"receiveUDPPackets","Adding " . length($data) . " bytes for $address");
			$datarecords .= "|$address=$data";
		}

		if (length($data) > 0) {
			if (getOptionDumpPackets()) {
				if (getOptionDumpBadPacketsOnly()) {
					if ($invalid_packet) {
						writeLog($_OUTPUT_DEBUG,"receiveUDPPackets","Writing data to $address.bad");
						dumpFile(getDumpPath() . "$address.bad",$data,1);
					}
				}else{
					writeLog($_OUTPUT_DEBUG,"receiveUDPPackets","Writing data to $address.udp");
					dumpFile(getDumpPath() . "$address.udp",$data,1);
				}
			}
		}
		writeLog($_OUTPUT_DEBUG,"receiveUDPPackets","Waiting for Timeout or New Data (up to " . getSocketTimeout() . " second(s))");

	}

        close($sock);
	writeLog($_OUTPUT_DEBUG,"receiveUDPPackets","Socket Closed");
	writeLog($_OUTPUT_DEBUG,"receiveUDPPackets","Returning " . length($datarecords) . " bytes");
	writeLog($_OUTPUT_DEBUG,"receiveUDPPackets","Exit");

	return $datarecords;
}

#-----------------------------
sub deviceIsReadyNAS{
	return 1;
}

#-----------------------------
sub readSocket{
	my $data = "";
	my $error = 0;

	writeLog($_OUTPUT_DEBUG,"readSocket","Start");

	writeLog($_OUTPUT_DEBUG,"readSocket","Receiving Data for $sock");
	my $peer = recv(SOCKET,$data,getSocketBufferSize(),getSocketFlags());
	
	if ($peer ne "") {	
		$bytes_read += length($data);
		
		my ($port,$peeraddr) = sockaddr_in($peer);
		writeLog($_OUTPUT_DEBUG,"readSocket","Read " . length($data) . " bytes from " . inet_ntoa($peeraddr) . ":$port");
		writeLog($_OUTPUT_DEBUG,"readSocket","Exit(0)");
		return (inet_ntoa($peeraddr),$data);
	}else{
		return ("0.0.0.0","ERROR");
	}
}

#------------------------------------------------------------
# Generate IDs
#------------------------------------------------------------

#-----------------------------
sub generateSID{
	return $_PROGRAM_SID;
}

#-----------------------------
sub generateCID{
	return 0xffffffff & time;
}


#------------------------------------------------------------
# Module Variable Methods
#------------------------------------------------------------

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

#-----------------------------
sub getInfrantFlags{
	return $ioproxy_flags;
}

#-----------------------------
sub getInfrantOffset{
	return $ioproxy_offset;
}

#-----------------------------
sub getInfrantDatasize{
	return $ioproxy_datasize;
}

#-----------------------------
sub getInfrantVersion{
	return $ioproxy_version;
}

#-----------------------------
sub getInfrantChecksum{
	return $ioproxy_checksum;
}

#-----------------------------
sub getInfrantCID{
	return $ioproxy_cid;
}

#-----------------------------
sub getInfrantSID{
	return $ioproxy_sid;
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
sub getSocketBufferSize{
	return int $socket_buffer_size;
}

#-----------------------------
sub getSocketErrorTimeout{
	return $socket_error_timeout;
}

#-----------------------------
sub getSourceAddress{
	return $src_address;
}

#-----------------------------
sub getSrcPort{
	return $src_port;
}

#-----------------------------
sub getSocketTimeout{
	return $socket_timeout;
}

#-----------------------------
sub getDstPort{
	return $dst_port;
}

#-----------------------------
sub getCommunity{
	return $dst_community;
}

#-----------------------------
sub getDstSNMPPort{
	return $dst_snmp_port;
}

#-----------------------------
sub getOptionVerbose{
	return $option_verbose;
}

#-----------------------------
sub getOptionDumpPackets{
	return $option_dump_packets;
}

#-----------------------------
sub getOptionDumpBadPacketsOnly{
	return $option_bad_packets;
}

#-----------------------------
sub getBroadcastAddress{
	return $broadcast;
}

#-----------------------------
sub getDestinationAddress{
	return $dst_address;
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
sub getOptionRequireUniqueHosts{
	return $option_unique_hosts;
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

#-----------------------------
sub getUnitData{
	my $address = shift;
	my $octet = 0;
	my $found = 1;
	my $datarecord = "";

	writeLog($_OUTPUT_VERBOSE,"getUnitData","Start");

	$octet = getLastOctet($address);

	writeLog($_OUTPUT_VERBOSE,"getUnitData","Last Octet is $octet");

	$datarecord = $unit_data[$octet];

	$found = length($datarecord);

	writeLog($_OUTPUT_VERBOSE,"getUnitData","Data Record of " . length($datarecord));

	writeLog($_OUTPUT_VERBOSE,"getUnitData","Exit($found)");
	
	return $datarecord;
}

#-----------------------------
sub getUnitCount{
	return $unit_count;
}

#-----------------------------
sub getBytesSent{
	return $bytes_sent;
}

#-----------------------------
sub getBytesRead{
	return $bytes_read;
}

#-----------------------------
sub getDumpPath{
	return $dump_path;
}

#-----------------------------
sub getDebugBuffer{
	return $debug_buffer;
}

#-----------------------------
sub getSocketFlags{
	return $socket_flags;
}

#-----------------------------
sub setDestinationAddress{
	$dst_address = shift;
	return 1;
}

#-----------------------------
sub setSrcPort{
	$src_port = int shift;
	return 1;
}

#-----------------------------
sub setDstPort{
	$dst_port = int shift;
	return 1;
}

#-----------------------------
sub setDstSNMPPort{
	$dst_snmp_port = int shift;
	return 1;
}

#-----------------------------
sub setCommunity{
	$dst_community = shift;
	return 1;
}

#-----------------------------
sub setDebugBuffer{
	$debug_buffer = shift;
	return 1;
}

#-----------------------------
sub setSocketTimeout{
	$socket_timeout = int shift;
	return 1;
}

#-----------------------------
sub setSocketErrorTimeout{
	$socket_error_timeout = int shift;
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
sub setDumpPath{
	$dump_path = shift;
	return 1;
}

#-----------------------------
sub setOptionDumpPackets{
	$option_dump_packets = int shift;
	return 1;
}

#-----------------------------
sub setOptionDumpBadPacketsOnly{
	$option_bad_packets = int shift;
	return 1;
}

#-----------------------------
sub setOptionDebugFile{
	$option_debug_file = shift;
	return 1;
}

#-----------------------------
sub setOptionRequireUniqueHosts{
	$option_unique_hosts = shift;
	return 1;
}

#-----------------------------
sub setSourceAddress{
	$src_address = shift;
	return 1;
}

#-----------------------------
sub setBroadcastAddress{
	$broadcast = shift;
	return 1;
}

#-----------------------------
sub setInfrantFlags{
	$ioproxy_flags = shift;
	return 1;
}

#-----------------------------
sub setInfrantOffset{
	$ioproxy_offset = shift;
	return 1;
}

#-----------------------------
sub setInfrantDatasize{
	$ioproxy_datasize = shift;
	return 1;
}

#-----------------------------
sub setInfrantVersion{
	$ioproxy_version = shift;
	return 1;
}

#-----------------------------
sub setInfrantChecksum{
	$ioproxy_checksum = shift;
	return 1; 
}

#-----------------------------
sub setSocketBufferSize{
	$socket_buffer_size = shift;
	return 1;
}

#-----------------------------
sub setInfrantCID{
	$ioproxy_cid = shift;;
	return 1;
}

#-----------------------------
sub setInfrantSID{
	$ioproxy_sid = shift;
	return 1;
}

#-----------------------------
sub setSocketFlags{
	$socket_flags = shift;
	return 1;
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

#----------------------------------------------------------------------
sub getMACIndex {
	my $tempvar = shift;
	
	$tempvar =~ s/\://g;

	return $tempvar;
}

#-----------------------------
sub getLastError{
	return $last_error;
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

#----------------------------------------------------------------------
sub loadReadyNASLibrary{
	return 1;
}

1;




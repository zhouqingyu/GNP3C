                          Installation Notes
                            Version 1.2.10
                              05/03/2011
                 Broadcom's Linux iSCSI Offload Driver

                          Broadcom Corporation
                         5300 California Avenue,
                            Irvine, CA 92617

              Copyright (c) 2006-2011 Broadcom Corporation
                           All rights reserved


Table of Contents
=================

  Introduction
  Limitations
  Distros Supported
  Load and Run Necessary iSCSI Software Components
  BNX2I Driver Dependencies
  BNX2I Driver Parameters
  Unloading and Removing Driver
  Driver Messages
  User Application - 'brcm_iscsiuio'
  Open-iSCSI User applications
  Bind iSCSI target to Broadcom NX2 iSCSI tranport name
  Making connections to iSCSI Targets
  Maximize Offload iSCSI Connections
  Caveats
  

Introduction
============

This file describes the bnx2i Linux drivers for the Broadcom's
NetXtreme II BCM5706/BCM5708/5709/57710/57711/57711E/57712
10/100/1000/2500/10G Mbps PCI/PCI-X/PCIE CNIC Network Controller.
The bnx2i driver enables iSCSI offload on NetXtreme II family of
devices.


Distros Supported
=================
	Redhat Enterprise Linux 5.4, 5.5, 5.6
	Redhat Enterprise Linux 6.0, 6.1
	SUSE Linux Enterprise Server 11 SP1+

Limitations
===========

The current version of the driver has been tested on 2.6.x kernels starting
from 2.6.32 kernel. The driver may not compile on older kernels except the
distributions listed above.  Broadcom QA validation is limited to i386 and
x86_64 architectures, Redhat EL5, EL6, and SUSE 11 SP1 distributions.


Load and Run Necessary iSCSI Software Components
================================================
Broadcom iSCSI Offload software suite consists of 3 kernel modules and
a user daemon (uIP).  The user daemon is included in the iscsi-initiator-utils
package in the supported distributions.  Refer to uIP README on how to update
the uIP daemon if necessary.

Required software components can be loaded either manually or
through system services -

1. Unload existing driver if necessary:
Manual:
-------
   # rmmod bnx2i

Please refer to the uIP README for manual termination of the uIP daemon.


2. Load iscsi driver:
Manual:
-------
   # insmod bnx2i.ko
or
   # modprobe bnx2i

Please refer to the uIP README for manual initiation of the uIP daemon.


BNX2I Driver Dependencies
=========================

The driver uses library functions in the scsi_transport_iscsi, bnx2, bnx2x,
cnic and ipv6.ko. It is required to load these library modules either as
loadable module or as kernel built-in component before attempting to load
the driver or unresolved symbol errors will appear. Using modprobe will
resolve the dependencies automatically.


BNX2I Module Parameters
======================

optional parameters "en_tcp_dack", "error_mask1", and "error_mask2"
can be supplied as a command line arguments to the insmod or modprobe
command for bnx2i.

----------------------------
error_mask1 and error_mask2:
----------------------------
Description: "Config FW iSCSI Error Mask #", use to configure
	certain iSCSI protocol violation to treated either as warning
	or fatal error. All fatal iSCSI protocol voilations will result
	in session recovery (ERL 0). These are bit masks

Defaults: All violation will be treated as errors. 

CAUTION: Do not meddle with 'error_mask' if you are not sure about the
	consequences. These values are to be discussed with Broadcom
	development team on case by case basic. This is just a mechanism
	to work around iSCSI implementation issues on the target side and
	without proper knowledge of iSCSI protocol details, user are advised
	not to experiment with these parameters


------------
en_tcp_dack:
------------
Description: "Enable TCP Delayed ACK", enables/disables TCP delayed ACK
	feature on offloaded iSCSI connections

Defaults: TCP delayed ACK is ENABLED

e.g.
	# insmod bnx2i.ko en_tcp_dack=0
		or
	# modprobe bnx2i en_tcp_dack=0


-------------
time_stamps :
-------------
Description: "Enable TCP TimeStamps", enables/disables TCP time stamp feature
	on offloaded iSCSI connections

Defaults: TCP time stamp option is DISABLED

e.g.
	# insmod bnx2i.ko time_stamps=1
		or
	# modprobe bnx2i time_stamps=1


-----------
ooo_enable:
-----------
Description: "Enable TCP Out-of-order Rx Feature", enables/disables TCP OOO
	handling feature on offloaded iSCSI connections

Defaults: TCP OOO rx feature is ENABLED

e.g.
	# insmod bnx2i.ko ooo_enable=1
		or
	# modprobe bnx2i ooo_enable=1


--------
sq_size:
--------
Description: "Configure SQ size", used to choose send queue size for offloaded
	connections and SQ size determines maximum SCSI commands that can be
	queued. SQ size also has a bearing on the number of connections that can
	be offloaded, as QP size increases, number of connections supported will
	decrease. With default values, 5706/5708 can offload 28 connections.

Defaults: 128
Range: 32 to 128
Note: Broadcom validation is limited to power of 2, e.g. 32, 64, 128


--------
rq_size:
--------
Description: "Configure RQ size", used to choose size of asynchronous buffer
	queue size per offloaded connections and RQ size is not required be
	greater than 16 as it is used to place iSCSI ASYNC/NOP/REJECT messages
	and SCSI sense data.

Defaults: 16
Range: 16 to 32
Note: Broadcom validation is limited to power of 2, e.g. 16, 32


----------------
event_coal_min :
----------------
Description: "Event Coalescing Minimum Commands", performance tuning parameter
	used to control the minimum rate of interrupt generation by the iscsi
	firmware

Defaults: 24
Valid Values: 16-32
Note: This parameter is meant for developers to tune the event coalescing for
	performance adjustment and not intended for end users.


----------------
event_coal_div :
----------------
Description: "Event Coalescing Divide Factor", performance tuning parameter
	used to moderate the rate of interrupt generation by the iscsi firmware

Defaults: 1
Valid Values: 1,2,4,8
Note: Broadcom did find a single digit improvement in IOPS numbers on 1G chips
	But Broadcom has decided to disable interrupt coalescing for
	5706/5708/5709 as our IOPS numbers are more than double the competition.
	However we believe this parameter makes more sense to 5771x (10G)


----------------------
last_active_tcp_port :
----------------------
Description: "Last active TCP port", TCP port monitor parameter
	used to indicate the last used TCP port by the iscsi firmware

Defaults: N/A
Valid Values: N/A


The parameters can also be set in modprobe.conf. See the man page
for more information.


Unloading and Removing Driver
=============================

To unload the driver, disconnect all active iSCSI sessions to targets and run
the following command -

rmmod bnx2i

NOTE: refer to open-iscsi CLI tool, 'iscsiadm' for session teardown instructions

If the driver was installed using rpm, do the following to remove it:

rpm -e nextreme2 ***

Note *** - this will remove bnx2, bnx2x and cnic modules as well

If the driver was installed using make install from the tar file, the driver
bnx2i.ko has to be manually deleted from the system. Refer to the section
"Installing Source RPM Package" for the location of the installed driver.


Driver Messages
===============

The following are the most common sample messages that may be logged in the file
/var/log/messages. Use dmesg -n <level> to control the level at which messages
will appear on the console. Most systems are set to level 6 by default. To see
all messages, set the level higher.

BNX2I Driver signon:
-------------------

Broadcom NetXtreme II iSCSI Driver bnx2i v2.1.2d (May 12, 2010)


Driver completes handshake with iSCSI Offload Enabled CNIC device:
------------------------------------------------------------------

bnx2i [05:00.00]: ISCSI_INIT passed

NOTE: this message is displayed only when user attempts to make an
iSCSI connection


Driver detects iSCSI Offload is not enabled on the CNIC device:
---------------------------------------------------------------

bnx2i: iSCSI not supported, dev=eth3
bnx2i: LOM is not enabled to offload iSCSI connections, dev=eth0
bnx2i: dev eth0 does not support iscsi


Exceeds maximum allowed iSCSI connection offload limit:
-------------------------------------------------------

bnx2i: alloc_ep: unable to allocate iscsi cid
bnx2i: unable to allocate iSCSI context resources


Network route to target node and transport name binding are 2 different devices:
--------------------------------------------------------------------------------

bnx2i: conn bind, ep=0x... ($ROUTE_HBA) does not belong to hba $USER_CHOSEN_HBA
	where 	ROUTE_HBA --> net device on which connection was offloaded
				based on route information
		USER_CHOSEN_HBA --> HBA to which target node is bound (using
				iscsi transport name)


Target cannot be reached on any of CNIC devices:
------------------------------------------------

bnx2i: check route, can't connect using cnic


Network route is assigned to network interfce which is down:
------------------------------------------------------------

bnx2i: check route, hba not found


SCSI-ML initiated host reset (session recovery):
------------------------------------------------

bnx2i: attempting to reset host, #3


CNIC detects iSCSI protocol violation - FATAL errors:
-----------------------------------------------------

bnx2i: iscsi_error - wrong StatSN rcvd
bnx2i: iscsi_error - hdr digest err
bnx2i: iscsi_error - data digest err
bnx2i: iscsi_error - wrong opcode rcvd
bnx2i: iscsi_error - AHS len > 0 rcvd
bnx2i: iscsi_error - invalid ITT rcvd
bnx2i: iscsi_error - wrong StatSN rcvd
bnx2i: iscsi_error - wrong DataSN rcvd
bnx2i: iscsi_error - pend R2T violation
bnx2i: iscsi_error - ERL0, UO
bnx2i: iscsi_error - ERL0, U1
bnx2i: iscsi_error - ERL0, U2
bnx2i: iscsi_error - ERL0, U3
bnx2i: iscsi_error - ERL0, U4
bnx2i: iscsi_error - ERL0, U5
bnx2i: iscsi_error - ERL0, U
bnx2i: iscsi_error - invalid resi len
bnx2i: iscsi_error - MRDSL violation
bnx2i: iscsi_error - F-bit not set
bnx2i: iscsi_error - invalid TTT
bnx2i: iscsi_error - invalid DataSN
bnx2i: iscsi_error - burst len violation
bnx2i: iscsi_error - buf offset violation
bnx2i: iscsi_error - invalid LUN field
bnx2i: iscsi_error - invalid R2TSN field
bnx2i: iscsi_error - invalid cmd len1
bnx2i: iscsi_error - invalid cmd len2
bnx2i: iscsi_error - pend r2t exceeds MaxOutstandingR2T value
bnx2i: iscsi_error - TTT is rsvd
bnx2i: iscsi_error - MBL violation
bnx2i: iscsi_error - data seg len != 0
bnx2i: iscsi_error - reject pdu len error
bnx2i: iscsi_error - async pdu len error
bnx2i: iscsi_error - nopin pdu len error
bnx2i: iscsi_error - pend r2t in cleanup
bnx2i: iscsi_error - IP fragments rcvd
bnx2i: iscsi_error - IP options error
bnx2i: iscsi_error - urgent flag error


CNIC detects iSCSI protocol violation - non-FATAL, warning:
-----------------------------------------------------------

bnx2i: iscsi_warning - invalid TTT
bnx2i: iscsi_warning - invalid DataSN
bnx2i: iscsi_warning - invalid LUN field

NOTE: driver by default is configured to consider certain violation to be
treated as warning and not as errors


Driver puts a session through recovery:
---------------------------------------

conn_err - hostno 3 conn 03fbcd00, iscsi_cid 2 cid a1800


REJECT iSCSI PDU recieved from the target:
------------------------------------------

bnx2i - printing rejected PDU contents
[0]: 1 ffffffa1 0 0 0 0 20 0
[8]: 0 7 0 0 0 0 0 0
[10]: 0 0 40 24 0 0 ffffff80 0
[18]: 0 0 3 ffffff88 0 0 3 4b
[20]: 2a 0 0 2 ffffffc8 14 0 0
[28]: 40 0 0 0 0 0 0 0


Open-iSCSI daemon handing over session to driver:
-------------------------------------------------
bnx2i: conn update - MBL 0x800 FBL 0x800MRDSL_I 0x800 MRDSL_T 0x2000 


User Application - 'brcm_iscsiuio':
=================================

'brcm_iscsiuio' application needs to be installed because iSCSI offload
connections can be made.  Please refer to the 'brcm_iscsiuio' README for 
details.  Run 'brcm_iscsiuio' daemon before attempting to create iSCSI 
connections
Driver won't be able to establish connections to iSCSI target without daemon's
assistance

	# brcm_iscsiuio


Open-iSCSI User applications:
=============================

Install and run open-iscsi programs, 'iscsid' & 'iscsiadm' from the
open-iscsi package, refer to "Packaging" section for more
details. 

1. Start the daemon
   # iscsid


Making connections to iSCSI Targets:
====================================

Please refer to open-iscsi documentation for comprehensive list of 'iscsiadm'
commands. Here is a sample list of commands to discover targets and
create iscsi connections to target.


Add static entry:
-----------------

	# iscsiadm -m node -p <ipaddr[:port],TPGT> -T <iqn.targetname> -o new 


iSCSI target discovery using 'SendTargets':
-------------------------------------------

	# iscsiadm -m discovery --type sendtargets -p <ipaddr[:port]> 


Bind iSCSI target to Broadcom NX2 transport (bnx2i) :
-------------------------------------------------------------------------------------------------

	# iscsiadm -m node -p <ipaddr[:port]> -T <iqn.targetname> --op=update 
		--name=iface_file_name


Login to target using 'iscsiadm' command:
-----------------------------------------

	# iscsiadm -mode node -p <ipaddr[:port]> -T <iqn.targetname> --login


List all drives active in the system:
-------------------------------------
	# fdisk -l


Bind iSCSI target to Broadcom NX2 iSCSI tranport name:
======================================================

By default open-iscsi daemon connects to discovered targets using software
initiatior (transport name = 'tcp'). Users who wish to offload iSCSI connection
onto CNIC device should explicitly change transport binding of the iSCSI node.
This can be easily done using 'iscsiadm' cli utlity as follows,

	# iscsiadm --mode node --targetname iqn.2004-06.com.broadcom:tg1 \
		--portal 192.168.1.100 --op=update			 \
		--name=iface_file_name

where the iface file includes the following information: 

	iface.net_ifacename = ethX
	iface.iscsi_ifacename = <name of this iface file> 
	iface.hwaddress = XX:XX:XX:XX:XX:XX <make sure this is lower case>
	iface.ipaddress = XX.XX.XX.XX
	iface.transport_name = bnx2i

Note that the iface.hwaddress must be in the lower case format.

If user wishes to switch back to use software initiator for whatever reason,
following command will do the trick,
	# iscsiadm --mode node --targetname iqn.2004-06.com.broadcom:tg1 \
		--portal 192.168.1.100 --op=update			 \
		--name=iface_file_name

where the iface file specifies TCP transport

	iface.net_ifacename = ethX
	iface.iscsi_ifacename = <name of this iface file> 
	iface.transport_name = tcp

Please refer to the open-iscsi README for further details.


Maximize iSCSI Offload Connections:
===================================
With default driver parameter set which includes 128 outsanding commands, bnx2i
can offload a following number of connections,
	5706/5708	- 28
	5709		- 43
	5771x		- 128
This is no hard limit, just a simple on chip resource allocation math.
bnx2i will be able to offload > 28 connections on 1G devices by reducing
the shared queue size which in turn limits the maximum outstanding tasks
on a connection. Refer to section "BNX2I Module Parameters" for further
details on sq_size and rq_size. Driver logs the following message to syslog
when maximum allowed connection offload limit is reached -
 "bnx2i: unable to allocate iSCSI context resources"


Caveats:
========

1. iSCSI support on CNIC devices:
---------------------------------

Not all Broadcom NetExteme II device support iSCSI offload, please contact
your server manufacturer on instructions to enable iSCSI offload


2) iSCSI Session won't recover after hot remove and hotplug:
------------------------------------------------------------

   Cause is successive device registration with iSCSI transport layer would
result in different 64-bithandles. Also when the device is removed, route
could resolve to a different CNIC port in which case iSCSI session/connection
are bound to HBA 1 (which just got hot removed) and TCP connection is
established on HBA 2 and this is not an acceptable configuration. Broadcom
advises administrator to logoff all iSCSI session before removing the HBA from
the server


3. iSCSI Session recovery due to network device operation:
----------------------------------------------------------

Following popular network device operations will result in iSCSI connection
teardown, in most cases connection will recover but sometime it may not
depending on the network configuration,
  a) Ethernet interface reset
	# service network restart
	# ifdown eth#; ifup eth#

  b) Change IP address
	# ifconfig eth0 192.168.1.20

  c) MTU change
	# ifconfig eth0 mtu 1000 up

  d) ethtool selftest
	# ethtool -t eth0


4. MPIO using open-iscsi needs pro-active iSCSI nopout's enabled:
-----------------------------------------------------------------
For MPIO to work properly iSCSI nopout should be enabled on each iSCSI session.
Please refer to open-iscsi documentation on how to set 'noop_out_interval' and
'noop_out_timeout' values. Default values could be differ between releases and
is advisible to set them to 10 sec and 15 secs respectively


5. iSCSI boot using iSCSI Offload with VLAN issue:
--------------------------------------------------
For VLAN configuration, user has to the hardware net device identifier instead
of the VLAN net device identifier.  For example:
For VLAN ethX.y net device, use ethX in the net device identification.

Please refer to the uIP README for more details on VLAN operation.


6. iSCSI Sessions can no longer be established after some strenuous reset test:
-------------------------------------------------------------------------------
Please always use the latest open-iscsi util for the supported OS.

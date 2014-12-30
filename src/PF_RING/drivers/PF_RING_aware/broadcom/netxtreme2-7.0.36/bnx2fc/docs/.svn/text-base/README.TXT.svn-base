                          Installation Notes
                            Version 1.0.1
                              04/12/2011
		  Broadcom's Linux FCoE Offload Driver

                          Broadcom Corporation
                         5300 California Avenue,
                            Irvine, CA 92617

             Copyright (c) 2010-2011 Broadcom Corporation
                           All rights reserved


Table of Contents
=================

  Introduction
  Limitations
  Distros Supported
  Packaging and Installation
  BNX2FC Driver Dependencies
  BNX2FC Driver Parameters
  Driver Messages
  

Introduction
============

This file describes the bnx2fc Linux drivers for the Broadcom's NetXtreme II
BCM57712/BCM57810 10G Mbps PCIe CNIC Network Controller chipset.  The bnx2fc
driver enables users to offload FCoE data path onto licensed 57712 devices.

Distros Supported
=================
	RedHat Enterprise Linux 6.1 (i386 and x86_64)
	SLES 11 SP1 U1 (Errata kernel)

Limitations
===========

The current version of the driver has been tested on 2.6.x kernels starting
from 2.6.32 kernel which is included in RH 6.1 distribution. This driver may
not compile on older kernels. Broadcom QA validation is limited to i386 and
x86_64 architectures, RHEL6.1 distribution.

Packaging & Installation
========================

Refer INSTALL.TXT for netxtreme2 package & installation instructions.

BNX2FC Driver Dependencies
==========================

The driver uses library functions in the scsi_transport_fc, bnx2, bnx2x, cnic.
It is required to load these library modules either as loadable module or as
kernel built-in component before attempting to load the driver or unresolved
symbol errors will appear. Using modprobe will resolve the dependencies
automatically.


BNX2FC Module Parameters
========================

optional parameters "debug_logging" can be supplied as a command line arguments
to the insmod or modprobe command for bnx2fc.

-------------------
bnx2fc_debug_level
-------------------
Description: "Bit mask to enable debug logging", enables/disables driver debug
	logging

Defaults: NONE

e.g.
	# modprobe bnx2fc debug_logging=0xff

IO level debugging	= 0x1
Session level debugging = 0x2
HBA level debugging	= 0x4
ELS debugging		= 0x8
Misc debugging		= 0x10
Max debugging		= 0xff



FCoE Operation
==============
Broadcom FCoE offload through bnx2fc is full stateful hardware offload that
cooperates with all interfaces provided by the Linux ecosystem for FC/FCoE and
SCSI controllers.  As such, FCoE functionality, once enabled is largely
transparent. Devices discovered on the SAN will be registered and unregistered
automatically with the upper storage layers.

Despite the fact that the Broadcom's FCoE offload is fully offloaded, it does
depend on the state of the network interfaces to operate. As such, the network
interface (e.g. eth0) associated with the FCoE offload initiator must be 'up'.
It is recommended that the network interfaces be configured to be brought up
automatically at boot time. This can be accomplished by configuring the
interface through YaST/YaST2 on SuSE Linux or through network device control on
Red Hat.

Furthermore, the Broadcom FCoE offload solution creates VLAN interfaces to
support the VLANs that have been discovered for FCoE operation (e.g.
eth0.1001-fcoe).  Do not delete or disable these interfaces or FCoE operation
will be interupted.

MTU configuration of the native Ethernet interface is independent of the FCoE
protocols effective MTU. The networking MTU may be configured for any value,
and the FCoE offload will continue to use an appropriately size mini-jumbo MTU
for FCoE operation.

The interfaces on which bnx2fc driver has to operate need to be configured.
Here are the steps to configure:
1. cd /etc/fcoe
2. copy cfg-ethx to cfg-eth5 if FCoE has to be enabled on eth5. Repeat this for
all the interfaces where FCoE has to be enabled.
3. Edit all the cfg-eth files to set "no" for DCB_REQUIRED field

Refer to fcoeadm manpage for more information and fcoeadm operations to
create/destroy interfaces or to display lun/target information.

With Broadcom's FCoE solution, LLDP packets are sent by the MCP firmware.
However, the lldp frames are also sent by lldpad daemon. To disable the
duplicate lldp packets, run the following command:

lldptool set-lldp -i <interface_name> adminStatus=disabled

Driver Messages
===============

The following are the most common sample messages that may be logged in the
file /var/log/messages. Use dmesg -n <level> to control the level at which the
messages should appear on the console. Mmost systems are set to level 6 by
default. To see all messages, set the level higher.

BNX2FC Driver Signon:
---------------------
Broadcom NetXtreme II FCoE Driver bnx2fc v0.8.7 (Mar 25, 2011)

Driver comples handshake with FCoE Offload Enabled CNIC device:
--------------------------------------------------------------
bnx2fc [04:00.00]: FCOE_INIT passed

Driver fails handshake with FCoE Offload Enabled CNIC device:
------------------------------------------------------------
bnx2fc: init_failure due to invalid opcode
bnx2fc: init_failure due to context allocation failure
bnx2fc: init_failure due to NIC error
bnx2fc: init_failure due to completion status error
bnx2fc: init_failure due to HSI mismatch

No valid license to start FCoE:
-------------------------------
bnx2fc: FCoE function not enabled <ethX>
bnx2fC: FCoE not supported on <ethX>

Session failures due to exceeding maximum allowed FCoE offload connection limit
or memory limits:
-------------------------------------------------------------------------------
bnx2fc: Failed to allocate conn id for port_id <remote port id>
bnx2fc: exceeded max sessions..logoff this tgt
bnx2fc: Failed to allocate resources

Session offload failures:
------------------------
bnx2fc: bnx2fc_offload_session - Offload error
<rport> not FCP type. not offloading
<rport> not FCP_TARGET. not offloading

Session upload failures:
-----------------------
bnx2fc: ERROR!! destroy timed out
bnx2fc: Disable request timed out.  destroy not set to FW
bnx2fc: Disable failed with completion status <status>
bnx2fc: Destroy failed with completion status <status>

Unable to issue ABTS:
--------------------
bnx2fc: initiate_abts: tgt not offloaded
bnx2fc: initiate_abts: rport not ready
bnx2fc: initiate_abts: link is not ready
bnx2fc: abort failed, xid = <xid>

Unable to recover the IO using ABTS(due to ABTS timeout):
--------------------------------------------------------
bnx2fc: Relogin to the target

Unable to issue IO request due to session not ready:
---------------------------------------------------
bnx2fc: Unable to post io_req

Drop incorrect L2 receive frames:
--------------------------------
bnx2fc: FPMA mismatch... drop packet
bnx2fc: dropping frame with CRC error

HBA/lport allocation failures:
------------------------------
bnx2fc: Unable to allocate hba
bnx2fc: Unable to allocate scsi host

NPIV port creation:
-------------------
bnx2fc: Setting vport names, <WWNN>, <WWPN>

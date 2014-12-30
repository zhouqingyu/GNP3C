                              README Notes
                       Broadcom bnx2x Linux Driver

                          Broadcom Corporation
                         5300 California Avenue,
                            Irvine, CA 92617

                 Copyright (c) 2007-2011 Broadcom Corporation
                           All rights reserved


Table of Contents
=================

  Introduction
  Limitations
  Driver Dependencies
  Driver Settings
  Driver Parameters
  Driver Defaults
  Unloading and Removing Driver
  Driver Messages
  Dual Media Support

Introduction
============

This file describes the bnx2x Linux driver for the Broadcom NetXtreme II
BCM57710/BCM57711/BCM57711E/BCM57712/BCM57712_MF/BCM57800/BCM57800_MF/BCM57810/
BCM57810_MF/BCM57840/BCM57840_MF 10Gb PCIE Ethernet Network Controllers and 
Broadcom NetXtreme II BCM57840 10Gb/20Gb PCIE Ethernet Network Controllers.


Limitations
===========

The current version of the driver has been tested on 2.6.x kernels starting
from 2.6.9. The driver may not compile on kernels older than 2.6.9. Testing
is concentrated on i386 and x86_64 architectures. Only limited testing has
been done on some other architectures.

Minor changes to some source files and Makefile may be needed on some
kernels.

IP Forwarding (bridging) cannot be used with TPA on kernels older than
2.6.26. Please disable TPA with either ethtool (if available) or driver
parameter (see "Driver Parameters" section below)

The driver makes use of virtual memory for DMA operations. Normally, the
driver requires virtual memory of size 8264 kB per physical function at the
probe stage. At the open stage, on kernels older than 2.6.16, the driver
requires 384 kB of virtual memory per physical function, and on kernels
from 2.6.16 and above, the driver requires more 256 kB of virtual memory
per physical function. On architectures that the default vmalloc size is
relatively small and not sufficient to load many interfaces, use
vmalloc=<size> during boot to increase the size.


Driver Dependencies
===================

The driver uses library functions in the crc32 and zlib_inflate libraries.
On most kernels, these libraries are already built into the kernel. In
some cases, it may be necessary to load these library modules before the
driver or unresolved symbol errors will appear. Using modprobe will
resolve the dependencies automatically.

In rare cases where the crc32 and zlib_inflate libraries are not enabled
in the kernel, it will be necessary to compile the kernel again with the
libraries enabled.

The driver uses also library functions in the crc32c library. On new kernels,
this library is already built into the kernel. In some old kernels,
it may be necessary to load this library module before the driver or
unresolved symbol errors will appear. Using modprobe will resolve the
dependencies automatically.

On systems where GRO feature is available, driver uses functions from 8021q
library. In some kernels this library is already built into the kernel, in
others it may be necessary to load this library module before the driver or
unresolved symbol errors will appear. Using modprobe will resolve the
dependencies automatically.

Driver Settings
===============

The bnx2x driver settings can be queried and changed using ethtool. The
latest ethtool can be downloaded from http://sourceforge.net/projects/gkernel
if it is not already installed. The following are some common examples on how
to use ethtool. See the ethtool man page for more information. ethtool settings
do not persist across reboot or module reload. The ethtool commands can be put
in a startup script such as /etc/rc.local to preserve the settings across a
reboot. On Red Hat distributions, "ethtool -s" parameters can be specified
in the ifcfg-ethx scripts using the ETHTOOL_OPTS keyword. The specified
ethtool parameters will be set during ifup. Example:
/etc/sysconfig/network-scripts/ifcfg-eth0:

ETHTOOL_OPTS="wol g speed 100 duplex half autoneg off"

Some ethtool examples:

1. Show current speed, duplex, and link status:

   ethtool eth0

2. Change speed, duplex, autoneg:

Example: 100Mbps half duplex, no autonegotiation:

   ethtool -s eth0 speed 100 duplex half autoneg off

Example: Autonegotiation with full advertisement:

   ethtool -s eth0 autoneg on

Example: Autonegotiation with 100Mbps full duplex advertisement only:

   ethtool -s eth0 speed 100 duplex full autoneg on

3. Show flow control settings:

   ethtool -a eth0

4. Change flow control settings:

Example: Turn off flow control

   ethtool -A eth0 autoneg off rx off tx off

Example: Turn flow control autonegotiation on with tx and rx advertisement:

   ethtool -A eth0 autoneg on rx on tx on

   Note that this is only valid if speed is set to autonegotiation.

5. Show offload settings:

   ethtool -k eth0

6. Change offload settings:

Example: Turn off TSO (TCP segmentation offload)

   ethtool -K eth0 tso off

7. Get statistics:

   ethtool -S eth0

8. Perform self-test:

   ethtool -t eth0

   Note that the interface (eth0) must be up to do all tests.

9. See ethtool man page for more options.


Driver Parameters
=================

Several optional parameters can be supplied as a command line argument
to the insmod or modprobe command. These parameters can also be set in
modprobe.conf. See the man page for more information.

The optional parameter "int_mode" is used to force using an interrupt mode
other than MSI-X. By default, the driver will try to enable MSI-X if it is
supported by the kernel. In case MSI-X is not attainable, the driver will try
to enable MSI if it is supported by the kernel. In case MSI is not attainable,
the driver will use legacy INTx mode. In some old kernels, it's impossible to
use MSI if device has used MSI-X before and impossible to use MSI-X if device
has used MSI before, in these cases system reboot in between is required.

Set the "int_mode" parameter to 1 as shown below to force using the legacy
INTx mode on all NetXtreme II NICs in the system.

   insmod bnx2x.ko int_mode=1

or

   modprobe bnx2x int_mode=1

Set the "int_mode" parameter to 2 as shown below to force using MSI mode
on all NetXtreme II NICs in the system.

   insmod bnx2x.ko int_mode=2

or

   modprobe bnx2x int_mode=2


The optional parameter "disable_tpa" can be used to disable the
Transparent Packet Aggregation (TPA) feature. By default, the driver will
aggregate TCP packets, but if a user would like to disable this advanced
feature - it can be done.

Set the "disable_tpa" parameter to 1 as shown below to disable the TPA
feature on all NetXtreme II NICs in the system.

   insmod bnx2x.ko disable_tpa=1

or

   modprobe bnx2x disable_tpa=1

Use ethtool (if available) to disable TPA (LRO) for a specific NetXtreme II NIC.

The optional parameter pri_map is used to map the skb-priority to a Class Of 
Service (CoS) in the HW. This 32 bit parameter is evaluated by the  driver as 8 
values of 4 bits each. Each nibble sets the desired HW queue number for that 
priority.

This parameter is only available in kernels which support mapping skb 
priorities to traffic classes and traffic classes to transmission queues. This 
means kernel 2.6.39 or newer.
Also:
on the 5771x family this feature is unavailable (a single COS services all).
on the 57712 family two classes of service are available.
on the 578xx family three classes of service are availabe.
configuring  priorities to unavailable COSs will log an error and default to 
COS 0.

For example, set the pri_map parameter to 0x22221100 to map priority 0 and 1 to 
CoS 0, map priority 2 and 3 to CoS 1, and map priority 4 to 7 to CoS 2. Another 
example, set the pri_map parameter to 0x11110000 to map priority 0 to 3 to CoS 
0, and map priority 4 to 7 to CoS 1.

The optional parameter "dropless_fc" can be used to enable a complementary
flow control mechanism on 57711 or 57711E. The default flow control mechanism
is to send pause frames when the on chip buffer (BRB) is reaching a certain
level of occupancy. This is a performance targeted flow control mechanism.
On 57711 or 57711E, one can enable another flow control mechanism to send pause
frames in case where one of the host buffers (when in RSS mode) are exhausted.
This is a "zero packet drop" targeted flow control mechanism.

Set the "dropless_fc" parameter to 1 as shown below to enable the dropless
flow control mechanism feature on all 57711 or 57711E NetXtreme II NICs in the
system.

   insmod bnx2x.ko dropless_fc=1

or

   modprobe bnx2x dropless_fc=1

The optional parameter "autogreeen" can be used to force specific AutoGrEEEN
behavior. By default, the driver will use the nvram settings per port, but if
the module parameter is set, it can override the nvram settings to force
AutoGrEEEN to either active (1) or inactive (2). The default value of 0 to use
the nvram settings.

There are some more optional parameters that can be supplied as a command line
argument to the insmod or modprobe command. These optional parameters are
mainly to be used for debug and may be used only by an expert user.

The debug optional parameter "poll" can be used for timer based polling.
Set the "poll" parameter to the timer polling interval on all NetXtreme
II NICs in the system.

The debug optional parameter "mrrs" can be used to override the MRRS
(Maximum Read Request Size) value of the HW. Set the "mrrs" parameter to
the desired value (0..3) for on all NetXtreme II NICs in the system.

The debug optional parameter "debug" can be used to set the default
msglevel on all NetXtreme II NICs in the system. Use "ethtool -s" to set
the msglevel for a specific NetXtreme II NIC.


Driver Defaults
===============

Speed :                    Autonegotiation with all speeds advertised

Flow control :             Autonegotiation with rx and tx advertised

MTU :                      1500 (range 46 - 9000)

Rx Ring size :             4078 (range 0 - 4078)

Tx Ring size :             4078 (range (MAX_SKB_FRAGS+4) - 4078)

                            MAX_SKB_FRAGS varies on different kernels and
                            different architectures. On a 2.6 kernel for
                            x86, MAX_SKB_FRAGS is 18.

Coalesce rx usecs :          25 (range 0 - 3000)

Coalesce tx usecs :          50 (range 0 - 12288)

MSI-X :                    Enabled (if supported by 2.6 kernel)

TSO :                      Enabled

WoL :                      Disabled


Unloading and Removing Driver
=============================

To unload the driver, do the following:

   rmmod bnx2x

If the driver was installed using rpm, do the following to remove it:

   rpm -e bnx2x


If the driver was installed using make install from the tar file, the driver
bnx2x.ko has to be manually deleted from the system. Refer to the section
"Installing Source RPM Package" for the location of the installed driver.


Driver Messages
===============

The following are the most common sample messages that may be logged in the file
/var/log/messages. Use dmesg -n <level> to control the level at which messages
will appear on the console. Most systems are set to level 6 by default. To see
all messages, set the level higher.

Driver signon:
-------------

Broadcom NetXtreme II 5771x 10Gigabit Ethernet Driver bnx2x 0.40.15 ($DateTime: 2007/11/22 05:32:40 $)


NIC detected:
------------

eth0: Broadcom NetXtreme II BCM57710 XGb (A1) PCI-E x8 2.5GHz found at mem e8800000, IRQ 16, node addr 001018360012


MSI-X enabled successfully:
--------------------------

bnx2x: eth0: using MSI-X


Link up and speed indication:
----------------------------

bnx2x: eth0 NIC Link is Up, 10000 Mbps full duplex, receive & transmit flow control ON


Link down indication:
--------------------

bnx2x: eth0 NIC Link is Down


Dual Media Support
==================
A dual media capable system connects two PHYs to a single MAC. These PHYs
generally use different media types (for example SFP+ fiber and 10GBase-T
twisted pair copper) and the dual media configuration requires that the user
select a preference among the two PHYs. Supported preferences include manual
selection and PHY priority selection. With manual selection, the user specifies
that only one PHY should be configured and use to connect to the network. (For
example, use the fiber PHY only, always ignore the copper PHY.) With PHY
priority selection, the user specifies that either PHY may be used to connect
to the network, but when both PHYs indicate link, the PHY with the higher
priority will be used to connect to the network. (For example, with fiber PHY
priority, if either the copper PHY or the fiber PHY has link, that PHY will be
used to connect to the network. However, if both the fiber and copper PHYs have
link, the fiber PHY will be used to connect to the network and the copper PHY
will be ignored.) When PHY priority selection is used, the PHY which has been
selected for network connectivity is referred to as the active PHY. When PHY
manual selection is used, there are no special considerations when running
ethtool since only one media type is used by the MAC and ethtool is able to
control that media type as expected. However, since ethtool is currently not
designed to manage the multiple physical interfaces enabled by Dual Media
support,  the following limitations will apply when ethtool is used on a system
with PHY priority selection enabled:

1. Ethtool can be used to display the current physical media information
   for the active PHY.
2. Ethtool cannot be used to determine whether PHY manual selection or PHY
   priority selection is in use. This configuration information is available
   through system specific utilities provided by the vendor.
3. Ethtool can be used to control the current  physical media configuration,
   but this will force the configuration back to PHY manual selection.
4. When ethtool is used to configure the active PHY, ethtool must be called
   twice, first to change AWAY from the active PHY, then to change BACK to the
   active PHY. (For example, if the active PHY is copper, ethtool must be first
   called to change the active PHY to fiber, forcing PHY manual selection
   to be enabled, then ethtool must be called again to change the active PHY
   to copper.)
5. Using ethtool to change from PHY priority selection to PHY manual selection
   only applies to the current session. When the driver is unloaded/reloaded or
   the system is rebooted, PHY selection will return to the default value.
   PHY selection defaults must be set outside of Linux with system specific
   utilities provided by the vendor.


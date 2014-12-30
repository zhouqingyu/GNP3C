                              README Notes
                       Broadcom bnx2x Linux Driver

                          Broadcom Corporation
                         5300 California Avenue,
                            Irvine, CA 92617

                 Copyright (c) 2007-2013 Broadcom Corporation
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
BCM57810_MF/BCM57811/BCM57811_MF/BCM57840/BCM57840_MF 10Gb PCIE Ethernet Network
Controllers and Broadcom NetXtreme II BCM57840 10Gb/20Gb PCIE Ethernet Network
Controllers.


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

32-bit Linux operating systems have a limited amount of memory space available
for Kernel data structures. Therefore, when using the bnx2x driver on such a
platforms, it may be required to decrease amount of memory pre-allocated by the
driver. Decreasing the memory is possible by using the "num_queues" driver
parameter, to limit the number of RX queues, and by using the ethtool -G option,
to limit the number of RX buffers for each queue.

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

 9. Set the number of RSS rings:

    ethtool -L eth0 combined 6

    Note that only 'combined' can be set, as we don't have independant rx or
    tx rings.

10. Set the 57712/578xx Maximum Bandwidth value of a partition without a
    system reboot:

    ethtool -s eth0 speed 5000

    Note that "ethX" is the partition and the speed is the partition's new
    maximum Bandwidth value in 1 Mbps increments (i.e. it is NOT a percentage).
    For a 10GbE link connection you could set it from 100 (which is equivalent
    to 100 Mbps or 1% of the 10 GbE link speed) to 10000 (which is equivalent
    to 10 Gbps or 100% of the 10 GbE link speed), with 100 Mbps granularity.
    For a 1GbE link connection you could set it from 10 (which is equivalent
    to 10 Mbps or 1% of the 1 GbE link speed) to 1000 (which is equivalent to
    1 Gbps or 100% of the 1 GbE link speed), with 10 Mbps granularity.

    Note that you cannot change the Relative Bandwidth Weight value using ethtool.

11. Set UDP 4-tupple hash:

    ethtool -N eth0 rx-flow-hash udp4 sdfn

    Note that for UDP over IPv4/IPv6 either 2-tuple and 4-tuple hash is
    supported, while for TCP only 4-tuple hash is supported.

12. See ethtool man page for more options.

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

The optional parameter "dropless_fc" can be used to enable a complementary
flow control mechanism on 57711, 57711E, 57712 or 578xx. The default flow
control mechanism is to send pause frames when the on chip buffer (BRB) is
reaching a certain level of occupancy. This is a performance targeted flow
control mechanism. On 57711, 57711E, 57712 or 578xx one can enable another flow
control mechanism to send pause frames in case where one of the host buffers
(when in RSS mode) are exhausted. This is a "zero packet drop" targeted flow
control mechanism.

Set the "dropless_fc" parameter to 1 as shown below to enable the dropless
flow control mechanism feature on all 57711 or 57711E NetXtreme II NICs in the
system. The parameters will also work on 57712 and 578xx devices with DCBX
feature disabled or in case of DCB protocol has negotiated pause flow control
with a link partner.

   insmod bnx2x.ko dropless_fc=1

or

   modprobe bnx2x dropless_fc=1

The optional parameter "autogreeen" can be used to force specific AutoGrEEEN
behavior. By default, the driver will use the nvram settings per port, but if
the module parameter is set, it can override the nvram settings to force
AutoGrEEEN to either active (1) or inactive (2). The default value of 0 to use
the nvram settings.

The optional parameter "native_eee" can be used to force specfic EEE behaviour.
By default, the driver will use the nvram settings per port, but if the module
parameter is set, it can force EEE to be enabled, and the value will be used
as the idle time required prior to entering Tx LPI. The default value of 0 
indicates usage of the nvram settings.

The optional parameter "num_queues" can be used to force number of RSS queues
and override the default value which is equals to number of CPUs (limited by
HW capabilities).

The optional parameter "pri_map" is used to map the skb-priority to a Class Of
Service (CoS) in the HW. This 32 bit parameter is evaluated by the  driver as 8
values of 4 bits each. Each nibble sets the desired Class Of Service for that
priority.

This parameter is only available in kernels which support mapping skb
priorities to traffic classes and traffic classes to transmission queues. This
means kernel 2.6.39 or newer.

On the 5771x family three classes of service are available, but are always
served in round robin manner allowing small bulk high priority traffic to be
serviced before low priority large bulk traffic by assigning it a separate COS
and thus a separate hardware queue. More advanced COS features such as Strict
Priority, Enhanced Transmission Selection and Priority Flow Control are
unavailable as the hardware doesn't support them.

On the 57712 family two classes of service are available, with complete Data
Center Bridging support (including SP, ETS and PFC).

On the 578xx family three classes of service are available, with complete Data
Center Bridging support (including SP, ETS and PFC).

Configuring  priorities to unavailable COSs will log an error and default to
COS 0.

For example, set the pri_map parameter to 0x22221100 to map priority 0 and 1 to
CoS 0, map priority 2 and 3 to CoS 1, and map priority 4 to 7 to CoS 2. Another
example, set the pri_map parameter to 0x11110000 to map priority 0 to 3 to CoS
0, and map priority 4 to 7 to CoS 1.

The optional parameter "tx_switching" makes the L2 transmitter test for each
transmitted packet whether packet is intended for the transmitting NIC. This is
only relevant in multifunction mode, especially in virtualized environments. For
example, if the destination mac address of the transmitted packet belongs to
another function in the same port, and other conditions such as vlan are met,
the packet is loopbacked instead of being transmitted on the wire. In certain
cases the packet is replicated both to the loopback and the wire. An example for
this is the receiver being in promiscuous mode. Important: enabling tx-switching
has performance penalties, even if no tx-switching is taking place (testing
whether the packets need to be loopbacked is the cause for the penalty). By
default tx-switching is disabled.

   modprobe bnx2x tx_switching=1

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

Speed :                    According to nvram configuration, but in general
                           Autonegotiation with all speeds advertised.

Flow control :             According to nvram configuration, but in general
                           Autonegotiation with rx and tx advertised. Note that
                           for adapters/interfaces which do not support flow
                           control autonegotiation, ie SFP+, driver default will
                           be off if the nvram is set to autonegotiation.

MTU :                      1500 (range 46 - 9000)

Rx Ring size :             4078/(number of RSS queues) (range 128 - 4078)

Tx Ring size :             4078 (range (MAX_SKB_FRAGS+4) - 4078)

                           MAX_SKB_FRAGS varies on different kernels and
                           different architectures. On a 2.6 kernel for x86,
                           MAX_SKB_FRAGS is 18.

Coalesce rx usecs :        25 (range 0 - 3000)

Coalesce tx usecs :        50 (range 0 - 12288)

MSI-X :                    Enabled (if supported by 2.6 kernel)

TSO :                      Enabled

WoL :                      According to nvram configuration for OOB WoL.


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

SR-IOV SUPPORT
==============
SR-IOV stands for Single Root Input Output Virtualization. In SRIOV a single
physical device can identify over the PCI, in addition to its own PCI id, as
multiple virtual devices. In networking, these additional devices are
lightweight nics. Physical devices are noted as Physical Functions, or PFs in
short. Likewise Virtual devices are noted as VFs.

bnx2x
In the bnx2x solution, the VFs have only fastpath components (tx/rx rings,
interrupts) while the PF which spawned them manages the slowpath for itself as
well as that of all of its virtual offspring.
The same bnx2x module used to drive PFs is used to drive VFs as well (single
binary). This means that no additional module needs to be loaded for VFs.
This also means that the VF devices will be probed as soon as they appear
in the Hypervisor.

PCI Passthrough
SR-IOV is particularly useful in conjunction with PCI passthrough, where
devices, be they physical or virtual, are passed through’to Virtual Machines.
in PCI passthrough, in contrast with classic virtualization, no emulation of
the device is being performed by the HyperVisor.
Instead, the device is passed through as is into the VM, and the VM is
responsible to operate the device. Interrupts and BARs are handed over directly
to the VM, and the hypervisor relinquishes control over the device. A passed
through VF can supply its hosting VM with high quality networking in terms of
traffic and CPU (since no HyperVisor intervention takes place). SR-IOV is
particularly useful alongside PCI passthrough since a single PF can spawn
multiple VFs, and then pass them through into multiple VMs, thus supplying
multiple VMs with high performance networking while saving on CPU usage.
The alternatives, either the HyperVisor emulating multiple nics over a single
PF (classic Virtualization) or passing through the PF itself (Physical Device
Assignment), suffer greatly from poor performance and high CPU usage (the
former) or too few nics to go around and severe security issues (the latter).

Activation
SR-IOV can be activated with the num_vfs module parameter like this:
modprobe bnx2x num_vfs=<num of VFs, 1..64>
The actuall number of VFs will be derived from this parameter, as well as the
vf max value configured by CCM.
Only when the PF device is loaded, will the VF devices appear in lspci. At this
point the devices can be passed through to VMs (or they can be used in the
HyperVisor).
VF devices have all zeroes mac addresses be default. The user must configure
a mac address for the VFs before they can be loaded. This can be donw directly
against the VF device (whether the device is in the HyperVisor or in a VM).
Alternately, the user can configure the mac address to a VF from the hypervisor
against the PF device using the iproute2 suite commands, e.g.
ip link set <pf device> vf <vf index> mac <mac address>
MAC addresses configured to a VF by the hypervisor trump any configuration
done against the Vf device.

Limitations
VFs can only operate as long as their PF stays loaded. unloading the PF or
removing the driver altogether when a PF has VFs, especially when passed
through, should be avoided. VFs whose PF was unloaded are "stranded", meaning
they are no longer operational and cannot pass traffic. Loading the PF again
will not change this state. Only removing the module in all VMs and in the
hypervisor and probing again can fix it.
VFs do not support RSS (each only has a single queue). This is planned to be
supported in future releases.

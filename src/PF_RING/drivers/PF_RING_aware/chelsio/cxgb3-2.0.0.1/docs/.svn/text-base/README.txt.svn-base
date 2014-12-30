                    ****************************************
                                   README

                    ****************************************
	
                       Chelsio T3 Network Driver for Linux


                             Version : 2.0.0.1
                             Date    : 08/23/2012



Overview
================================================================================

Chelsio T3 network driver package installs Network (NIC/TOE) driver, Offload
bonding driver and various utility tools (cop,cxgbtool,perftune.sh)for Chelsio's
T3 10/1G adapters.



================================================================================
  CONTENTS
================================================================================

- 1. Requirements
- 2. Supported Operating System
- 3. Supported Cards
- 4. How to Use
- 5. Support Documentation
- 6. Customer Support



1. Requirements
================================================================================

- Chelsio - T3 10/1Gb adapter and system with below mentioned supported platforms.



2. Supported Operating System
================================================================================

- Redhat Enterprise Linux 4 update 3 kernel   (RHEL4.3)		2.6.9-34.EL
- Redhat Enterprise Linux 4 update 4 kernel   (RHEL4.4)		2.6.9-42.EL
- Redhat Enterprise Linux 4 update 5 kernel   (RHEL4.5)		2.6.9-55.EL
- Redhat Enterprise Linux 4 update 6 kernel   (RHEL4.6)		2.6.9-67.EL
- Redhat Enterprise Linux 4 update 7 kernel   (RHEL4.7)		2.6.9-78.EL
- Redhat Enterprise Linux 4 update 8 kernel   (RHEL4.8)		2.6.9-89.EL
- Redhat Enterprise Linux 5 base kernel       (RHEL5)		2.6.18-8.el5
- Redhat Enterprise Linux 5 update 1 kernel   (RHEL5.1)		2.6.18-53.el5
- Redhat Enterprise Linux 5 update 2 kernel   (RHEL5.2)		2.6.18-92.el5
- Redhat Enterprise Linux 5 update 3 kernel   (RHEL5.3)		2.6.18-128.el5
- Redhat Enterprise Linux 5 update 4 kernel   (RHEL5.4)		2.6.18-164.el5
- Redhat Enterprise Linux 5 update 5 kernel   (RHEL5.5)		2.6.18-194.el5
- Redhat Enterprise Linux 5 update 6 kernel   (RHEL5.6)		2.6.18-238.el5
- Redhat Enterprise Linux 5 update 7 kernel   (RHEL5.7)		2.6.18-274.el5
- Redhat Enterprise Linux 5 update 8 kernel   (RHEL5.8)		2.6.18-308.el5
- Redhat Enterprise Linux 6 base kernel       (RHEL6)		2.6.32-71.el6  
- Redhat Enterprise Linux 6 update 1 kernel   (RHEL6.1)		2.6.32-131.0.15.el6
- Redhat Enterprise Linux 6 update 2 kernel   (RHEL6.2)		2.6.32-220.el6
- Redhat Enterprise Linux 6 update 3 kernel   (RHEL6.3)		2.6.32-279.el6 
- Suse Linux Enterprise Server 10 SP2 kernel  (SLES10.2)	2.6.16.60-0.21
- Suse Linux Enterprise Server 10 SP3 kernel  (SLES10.3)	2.6.16.60-0.54.5
- Suse Linux Enterprise Server 11 base kernel (SLES11)		2.6.27.19-5
- Suse Linux Enterprise Server 11 SP1 kernel  (SLES11.1)	2.6.32.12-0.7
- Kernel.org linux-2.6.19 - linux-2.6.36

Offload (TOE) support is available on x86_64, i386, and ia64 architectures.


The offloaded bonding driver is supported on the following kernels:

- Redhat Enterprise Linux 4 update 4 kernel   (RHEL4.4)		2.6.9-42.EL
- Redhat Enterprise Linux 4 update 5 kernel   (RHEL4.5)		2.6.9-55.EL
- Redhat Enterprise Linux 4 update 6 kernel   (RHEL4.6)		2.6.9-67.EL
- Redhat Enterprise Linux 4 update 7 kernel   (RHEL4.7)		2.6.9-78.EL
- Redhat Enterprise Linux 4 update 8 kernel   (RHEL4.8)		2.6.9-89.EL
- Redhat Enterprise Linux 5 base kernel       (RHEL5)		2.6.18-8.el5
- Redhat Enterprise Linux 5 update 1 kernel   (RHEL5.1)		2.6.18-53.el5
- Redhat Enterprise Linux 5 update 2 kernel   (RHEL5.2)		2.6.18-92.el5
- Redhat Enterprise Linux 5 update 3 kernel   (RHEL5.3)		2.6.18-128.el5
- Redhat Enterprise Linux 5 update 4 kernel   (RHEL5.4)		2.6.18-164.el5
- Redhat Enterprise Linux 5 update 5 kernel   (RHEL5.5)		2.6.18-194.el5
- Redhat Enterprise Linux 5 update 6 kernel   (RHEL5.6)		2.6.18-238.el5
- Redhat Enterprise Linux 5 update 7 kernel   (RHEL5.7)		2.6.18-274.el5
- Redhat Enterprise Linux 5 update 8 kernel   (RHEL5.8)		2.6.18-308.el5
- Redhat Enterprise Linux 6 base kernel       (RHEL6)		2.6.32-71.el6  
- Redhat Enterprise Linux 6 update 1 kernel   (RHEL6.1)		2.6.32-131.0.15.el6
- Redhat Enterprise Linux 6 update 2 kernel   (RHEL6.2)		2.6.32-220.el6 
- Suse Linux Enterprise Server 10 SP2 kernel  (SLES10.2)	2.6.16.60-0.21
- Suse Linux Enterprise Server 10 SP3 kernel  (SLES10.3)	2.6.16.60-0.54.5
- Suse Linux Enterprise Server 11 base kernel (SLES11)		2.6.27.19-5
- Suse Linux Enterprise Server 11 SP1 kernel  (SLES11.1)	2.6.32.12-0.7
- Kernel.org linux-2.6.19 - linux-2.6.36


Other kernel versions have not been tested and are not guaranteed to work.



3. Supported Cards
================================================================================

- S302E
- S302E-C
- S310E-CR
- S310E-CR-C
- S310E-CXA
- S310E-SR+
- S310E-SR
- S310E-BT
- S320E-CR
- S320E-LP-CR
- S320E-CXA
- S320EM-BS
- S320EM-BCH
- N320E-G2-CR
- N320E
- N320E-CXA
- N320E-BT
- N310E
- N310E-CXA  



4. How to Use
================================================================================

4.1. Driver Installation
========================================

a. Using Source:
------------------

The driver must be installed by the root user. Any attempt to install the driver
as a regular user will fail.

If building the driver for a kernel other than the current running kernel, it is
necessary to pass in KSRC=<kernelsource> to make. Furthermore, if your build 
tree is in a different location than the source tree, you will need to pass in 
KOBJ=<kernelobj> to make as well.

The src directory contains the driver source files for building kernel modules. 
To build the TOE driver, change to the src/ directory and run:

[root@host]# make
[root@host]# make install

To build the NIC driver (without offload support),change to src/ directory 
and run:

[root@host]# make nic
[root@host]# make nic install

Only one type of driver needs to be compiled, NIC or TOE, not both. The TOE 
driver is built by default without passing any arguments to make. Compiling the 
TOE driver also provides NIC only support if the 't3_tom' driver is not loaded. 
Once the t3_tom module is loaded, all new TCP connections will be offloaded. If 
there are any TCP listening servers started before t3_tom has been loaded, it 
will be necessary to restart those servers for TCP to be offloaded.


b. Using RPM
-----------------

The driver may be built as an RPM for the current running kernel. To build the 
driver RPM, change to src/ directory and run:

[root@host]# make rpm

OR

[root@host]# make nic rpm

The rpm binary will be located in the src/ directory.


**NOTE: If OFED package is already installed, installing cxgb3toe-<x.x.x.x> rpm 
will cause conflicts with kernel-ib rpm. Workaround for this is either install 
cxgb3toe-<x.x.x.x> using "make && make install" or delete kernel-ib rpm first 
and then install cxgb3toe-<x.x.x.x> rpm.



4.2. Tools
================================================================================

The tools/ directory contains user-space apps and/or scripts. To compile the 
tools, change to the desired subdirectory and run:

[root@host]# make
[root@host]# make install

Scripts provided may be copied to their desired location.



4.3. Firmware Update
================================================================================

The T3 firmware (7.12.0) is installed on the system, typically in 
/lib/firmware/cxgb3,and the driver will auto-load the firmware if an update is 
required. The kernel must be configured to enable userspace firmware loading 
support:

Device Drivers -> Generic Driver Options -> Userspace firmware loading support

The firmware image is located in src/firmware. In the event that the firmware is
not installed, or the driver does not locate the firmware directory, manual 
update may be necessary.

To manually update the firmware, use cxgbtool:

[root@host]# cxgbtool <iface> loadfw <t3fw-x.x.x.bin>

The firmware version can be verified using ethtool:

[root@host]# ethtool -i <iface>



4.4. Driver Loading/Unloading
================================================================================

a. Loading the driver
----------------------

The driver must be loaded by the root user. Any attempt to loading the driver as
a regular user will fail.
   
i. To load the driver in NIC mode(without offload support)
   
   [root@host]# modprobe cxgb3

ii. To load driver in TOE mode(with offload support)

   [root@host]# modprobe t3_tom
   
NOTE:
Offload support needs to be enabled upon each reboot of the system. This can be 
done manually as shown above.


b. Unloading the driver
-----------------------

i. To unload the NIC driver.

   [root@host]# rmmod cxgb3

ii. To unload the TOE driver.

Please reboot the system to unload the TOE driver.



4.5. Driver Uninstallation
========================================

To uninstall the driver , change to src/ directory and run the following 
command:

[root@host]# make uninstall



5. Support Documentation
================================================================================

The documentation for this release can be found inside the cxgb3toe-x.x.x.x/docs 
folder. 
It contains:

- README
- Release Notes
- User's Guide



6. Customer Support
================================================================================

Please contact Chelsio support at support@chelsio.com for any issues regarding 
the product.








********************************************************************************
Copyright (C) 2012 Chelsio Communications. All Rights Reserved

The information in this document is furnished for informational use only, is
subject to change without notice, and should not be construed as a commitment by
Chelsio Communications. Chelsio Communications assumes no responsibility or
liability for any errors or inaccuracies that may appear in this document or any
software that may be provided in association with this document. Except as
permitted by such license, no part of this document may be reproduced, stored in
a retrieval system,or transmitted in any form or by any means without the
express written consent of Chelsio Communications.

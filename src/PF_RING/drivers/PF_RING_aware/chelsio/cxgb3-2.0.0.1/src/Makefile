# Makefile for Chelsio T3 Offload driver.
# Copyright (c) 2006-2008 Chelsio Communications, Inc.
SHELL = /bin/bash

# Subdirectories to build, ordered list.
# This list order should not be modified do to symbol requirements.
#SUBDIRS := cxgb3 toecore t3_tom bonding
SUBDIRS := cxgb3

# Define offload drivers.
offload_dirs := toecore t3_tom bonding

# Define offload options.
txzcopy = 1

# Some subdirectories don't need to be compiled, but need to be installed.
INSTALLDIRS := $(SUBDIRS) firmware
ifeq ($(wildcard protosram),protosram)
  INSTALLDIRS += protosram
endif

ifeq ($(wildcard phyedc),phyedc)
  INSTALLDIRS += phyedc
endif

# Honor the -s (silent) make option.
verbose := $(if $(filter s,$(MAKEFLAGS)),,-v)

# Define paths.
srcdir := $(shell pwd)
topdir := $(shell cd $(srcdir)/.. && pwd)

# Define grep error output to NULL, since -s is not portable.
grep = grep 2>/dev/null

# Variables for RPM.
rpmdir = $(topdir)/rpmbuild
rpmrelease = custom

# Kernel directories.
KERNELRELEASE := $(shell uname -r)
# If KSRC=<path> is specified on the command line, KOBJ=<path> must
# also be specified. This is to avoid mixups if the kernel object path
# differs from the source path. A shortcut (KSRC=KOBJ) is to use KDIR.
ifeq ($(KDIR),)
  ifeq ($(KSRC),)
    ifneq ($(KOBJ),)
      $(warning When using KOBJ=<path>, the KSRC=<path> must also be defined.)
      $(warning Use KDIR=<path> when KSRC and KOBJ are the same.)
      $(error ERROR: kernel source path not specified)
    endif
  else
    ifeq ($(KOBJ),)
      $(warning When using KSRC=<path>, the KOBJ=<path> must also be defined.)
      $(warning Use KDIR=<path> when KSRC and KOBJ are the same.)
      $(error ERROR: KOBJ path not specified)
    endif
  endif
else
  override KSRC := $(KDIR)
  override KOBJ := $(KDIR)
endif

# Only if KSRC/KOBJ were not defined on the command line.
KSRC ?= $(wildcard /lib/modules/$(KERNELRELEASE)/source)
KOBJ ?= $(wildcard /lib/modules/$(KERNELRELEASE)/build)

# If this is a 2.4 kernel and KSRC/KOBJ is still not defined, it is probably
# because there is no source|build directory in /lib/modules/version/. Try
# to use /usr/src/linux-2.4 and print a warning to the user that this may
# not be correct.
ifeq ($(KSRC),)
  ifneq ($(wildcard /usr/src/linux-2.4),)
    $(warning Using KSRC from /usr/src/linux-2.4.)
    $(warning This may or may not be the correct kernel.)
    $(warning If not, you can override this selection by)
    $(warning using KSRC=<path> or KDIR=<path>.)
    KSRC = /usr/src/linux-2.4
  endif
endif
ifeq ($(KOBJ),)
  ifneq ($(wildcard /usr/src/linux-2.4),)
    $(warning Using KOBJ from /usr/src/linux-2.4.)
    $(warning This may or may not be the correct kernel.)
    $(warning If not, you can override this selection by)
    $(warning using KOBJ=<path> or KDIR=<path>.)
    KOBJ = /usr/src/linux-2.4
  endif
endif
KINC  = $(KSRC)/include

# Define kernel files.
VERSION_H  := $(KOBJ)/include/linux/version.h
AUTOCONF_H := $(KOBJ)/include/generated/autoconf.h
UTSRELEASE_H  := $(KOBJ)/include/generated/utsrelease.h

ifeq ($(wildcard $(AUTOCONF_H)),)
  AUTOCONF_H := $(KOBJ)/include/linux/autoconf.h
endif
ifeq ($(wildcard $(UTSRELEASE_H)),)
  UTSRELEASE_H := $(KOBJ)/include/linux/utsrelease.h
endif
# Define architecture and target(for RPM).
ARCH := $(shell uname -m)
target := $(ARCH)
override ARCH := $(shell echo $(ARCH) | sed 's/i.86/i386/')
ifeq ($(USER_ARCH),)
  ifeq ($(ARCH),ppc64)
    # Check if the kernel wants ppc64 or powerpc.
    ifeq ($(wildcard $(KOBJ)/arch/$(ARCH)),)
      override ARCH := powerpc
    endif
  endif
else
  # Honor the value of ARCH if specified by user.
  override ARCH := $(USER_ARCH)
endif

# This makefile performs configuration before building/installing any
# driver. The configuration is not required for targets that are not
# defined in 'config_targets'.
config_targets = nic toe xen rpm install uninstall distclean clean $(SUBDIRS)
override config = 1

ifeq ($(MAKECMDGOALS),)
  override MAKECMDGOALS = toe
endif
ifeq ($(filter $(config_targets),$(MAKECMDGOALS)),)
  override config = 0
endif

# Functions.
define path_check
$(if $(wildcard $(1)),$(1),)
endef
define reverse_sort
$(shell echo -e `echo "$(strip $(1))" |\
                 sed 's/[[:space:]]/\\\n/g'` | sort -r)
endef
define version_code
$(shell let x=`sed '/^\#define[[:space:]]*LINUX_VERSION_CODE/!d;\
                    s/.*LINUX_VERSION_CODE[[:space:]]*//' < $(1)\
               2>/dev/null`;\
        let a="$$x >> 16";\
        let x="$$x - ($$a << 16)";\
        let b="$$x >> 8";\
        let x="$$x - ($$b << 8)";\
        echo "$$a $$b $$x")
endef
define setup_bonding_src
$(shell cd bonding/;\
        for file in $(1)/*.[ch]; do \
	  ln -fs $$file || { err=1; break; };\
	done;\
	echo $$err;)
endef
define clean_symlinks
$(shell cd $(1)/;\
        if [ -z "$(2)" ]; then \
          pattern='*.[ch]';\
        else \
          pattern='$(2)';\
        fi;\
        for symlink in $$pattern; do \
	  [ ! -L $$symlink ] && continue;\
	  /bin/rm -f $$symlink;\
	done;)
endef
define get_pkgversion
$(shell pkgversion=`sed '/^Package Vers:[[:space:]]*/!d;\
                         s/^Package Vers:[[:space:]]*//' 2>/dev/null \
			 <$(topdir)/RELEASE`;\
        buildnumber=`sed '/^Build Number:[[:space:]]*/!d;\
                          s/^Build Number:[[:space:]]*//' 2>/dev/null \
			  <$(topdir)/RELEASE`;\
        if [ -n "$$pkgversion" ] && [ -n "$$buildnumber" ]; then \
	        echo "$$pkgversion.$$buildnumber";\
	else \
		echo "NONRELEASE";\
	fi;)
endef
define get_pkgname
$(shell pkgname=`sed '/^Package Name:[[:space:]]*/!d;\
                 s/^Package Name:[[:space:]]*\(.*\)-$(call get_pkgversion).*$$/\1/' \
	         2>/dev/null <$(topdir)/RELEASE`;\
	if [ -n "$$pkgname" ]; then \
		echo "$$pkgname";\
	else \
		echo "cxgb3toe";\
	fi;)
endef

# The following section of this makefile will be ignored if the target has
# been defined as not requiring configuration.
ifeq ($(config),1)

# Defines and checks for RPM build.
pkgvers := $(call get_pkgversion)
pkgname := $(call get_pkgname)
ifneq ($(filter rpm,$(MAKECMDGOALS)),)
  ifeq ($(pkgvers),)
    override rpm_fail = 1
    $(warning Package version not found in $(topdir)/RELEASE)
  endif
  ifeq ($(pkgname),)
    override rpm_fail = 1
    $(warning Package name not found in $(topdir)/RELEASE)
  endif
  ifeq ($(rpm_fail),1)
    $(error ERROR: RPM build not possible)
  endif
endif

# Checks for kernel source and object directories.
ifeq ($(call path_check,$(KSRC)),)
  $(warning Be sure the kernel source is properly installed or \
            try specifying the kernel source tree using 'make KSRC=<path>')
  $(error ERROR: missing kernel source)
endif
ifeq ($(call path_check,$(KOBJ)),)
  $(warning Try specifying the kernel build tree using 'make KOBJ=<path>'.)
  $(error ERROR: missing kernel build)
endif

# Check kernel source and build directories are somewhat likely to be correct.
ifneq ($(notdir $(wildcard $(KSRC)/Makefile)),Makefile)
  $(warning There seems to be a problem with the kernel \
            source [$(KSRC)] directory.)
  $(error ERROR: missing kernel Makefile)
endif
ifneq ($(notdir $(wildcard $(KOBJ)/Makefile)),Makefile)
  $(warning There seems to be a problem with the kernel \
            build [$(KOBJ)] directory.)
  $(error ERROR: missing kernel Makefile)
endif

# Get kernel version code info.
KERNELVERSION := $(strip $(call version_code,$(VERSION_H)))
ifneq ($(words $(KERNELVERSION)), 3)
  $(error ERROR: unexpected kernel version \
          '$(shell echo $(KERNELVERSION) | sed 's/[[:space:]]/./g')')
endif

# Define kernel version details.
kversion       := $(word 1, $(KERNELVERSION))
kpatchlevel    := $(word 2, $(KERNELVERSION))
ksublevel      := $(word 3, $(KERNELVERSION))
# The kernel base version, excluding the EXTRAVERSION string.
kbaseversion   := $(kversion).$(kpatchlevel).$(ksublevel)
# The kernel series version.
kseries        := $(kversion).$(kpatchlevel)

ifneq ($(kseries),2.6)
  override modsym =
else
  override modsym = 1
endif

ifeq ($(modsym),1)
# Fix for variation of Module.symvers naming (thanks 2.6.17!).
# I need to know the file name of the module symver generated by the kernel
# during an external module build (MODPOST). Also used for kernels that don't
# automatically generate the module symver file during MODPOST (2.6.0-2.6.17?).
ifeq ($(shell $(grep) -c '^modulesymfile[[:space:]]*:\?=' \
                $(KSRC)/scripts/Makefile.modpost),1)
  modulesymfile := $(shell $(grep) '^modulesymfile[[:space:]]*:\?=' \
                             $(KSRC)/scripts/Makefile.modpost)
  kernelsymfile := $(shell $(grep) '^kernelsymfile[[:space:]]*:\?=' \
                             $(KSRC)/scripts/Makefile.modpost)
else
ifeq ($(shell $(grep) -c '^symverfile[[:space:]]*:\?=' \
                $(KSRC)/scripts/Makefile.modpost),1)
  symverfile    := $(shell $(grep) '^symverfile[[:space:]]*:\?=' \
                             $(KSRC)/scripts/Makefile.modpost)
  kernelsymfile := $(subst symverfile,kernelsymfile,$(symverfile))
endif
endif
modulesymfile ?= $(symverfile)
ifeq ($(modulesymfile),)
  $(warning The parsing of $(KSRC)/scripts/Makefile.modpost \
            is not making sense.)
  $(error ERROR cannot determine module symvers file)
endif

# Gnu make (3.80) bug #1516, $(eval ...) inside conditionals causes errors.
# This is fixed in v3.81 and some v3.80 (RHEL4/5) but not on SLES10.
# Workaround: include a separate makefile that does the eval.
ifeq ($(shell echo '$(modulesymfile)' | $(grep) -c '^[[:alnum:]_]\+[[:space:]]*:\?=[[:space:]]*.\+'),1)
  $(shell echo '$$(eval $$(modulesymfile))' > eval.mak)
  include eval.mak
  #$(eval $(modulesymfile))
else
  modulesymfile =
endif
ifeq ($(shell echo '$(kernelsymfile)' | $(grep) -c '^[[:alnum:]_]\+[[:space:]]*:\?=[[:space:]]*.\+'),1)
  $(shell echo '$$(eval $$(kernelsymfile))' > eval.mak)
  include eval.mak
  #$(eval $(kernelsymfile))
else
  kernelsymfile =
endif
modulesymfile := $(notdir $(modulesymfile))
kernelsymfile := $(notdir $(kernelsymfile))
$(shell [ -f eval.mak ] && /bin/rm -f eval.mak)

ifneq ($(words $(modulesymfile)),1)
  $(warning The parsing of $(KSRC)/scripts/Makefile.modpost \
            is not making sense.)
  $(warning You can try passing 'modulesymfile=Module.symvers' or \
            similar to make.)
  $(error ERROR cannot determine module symvers file)
endif
endif # modsym == 1

# Check for configured kernel.
ifeq ($(wildcard $(AUTOCONF_H)),)
  $(warning The kernel is not properly configured, try running \
            'make menuconfig' on your kernel.)
  $(error ERROR: kernel missing autoconf.h)
endif
# Check for built kernel.
ifeq ($(wildcard $(VERSION_H)),)
  $(warning The kernel has not been compiled. Try building your kernel \
            before building this driver.)
  $(error ERROR: kernel missing version.h)
endif

# Check that kernel supports modules.
ifneq ($(shell $(grep) -c '^\#define[[:space:]]\+CONFIG_MODULES[[:space:]]\+1' $(AUTOCONF_H)),1)
  $(warning The kernel has not been configured for module support.)
  $(warning Try configuring the kernel to allow external modules and \
            recompile.)
  $(error ERROR: kernel CONFIG_MODULES not defined)
endif

# Get kernel UTS_RELEASE info.
ifneq ($(wildcard $(UTSRELEASE_H)),)
  ifneq ($(shell $(grep) -c '^\#define[[:space:]]\+UTS_RELEASE' \
                  $(UTSRELEASE_H)),0)
    utsrelease := $(UTSRELEASE_H)
  endif
else
ifneq ($(wildcard $(KOBJ)/include/linux/version.h),)
  ifneq ($(shell $(grep) -c '^\#define[[:space:]]\+UTS_RELEASE' \
                  $(KOBJ)/include/linux/version.h),0)
    utsrelease := $(KOBJ)/include/linux/version.h
  endif
endif
endif
ifeq ($(utsrelease),)
  $(error ERROR: cannot locate kernel UTS_RELEASE)
endif
# Getting the UTS_RELEASE on RHEL3 had problems due to the multiple defines
# within the file. I can run this file through the C pre-processor and get 
# the actual UTS_RELEASE definition. This has only been tested on gcc, other
# compilers may not work.
utsrelease := $(strip $(shell $(CC) -E -dM -I $(KSRC)/include $(utsrelease) \
                        2>/dev/null| sed '/^\#define[[:space:]]*UTS_RELEASE/!d;\
		                          s/^\#define UTS_RELEASE[[:space:]]*"//;\
					  s/"//g'))

# The kernel local version string if defined in config.
klocalversion  := $(shell sed '/^CONFIG_LOCALVERSION=/!d;\
                               s/^CONFIG_LOCALVERSION="//;s/"//g'\
                            2>/dev/null < $(KOBJ)/.config)
# The complete kernel EXTRAVERSION string.
kextraversion  := $(subst $(kbaseversion),,$(utsrelease))
# The full kernel version should be the same as uts_release.
kernelversion  := $(utsrelease)

# The kernel EXTRAVERSION creates a unique problem, especially since
# kernel versioning extended into the EXTRAVERSION and distributions 
# add strings such as smp, largesmp, xen, etc or when additional minor
# version numbers are appended.
# Some code that we supply is dependent on the kernel version and
# parts of the EXTRAVERSION, but not dependent on some of the additional
# flags. This requires that I have a list of kernel version strings that
# could map to the source version we require. For example, if the
# kernel version is 2.6.9-67.ELsmp, we only care about the "2.6.9-67"
# part, therefore, I need to split the EXTRAVERSION accordingly.
# Another problem is when a user builds their own kernel, say 2.6.21.4
# and adds an additional string to EXTRAVERSION. The EXTRAVERSION is
# now ".4-custom" and I have to parse this with hopes of extracting
# only the ".4" part, resulting in the needed "2.6.21.4" version.
# Adding a BUGFIX version (int) field would be very helpfull!

# EXTRAVERSION as defined only in the Makefile.
extraversion1 := $(strip $(shell sed '/^EXTRAVERSION/!d;\
                                      s/^EXTRAVERSION[[:space:]]*=//;s/"//g'\
                                    < $(KSRC)/Makefile 2>/dev/null))
# SLES9 likes to put make code in their EXTRAVERSION define. Let the
# variables expand out to nothing, because the code will cause problems.
extraversion1 := $(shell echo $(extraversion1))
# EXTRAVERSION without local version.
extraversion2 := $(strip $(subst $(klocalversion),,$(kextraversion)))
# EXTRAVERSION with only the kernel .version (hopefully).
extraversion3 := $(strip $(shell echo $(kextraversion) |\
				  sed 's/\(^\.[0-9]*\).*/\1/'))
# EXTRAVERSION without the Redhat EL tag.
extraversion4 := $(strip $(shell echo $(kextraversion) |\
			          sed 's/\.EL.*//i'))
# EXTRAVERSION with the Redhat EL tag, but nothing else after.
extraversion5 := $(strip $(shell echo $(kextraversion) |\
			          sed 's/\(\.EL\).*/\1/i'))
# EXTRAVERSION with the Redhat EL tag, including a number (el5).
extraversion6 := $(strip $(shell echo $(kextraversion) |\
			          sed 's/\(\.EL[[:digit:]]*\).*/\1/i'))
# EXTRAVERSION without the Redhat hotfix/update kernel version number.
extraversion7 := $(strip $(shell echo $(kextraversion) |\
			          sed 's/\(.*\-[[:digit:]]*\)\..*\(\.EL\).*/\1\2/i'))
# EXTRAVERSION without the Redhat hotfix/update kernel version number with Redhat EL tag, including the number (el5).
extraversion8 := $(strip $(shell echo $(kextraversion) |\
			          sed 's/\(.*\-[[:digit:]]*\)\..*\(\.EL[[:digit:]]\).*/\1\2/i'))
# EXTRAVERSION with only the RHEL distro version
extraversion9 := $(strip $(shell echo $(kextraversion) |\
			          sed 's/\(.*\-[[:digit:]]*\)\..*\.EL[[:digit:]].*/\1/i'))
#EXTRAVERSION with only SLES to ignore -default 
extraversion10 := $(strip $(shell echo $(kextraversion) |\
                                        sed 's/-default//g'))

# All known EXTRAVERSION strings, duplicates removed.
extraversions  := $(strip $(sort $(kextraversion) \
			         $(extraversion1) \
			         $(extraversion2) \
			         $(extraversion3) \
			         $(extraversion4) \
			         $(extraversion5) \
			         $(extraversion6) \
			         $(extraversion7) \
			         $(extraversion8) \
			         $(extraversion9) \
			         $(extraversion10)))
# List of all possible kernel version names for target kernel.
all_kernels    := $(sort $(kbaseversion) \
		         $(foreach a,$(extraversions),$(kbaseversion)$(a)))
# A reverse ordered list. This is used primarily to search source code
# directory names to match the target kernel version.
kversions := $(call reverse_sort, $(all_kernels))

# Check if kernel has toecore built-in.
disable_toecore := $(shell $(grep) -c '^\#define[[:space:]]\+CONFIG_TCP_OFFLOAD[[:space:]]\+1' \
                           $(AUTOCONF_H))

# Don't compile/install any offload drivers if using 'nic' target.
ifeq ($(filter nic,$(MAKECMDGOALS)),nic)
  disable_offload = 1
  disable_bonding = 1
endif

# Compile for XEN
ifeq ($(filter xen,$(MAKECMDGOALS)),xen)
  enable_xen = 1
endif

# Offload not supported if 2.6.5 and toecore not in kernel
ifeq ($(KERNELVERSION),2 6 5)
  ifneq ($(disable_toecore),1)
    disable_offload = 1
    disable_bonding = 1
  endif
endif

# Special cases for 2.4 series kernels.
ifeq ($(kseries),2.4)
  # Firmware auto-load not supported in 2.4.
  INSTALLDIRS := $(filter-out protosram firmware,$(INSTALLDIRS))
  # Kprobes not supported in 2.4.
  kprobes = 0
  # Modular offload driver not supported in 2.4.
  # Also disables offload bonding.
  disable_offload = 1
  disable_bonding = 1
endif

# Cleanup symlinks.
$(call clean_symlinks,bonding)

# Determine bonding source code for target kernel.
ifneq ($(disable_bonding),1)
  bondsrc := $(firstword $(notdir $(strip \
	     $(foreach version,$(kversions), $(wildcard bonding/$(version))))))

  # Does the user define a bonding_version?
  ifneq ($(bonding_version),)
    # Is the user defined bonding version valid?
    ifeq ($(shell [ -d $(srcdir)/bonding/$(bonding_version) ] || echo "1"),1)
      # The bonding_version is invalid
      bondsrc := 
      disable_bonding=1;
    else 
      # bonding_version is valid use it when build bonding driver
      bondsrc := $(bonding_version)
    endif
  else
    # Determine what kernel the extraversion matched. if it matched on the base
    # kernel but was a distro then we need to disable bonding to avoid potential
    # compile time errors.
    ifneq ($(KERNELRELEASE),$(kbaseversion))
      ifeq ($(kbaseversion),$(bondsrc))
        disable_bonding=1;
	bondsrc := 
      endif
    endif
  endif

  ifeq ($(bondsrc),)
    disable_bonding = 1
    $(warning WARNING: The offload bonding driver is not supported \
              on the target kernel. The bonding driver will not be built.)
    post_msg += Bonding driver not compiled.\n
  else
    # Setup the bonding source code so toecore has access to header files.
    # TODO: Indicate level of confidence for discovered source (see function).
    ifneq ($(call setup_bonding_src,$(bondsrc)),)
      $(warning WARNING: An error occured while linking bonding files. \
                The bonding driver will not be built.)
      post_msg += Bonding driver not compiled.\n
      disable_bonding = 1
      bondsrc =
    endif
  endif
endif

# Don't compile/install offload drivers if defined 'disable_offload=1'.
ifeq ($(disable_offload),1)
  SUBDIRS     := $(filter-out $(offload_dirs),$(SUBDIRS))
  INSTALLDIRS := $(filter-out $(offload_dirs),$(INSTALLDIRS))
  disable_toecore = 1
  disable_bonding = 1
  txzcopy = 0
  # Change pkgname when building only nic.
  pkgname := $(subst toe,,$(pkgname))
endif
# Don't compile/install offload bonding driver if defined 'disable_bonding=1'.
ifeq ($(disable_bonding),1)
  SUBDIRS     := $(filter-out bonding,$(SUBDIRS))
  INSTALLDIRS := $(filter-out bonding,$(INSTALLDIRS))
endif
# Don't compile/install toecore driver if defined 'disable_toecore=1'.
ifeq ($(disable_toecore),1)
  SUBDIRS     := $(filter-out toecore,$(SUBDIRS))
  INSTALLDIRS := $(filter-out toecore,$(INSTALLDIRS))
endif

# Note: Define only FLAGS here. These will convert to CFLAGS in the sub-make.
# If the environment variable FLAGS is defined with make, things will break,
# use CFLAGS instead.
# General compiler flags.
FLAGS += -DLINUX -D__KERNEL__ -DMODULE -O2 -pipe -Wall
# For cxgb3 driver module.
FLAGS += -DCONFIG_CHELSIO_T3_CORE
# For t3_tom driver module.
ifneq ($(disable_offload),1)
  FLAGS += -DCONFIG_CHELSIO_T3_OFFLOAD_MODULE
  FLAGS += -DCONFIG_TCP_OFFLOAD_MODULE
endif
# For toecore driver module.
ifeq ($(disable_toecore),1)
  FLAGS := $(filter-out -DCONFIG_TCP_OFFLOAD_MODULE,$(FLAGS))
  ifneq ($(disable_offload),1)
    FLAGS += -DCONFIG_TCP_OFFLOAD
  endif
  # Check for old offload.h
  ifeq ($(shell [ -e  $(KINC)/net/offload.h ] && echo 1), 1)
    ifeq ($(shell $(grep) -c 'sk_ofld_proto' $(KINC)/net/offload.h),0)
      FLAGS += -DOLD_OFFLOAD_H
    endif
  endif
  ifeq ($(shell [ -e $(KINC)/toedev.h ] && echo 1), 1)
    ifeq ($(shell $(grep) -c 'deactivate_offload' $(KINC)/linux/toedev.h),0)
      FLAGS += -DDEACTIVATE_OFFLOAD
    endif
  endif
endif

# Zero copy for offload modules.
ifeq ($(txzcopy),1)
  FLAGS += -DCONFIG_T3_ZCOPY_SENDMSG_MODULE
  ifeq ($(ARCH),x86_64)
    FLAGS += -DCONFIG_T3_ZCOPY_HUGEPAGES
  endif
endif
# For offload bonding support.
ifneq ($(disable_bonding),1)
  FLAGS += -DBOND_SUPPORT
endif
# Other FLAGS.
ifneq ($(shell $(grep) -c 'IRQF_SHARED' $(KINC)/linux/interrupt.h),0)
  FLAGS += -DIRQF
endif
ifneq ($(shell $(grep) -c 'atomic_add_return' $(KINC)/asm/atomic.h),0)
  FLAGS += -DATOMIC_ADD_RETURN
endif
ifneq ($(shell $(grep) -c 'spin_trylock_irqsave' $(KINC)/linux/spinlock.h),0)
  FLAGS += -DSPIN_TRYLOCK_IRQSAVE
endif
ifneq ($(shell $(grep) -c 'rtnl_trylock' $(KINC)/linux/rtnetlink.h),0)
  FLAGS += -DRTNL_TRYLOCK
endif
ifneq ($(shell $(grep) -c 'gso_size' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DGSO_SIZE
endif
ifneq ($(shell $(grep) -c 'gso_type' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DGSO_TYPE
endif
ifneq ($(shell $(grep) -c 'kzalloc' $(KINC)/linux/slab.h),0)
  FLAGS += -DKZALLOC
endif
ifneq ($(shell $(grep) -c 'pci_error_handlers' $(KINC)/linux/pci.h),0)
  FLAGS += -DHAS_EEH
endif
ifneq ($(shell $(grep) -c 'vlan_group_get_device' $(KINC)/linux/if_vlan.h),0)
  FLAGS += -DVLANGRP
endif
ifneq ($(shell $(grep) -c 'skb_copy_from_linear_data' \
               $(KINC)/linux/skbuff.h),0)
  FLAGS += -DNEW_SKB_COPY
endif
ifneq ($(shell $(grep) -c 'i_private' $(KINC)/linux/fs.h),0)
  FLAGS += -DI_PRIVATE
endif
ifneq ($(shell $(grep) -c 'skb_network_offset' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DNEW_SKB_OFFSET
endif
ifneq ($(shell $(grep) -c 'arp_hdr' $(KINC)/linux/if_arp.h),0)
  FLAGS += -DARP_HDR
endif
ifneq ($(shell $(grep) 'transport_header' $(KINC)/linux/skbuff.h | \
		$(grep) -c 'sk_buff_data_t'),0)
  FLAGS += -DTRANSPORT_HEADER
endif
ifneq ($(wildcard $(KINC)/net/netdma.h),)
  FLAGS += -DNETDMA_IN_KERNEL
endif
ifneq ($(shell $(grep) -c 'ioat_sock' $(KINC)/net/netdma.h),0)
  FLAGS += -DIOAT_SOCK
endif
ifneq ($(shell sed '/ip_route_connect/,/{/!d' 2>/dev/null \
                 < $(KINC)/net/route.h | $(grep) -c 'flags'),0)
  FLAGS += -DIP_ROUTE_FLAGS
endif
ifneq ($(shell $(grep) -c 'security_inet_conn_request' \
               $(KINC)/linux/security.h),0)
  FLAGS += -DSEC_INET_CONN_REQUEST
endif
ifneq ($(shell $(grep) -c 'security_inet_conn_established' \
               $(KINC)/linux/security.h),0)
  FLAGS += -DSEC_INET_CONN_ESTABLISHED
endif
ifneq ($(wildcard $(KINC)/net/netevent.h),)
  FLAGS += -DNETEVENT
endif
ifneq ($(shell $(grep) -c 'kallsyms_lookup_name' $(KOBJ)/$(modulesymfile)),0)
  FLAGS += -DKALLSYMS_LOOKUP_NAME
endif
ifneq ($(shell $(grep) -c 'symbol_name' $(KINC)/linux/kprobes.h),0)
  FLAGS += -DKPROBES_SYMBOL_NAME
endif
kallsyms := $(shell $(grep) '[[:space:]]\+kallsyms_lookup_name$$' /proc/kallsyms |\
                    cut -d' ' -f1)
ifneq ($(kallsyms),)
  FLAGS += -DKALLSYMS_LOOKUP=0x$(kallsyms)
endif

ifneq ($(shell $(grep) -c 'skb_transport_offset' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DT3_SKB_TRANSPORT_OFFSET
endif

ifneq ($(shell $(grep) -c 'ip_hdr' $(KINC)/linux/ip.h),0)
  FLAGS += -DT3_IP_HDR
endif

ifneq ($(shell $(grep) -c 'tcp_hdr' $(KINC)/linux/tcp.h),0)
  FLAGS += -DT3_TCP_HDR
endif

ifneq ($(shell $(grep) -c 'skb_reset_mac_header' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DT3_RESET_MAC_HEADER
endif

ifneq ($(shell $(grep) -c 'netif_napi_add' $(KINC)/linux/netdevice.h),0)
  FLAGS += -DNAPI_UPDATE
endif

ifneq ($(shell $(grep) -c 'skb_mac_header' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DT3_MAC_HEADER
endif

ifneq ($(shell $(grep) -c 'sk_filter_uncharge' $(KINC)/net/sock.h),0)
  FLAGS += -DSK_FILTER_UNCHARGE
endif

ifneq ($(shell $(grep) -c 'void inet_inherit_port' $(KINC)/net/inet_hashtables.h),0)
  FLAGS += -DINET_INHERIT_PORT
endif

ifneq ($(shell $(grep) 'pci_dma_mapping_error' $(KINC)/asm-generic/dma-mapping.h | \
		$(grep) -c 'pci_dev'),0)
  FLAGS += -DPDEV_MAPPING
endif
# Linux 2.6.30 moved the prototype declaration of pci_dma_mapping_error()
# to asm-generic/pci-dma-compat.h ...
ifneq ($(shell $(grep) 'pci_dma_mapping_error' $(KINC)/asm-generic/pci-dma-compat.h | \
		$(grep) -c 'pci_dev'),0)
  FLAGS += -DPDEV_MAPPING
endif

ifneq ($(shell $(grep) -c 'vlan_dev_real_dev' $(KINC)/linux/if_vlan.h),0)
  FLAGS += -DVLAN_DEV_API
endif

ifeq ($(shell [ -e  $(KINC)/linux/semaphore.h ] && echo 1), 1)
  FLAGS += -DLINUX_SEMAPHORE_H
endif

ifneq ($(shell $(grep) -c 'highest_sack' $(KINC)/linux/tcp.h),0)
  FLAGS += -DHIGHEST_SACK
endif

ifneq ($(shell $(grep) -c 'get_stats_count' $(KINC)/linux/ethtool.h),0)
  FLAGS += -DGET_STATS_COUNT
endif

ifeq ($(shell [ -e $(KINC)/net/inet_sock.h ] && echo 1),1)
  ifneq ($(shell $(grep) -c 'inet_daddr' $(KINC)/net/inet_sock.h),0)
    FLAGS += -DINET_PREFIX
  endif
endif

ifneq ($(shell $(grep) -c 'skb_dst_set' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DSKB_DST_SET
endif

ifneq ($(shell $(grep) -c 'netdev_get_tx_queue' $(KINC)/linux/netdevice.h),0)
  FLAGS += -DMQ_TX
endif

ifneq ($(shell $(grep) -c 'alloc_etherdev_mq' $(KINC)/linux/etherdevice.h),0)
  FLAGS += -DALLOC_ETHERDEV_MQ_DEF
endif

ifneq ($(shell $(grep) -c 'skb_record_rx_queue' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DSKB_RECORD_RX_QUEUE
endif

ifneq ($(shell $(grep) -c 'ctl_name' $(KINC)/linux/sysctl.h),0)
  FLAGS += -DSYSCTL_CTL_NAME
endif

ifneq ($(shell $(grep) -c 'NIPQUAD' $(KINC)/linux/kernel.h),0)
  FLAGS += -DCXGB3_NIPQUAD
endif

ifeq ($(shell $(grep) -c '__sk_add_backlog' $(KINC)/net/sock.h),0)
  FLAGS += -DCXGB3___SK_ADD_BACKLOG
endif

ifeq ($(shell [ -e  $(KINC)/net/secure_seq.h ] && echo 1), 1)
  FLAGS += -DSECURE_SEQ_H
endif

ifeq ($(shell $(grep) -c '_Bool' $(KINC)/linux/types.h),0)
  FLAGS += -DCXGB3_BOOL
endif

ifeq ($(shell [ -e  $(KINC)/linux/mutex.h ] && echo 1), 1)
  FLAGS += -DT3_LINUX_MUTEX_H
endif

ifneq ($(shell $(grep) -c 'usecs_to_jiffies' $(KINC)/linux/jiffies.h),0)
  FLAGS += -DUSECS_TO_JIFFIES
endif

ifneq ($(shell $(grep) -c "__GFP_MEMALLOC" $(KINC)/linux/gfp.h),0)
  FLAGS += -DGFP_MEMALLOC
endif

# General compiler flags for 2.4 kernels.
ifeq ($(kseries),2.4)
  FLAGS += -DLINUX_2_4
  FLAGS += -DEXPORT_SYMTAB
  ifeq ($(ARCH),x86_64)
    FLAGS += -mcmodel=kernel
  endif
  ifneq ($(shell $(grep) -c 'if_mii' $(KINC)/linux/mii.h),0)
    FLAGS += -DIF_MII
  endif
endif

# Debug flags.
ifeq ($(DEBUG),1)
  FLAGS += -g
  ifeq ($(shell $(grep) -c '^\#define[[:space:]]\+CONFIG_DEBUG_FS[[:space:]]\+1' \
                $(AUTOCONF_H)),1)
    FLAGS += -DT3_TRACE
    ifneq ($(disable_offload),1)
      FLAGS += -DT3_TRACE_TOM
    endif
  endif
endif

# Check if xen option selected 
ifeq ($(enable_xen),1)
  ifeq ($(shell $(grep) -c '^\#define[[:space:]]\+CONFIG_XEN[[:space:]]\+1' \
		$(AUTOCONF_H)),1)
    FLAGS += -DCHELSIO_FREE_TXBUF_ASAP
    FLAGS += -DDISABLE_LRO
  endif
endif

# Don't allow ARCH to overwrite the modified variable when passed to
# the sub-makes.
MAKEOVERRIDES := $(filter-out ARCH=%,$(MAKEOVERRIDES))
# Don't allow CFLAGS/EXTRA_CFLAGS to clobber definitions in sub-make.
MAKEOVERRIDES := $(filter-out CFLAGS=%,$(MAKEOVERRIDES))
MAKEOVERRIDES := $(filter-out EXTRA_CFLAGS=%,$(MAKEOVERRIDES))

# Exports.
export srcdir
export topdir
export KERNELRELEASE
export PREFIX
export INSTALL_MOD_DIR
export KSRC
export KOBJ
export ARCH
export FLAGS += $(CFLAGS) $(EXTRA_CFLAGS) $(CPPFLAGS)
export verbose
export utsrelease
export kversions
export kseries
export modulesymfile
export disable_bonding
export bondsrc
export AUTOCONF_H
export grep

endif # config

.PHONY: *.rpm
.PHONY: eval.mak

.PHONY: nic
nic: default

.PHONY: toe
toe: default

.PHONY: xen
xen: default


.PHONY: default
default: prep subdirs post

.PHONY: prep
prep: $(modulesymfile)
$(modulesymfile):
	@-if (($(modsym))); then \
	    cat $(KOBJ)/$(kernelsymfile) 2>/dev/null >./$(modulesymfile);\
	  fi;

.PHONY: subdirs $(SUBDIRS)
subdirs: $(SUBDIRS)
$(SUBDIRS):
	@if [ -n "$(verbose)" ]; then \
	   echo "#######################";\
	   printf "####  %-7s%6s####\n" $(@);\
	   echo "#######################";\
	 fi;
	@if (($(modsym))); then \
	   /bin/cp -f $(modulesymfile) $(@)/;\
	 fi;
	@drvdir=$(shell pwd)/$(@) $(MAKE) -C $(@);
	@if (($(modsym))); then \
	   /bin/cp -f $(@)/$(modulesymfile) .;\
	 fi;

.PHONY: install
install: default
	@-file=/etc/modprobe.d/libcxgb3.conf;\
	 lines=`grep -n "^install cxgb3 " $$file 2>/dev/null |\
	        sed 's/:.*//g' | sort -gr`;\
	 string="# Disabled by Chelsio Makefile on `date`";\
	 for i in $$lines; do \
	   sed -i "$$i"'s/^install cxgb3[[:space:]]/#install cxgb3 /' $$file;\
	   let i-=1;\
	   sed -i "$$i"'a'"$$string" $$file;\
	 done;
	@for dir in $(INSTALLDIRS); do \
	   drvdir=$(shell pwd)/$$dir $(MAKE) -C $$dir install ||\
		  exit 1;\
	 done;
	@-if (($(modsym))); then \
	   if [ -e $(modulesymfile) ]; then \
	     /bin/cp -f $(modulesymfile) $(KOBJ)/$(modulesymfile).Chelsio;\
	   fi;\
	 fi;
	-depmod

.PHONY: uninstall
uninstall:
	@-file=/etc/modprobe.d/libcxgb3.conf;\
	 string="# Disabled by Chelsio Makefile";\
	 lines=`grep -n "^$$string" $$file 2>/dev/null |\
	        sed 's/:.*//g' | sort -gr`;\
	 for i in $$lines; do \
	   sed -i "$$i"'d' $$file;\
	   sed -i "$$i"'s/^#//' $$file;\
	 done;
	@for dir in $(INSTALLDIRS); do \
	   drvdir=$(shell pwd)/$$dir $(MAKE) -C $$dir uninstall;\
	 done;
	-depmod

.PHONY: rpm
rpm: default
	 @package=$(pkgname)-$(pkgvers);\
	  /bin/mkdir -p $(rpmdir)/BUILD/$$package;\
	  /bin/mkdir -p $(rpmdir)/RPMS/$(target);\
	  rpmbuild -bb --define "_topdir $(rpmdir)" \
		       --define "srcdir $(srcdir)" \
		       --define "kversion $(kernelversion)" \
		       --define "version $(pkgvers)" \
		       --define "name $(pkgname)" \
		       --define "release $(rpmrelease)" \
		       --define "disable_offload $$(($(disable_offload)))" \
		       --define "disable_toecore $$(($(disable_toecore)))" \
		       --define "disable_bonding $$(($(disable_bonding)))" \
		       --target $(target) \
		      pkg.spec;\
	 /bin/cp -a \
	   $(rpmdir)/RPMS/$(target)/$$package-$(rpmrelease).$(target).rpm \
	   $(srcdir)/$$package-$(rpmrelease)-$(kernelversion).$(target).rpm;

.PHONY: clean
clean:
	@for dir in $(SUBDIRS); do \
	   drvdir=$(shell pwd)/$$dir $(MAKE) -C $$dir clean;\
	 done;
	-/bin/rm -f *.symvers eval.mak 2>/dev/null;

.PHONY: distclean
distclean: clean rpmclean
	-[ -n "$(rpmdir)" ] && /bin/rm -rf $(rpmdir) 2>/dev/null;
	-/bin/rm -f *.rpm 2>/dev/null;
	@-echo 'Removing t3_tom/module_support.c symlink'\
		$(call clean_symlinks,t3_tom,module_support.c)
	@-echo 'Removing toecore/module_support.c symlink'\
		$(call clean_symlinks,toecore,module_support.c)
	@-echo 'Removing bonding/*.[ch] symlinks'\
		$(call clean_symlinks,bonding)

.PHONY: rpmclean
rpmclean:
	@if [ -n "$(rpmdir)" ]; then \
	   /bin/rm -rf $(rpmdir);\
	 else \
	   exit 1;\
	 fi;

.PHONY: post
post:
	@if [ -n "$(post_msg)" ]; then \
	   echo -e "\nWARNING:\n $(post_msg)";\
	 fi;

.PHONY: help
help:
	@echo "Build Targets:";\
	 echo " nic               - Only build cxgb3 driver (no offload).";\
	 echo " toe               - Build all drivers. This is default.";\
	 echo " xen               - Build all drivers with xen specific change.";\
	 echo "                     Same as 'make'.";\
	 echo " rpm               - Generates a binary RPM. Can be used";\
	 echo "                     with other build targets and options.";\
	 echo "Other Targets:";\
	 echo " install           - Installs all compiled drivers.";\
	 echo " uninstall         - Uninstalls drivers.";\
	 echo " clean             - Removes all generated files.";\
	 echo " rpmclean          - Cleanup rpm directories.";\
	 echo " distclean         - Clean everything.";\
	 echo;\
	 echo "Build Options:";\
	 echo " bonding_version=<string> - Build the offload bonding driver against ";\
	 echo "                     the kernel version listed;"\
	 echo " disable_bonding=1 - Don't build the offload bonding driver.";\
	 echo " disable_offload=1 - Don't build any offload driver.";\
	 echo "                     Same as 'make nic'.";\
	 echo " disable_toecore=1 - Don't build the toecore driver.";\
	 echo "                     Useful if toecore is a kernel built-in.";\
	 echo " txzcopy=0         - Disable TX zero copy, on by default.";\
	 echo " KOBJ=<path>       - Kernel build (object) path.";\
	 echo " KSRC=<path>       - Kernel source path.";\
	 echo "                   - Note: When using KSRC or KOBJ, both must";\
	 echo "                           variables must be specified.";\
	 echo " KDIR=<path>       - Kernel build and source path. Shortcut for";\
	 echo "                     KOBJ=KSRC=<path>.";\
	 echo " DEBUG=1           - Enable debugging and tracing.";\
	 echo;\
	 echo "RPM Options:";\
	 echo " rpmrelease=<#>    - Change rpmrelease. Default is 0.";\
	 echo " pkgname=<string>  - Redefine package name.";\
	 echo " pkgvers=<string>  - Redefine package version.";\
	 echo;

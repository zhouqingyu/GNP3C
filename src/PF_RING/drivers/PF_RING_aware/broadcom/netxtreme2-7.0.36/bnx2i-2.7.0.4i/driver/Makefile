#!/usr/bin/make
# Makefile for building Linux Broadcom Gigabit L5 driver as a module.
# $id$
KVER=
ifeq ($(KVER),)
  KVER=$(shell uname -r)
endif

MMKVER := $(shell echo $(KVER) | sed -e 's/\([0-9]\.[0-9]\)\.[0-9]*[.|-].*/\1/')
FIKVER := $(shell echo $(KVER) | sed -e 's/[0-9]\.[0-9]\.\([0-9]*\)[.|-].*/\1/')

# PREFIX may be set by the RPM build to set the effective root.
PREFIX=
ifeq ($(shell ls /lib/modules/$(KVER)/build > /dev/null 2>&1 && echo build),)
# SuSE source RPMs
  _KVER=$(shell echo $(KVER) | cut -d "-" -f1,2)
  _KFLA=$(shell echo $(KVER) | cut -d "-" -f3)
  _ARCH=$(shell file -b /lib/modules/$(shell uname -r)/build | cut -d "/" -f5)
  ifeq ($(_ARCH),)
    _ARCH=$(shell uname -m)
  endif
  ifeq ($(shell ls /usr/src/linux-$(_KVER)-obj > /dev/null 2>&1 && echo linux),)
    LINUX=
  else
    LINUX=/usr/src/linux-$(_KVER)-obj/$(_ARCH)/$(_KFLA)
    LINUXSRC=/usr/src/linux-$(_KVER)
  endif
else
  LINUX=/lib/modules/$(KVER)/build
  ifeq ($(shell ls /lib/modules/$(KVER)/source > /dev/null 2>&1 && echo source),)
    LINUXSRC=$(LINUX)
  else
    LINUXSRC=/lib/modules/$(KVER)/source
  endif
endif

# Make sure only one bnx2? DKMS RPM is installed.
#ifneq ($(shell rpm -qa | grep -v "bnx2i-*" | grep "netxtreme2-.*dkms" | wc -l), 1)
    #$(error More than one netxtreme2 DKMS RPM installed!!!  Failing build.)
#endif

ifeq ($(BNX2_CNIC_INC),)
  # Obtain the current working directory.  $(PWD) doesn't work because this
  # makefile cannot override the $(PWD) definition of the parent makefile.
  BCMPWD = $(shell pwd)
  ifeq ($(shell test -e $(BCMPWD)/../../bnx2 > /dev/null 2>&1 || echo notfound),)
    BNX2_CNIC_INC := $(BCMPWD)/../../bnx2/src
  else
    $(error bnx2/cnic package not found. $(BCMPWD))
  endif
  export BNX2_CNIC_INC
endif

ifeq ($(BCMMODDIR),)
ifeq ($(shell ls /lib/modules/$(KVER)/updates > /dev/null 2>&1 && echo 1),1)
    BCMMODDIR=/lib/modules/$(KVER)/updates
  else
    ifeq ($(shell grep -q "search.*[[:space:]]updates" /etc/depmod.conf > /dev/null 2>&1 && echo 1),1)
      BCMMODDIR=/lib/modules/$(KVER)/updates
    else
      ifeq ($(shell grep -q "search.*[[:space:]]updates" /etc/depmod.d/* > /dev/null 2>&1 && echo 1),1)
        BCMMODDIR=/lib/modules/$(KVER)/updates
      else
        BCMMODDIR=/lib/modules/$(KVER)/kernel/drivers/scsi
      endif
    endif
  endif
endif

# iSCSI offload is only supported for RHELS5.4+, RHELS6.0+, SLES11sp1+,
# and 2.6 upstream kernels

# Check for the existence of version.h
ifneq ($(shell ls $(LINUXSRC)/include/linux/version.h > /dev/null 2>&1 && echo version),)
  ifneq ($(shell grep "RHEL" $(LINUXSRC)/include/linux/version.h > /dev/null 2>&1 && echo rhel),)
    MAJVER := $(shell grep "MAJOR" $(LINUXSRC)/include/linux/version.h | sed -e 's/.*MAJOR \([0-9]\)/\1/')
    MINVER := $(shell grep "MINOR" $(LINUXSRC)/include/linux/version.h | sed -e 's/.*MINOR \([0-9]\)/\1/')
  else
    # Can be upstream or SLES11 kernel
    ifeq ($(shell test -f /etc/SuSE-release > /dev/null 2>&1 || echo notfound),)
      VERSION := $(shell grep VERSION /etc/SuSE-release | sed -e 's/.*= //')
      PATCHLEVEL := $(shell grep PATCHLEVEL /etc/SuSE-release | sed -e 's/.*= //')
    else
      # Upstream kernel detected, allow compilation
      ifeq ($(shell [ "$(MMKVER)" = "2.6" -a $(FIKVER) -gt 30 ] || echo notfound),)
        BCM_ISCSI_BUILD=iscsibuild
        BCM_ISCSI_INSTALL=iscsiinstall
        BCM_ISCSI_CLEAN=iscsiclean
      else
        ifeq ($(shell [ "$(MMKVER)" = "3.0" ] || echo notfound),)
          BCM_ISCSI_BUILD=iscsibuild
          BCM_ISCSI_INSTALL=iscsiinstall
          BCM_ISCSI_CLEAN=iscsiclean
        endif
      endif
    endif
  endif
else
  #Only use the /etc/redhat or SuSE -release if the version.h doesn't exist
  ifeq ($(shell test -f /etc/redhat-release > /dev/null 2>&1 || echo notfound),)
    MAJVER := $(shell sed -e 's/.*release \([0-9]\).*/\1/' /etc/redhat-release)
    MINVER := $(shell sed -e 's/.*\.\([0-9]\)*.*/\1/' /etc/redhat-release)
  endif
  ifeq ($(shell test -f /etc/SuSE-release > /dev/null 2>&1 || echo notfound),)
    VERSION := $(shell grep VERSION /etc/SuSE-release | sed -e 's/.*= //')
    PATCHLEVEL := $(shell grep PATCHLEVEL /etc/SuSE-release | sed -e 's/.*= //')
  endif
endif

# Check for specific RHELS versions for iSCSI and dual iSCSI stack support
RHELS_DISTRO_VER = "0x0$(MAJVER)0$(MINVER)"
ifeq ($(shell [ "$(MAJVER)" = "5" ] || echo notfound),)
  ifeq ($(shell [ "$(MINVER)" -gt 3 ] || echo notfound),)
    BCM_ISCSI_BUILD=iscsibuild
    BCM_ISCSI_INSTALL=iscsiinstall
    BCM_ISCSI_CLEAN=iscsiclean
    BRCM_FLAGS += -D__RHELS_DISTRO_5__=$(RHELS_DISTRO_VER)
  endif
else
  ifeq ($(shell [ "$(MAJVER)" = "6" ] || echo notfound),)
    BCM_ISCSI_BUILD=iscsibuild
    BCM_ISCSI_INSTALL=iscsiinstall
    BCM_ISCSI_CLEAN=iscsiclean
    BRCM_FLAGS += -D__RHELS_DISTRO_6__=$(RHELS_DISTRO_VER)
  endif
endif

# Check for specific SLES versions for iSCSI support
SLES_DISTRO_VER = "0x$(VERSION)0$(PATCHLEVEL)"
ifeq ($(shell [ "$(VERSION)" = "11" ] || echo notfound),)
  ifeq ($(shell [ "$(PATCHLEVEL)" -gt 0 ] || echo notfound),)
    BCM_ISCSI_BUILD=iscsibuild
    BCM_ISCSI_INSTALL=iscsiinstall
    BCM_ISCSI_CLEAN=iscsiclean
    BRCM_FLAGS += -D__SLES_DISTRO__=$(SLES_DISTRO_VER)
  endif
endif

ifeq ($(shell grep scsi_get_resid $(LINUXSRC)/include/scsi/*.h > /dev/null 2>&1 && echo resid_defined),)
  BRCM_FLAGS += -D_DEFINE_SCSI_GET_RESID
endif

ifeq ($(shell grep scsi_set_resid $(LINUXSRC)/include/scsi/*.h > /dev/null 2>&1 && echo resid_defined),)
  BRCM_FLAGS += -D_DEFINE_SCSI_SET_RESID
endif

ifeq ($(shell awk '/(*create_session)/,/;/ {printf $$0; next}' $(LINUXSRC)/include/scsi/scsi_transport_iscsi.h | awk -F ',' '{print NF}'),6)
  BRCM_FLAGS += -D_CREATE_SESS_NEW_
endif

default: build 

# check if 2.6 kernel or 3.0 kernel

ifeq ($(shell [ "$(MMKVER)" = "2.6" ] || echo notfound),)
BCM_DRV = bnx2i.ko
else
ifeq ($(shell [ "$(MMKVER)" = "3.0" ] || echo notfound),)
BCM_DRV = bnx2i.ko
endif
endif

ifneq ($(BCM_DRV),)
ifneq ($(KERNELRELEASE),)
bnx2i-objs := bnx2i_iscsi.o bnx2i_hwi.o bnx2i_init.o bnx2i_sysfs.o
obj-m += bnx2i.o
EXTRA_CFLAGS += -I${BNX2_CNIC_INC} -D_SYSFS_INCL_ ${BRCM_FLAGS}
else # ($(KERNELRELEASE),)
iscsibuild:
	make -C $(LINUX) SUBDIRS=$(shell pwd) modules
endif

else # BCM_DRV

# 2.4 kernel not supported
$(error iSCSI Offload not supported on 2.4 kernel)

endif # BCM_DRV

iscsiinstall:
	make -C $(LINUX) SUBDIRS=$(shell pwd) modules
	mkdir -p $(PREFIX)/$(BCMMODDIR)
	install -m 444 $(BCM_DRV) $(PREFIX)/$(BCMMODDIR)
	@if [ "$(PREFIX)" = "" ]; then /sbin/depmod -a $(KVER);\
	else echo " *** Run '/sbin/depmod -a' to update the module database.";\
	fi

iscsiclean:
	rm -f bnx2i.o bnx2i.mod.[co] bnx2i_iscsi.o bnx2i_iscsi.mod.[co]
	rm -rf bnx2i_init.o bnx2i_init.mod.[co]
	rm -rf .bnx2i*cmd bnx2i.ko .tmp_versions
	rm -rf .*.swp *.symvers
	rm -rf bnx2i_hwi.o bnx2i_sysfs.o bnx2i_hwi.mod.[co] bnx2i_swi.mod.[co]

build:	$(BCM_ISCSI_BUILD)

install: $(BCM_ISCSI_INSTALL) 

.PHONEY: all clean install

clean: $(BCM_ISCSI_CLEAN)

cscope:
	find . -name "*.[ch]" > cscope.files
	cscope -bp3

tags:
	ctags -R

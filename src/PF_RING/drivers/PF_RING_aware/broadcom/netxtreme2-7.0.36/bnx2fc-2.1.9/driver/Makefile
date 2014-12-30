#!/usr/bin/make
# Makefile for building Linux Broadcom Gigabit L5 driver as a module.
# $id$
KVER=
ifeq ($(KVER),)
  KVER=$(shell uname -r)
endif

# PREFIX may be set by the RPM build to set the effective root.
PREFIX=

ifeq ($(FC2_INCLUDE),)
  # Obtain the current working directory.  $(PWD) doesn't work because this
  # makefile cannot override the $(PWD) definition of the parent makefile.
  BCMPWD = $(shell pwd)
  ifeq ($(shell test -e $(BCMPWD)/../../fclibs/include > /dev/null 2>&1 || echo notfound),)
    FC2_INCLUDE := $(BCMPWD)/../../fclibs/include
  else
      $(error fclibs package not found. $(BCMPWD))
  endif
  export FC2_INCLUDE
endif

ifeq ($(shell grep scsi_get_resid $(LINUXSRC)/include/scsi/*.h > /dev/null 2>&1 && echo resid_defined),)
  BRCM_FLAGS += -D_DEFINE_SCSI_GET_RESID
endif

ifeq ($(shell grep scsi_set_resid $(LINUXSRC)/include/scsi/*.h > /dev/null 2>&1 && echo resid_defined),)
  BRCM_FLAGS += -D_DEFINE_SCSI_SET_RESID
endif

# check if 2.4 kernel or 2.5+ kernel
BCM_KVER:=$(shell echo $(KVER) | cut -c1-3 | sed 's/2\.[56]/2\.6/')

ifeq ($(shell [ "$(BCM_KVER)" = "2.6" ] || [ "$(BCM_KVER)" = "3.0" ]),)
BCM_DRV = bnx2fc.ko
ARCH:=$(shell uname -m)


# Check distro/kernel compatibility
ifeq ($(INCDIR),)
    INCDIR:=$(CURDIR)
endif

include $(INCDIR)/version.mk
DISTRO_COMPATIBLE="no"

ifeq ($(DISTRO), "RHEL")
    ifeq ($(shell [ "$(MAJVER)" = "6" ] || echo notfound),)

        ifeq ($(shell [ "$(MINVER)" = "1" ] || echo notfound),)
            DISTRO_COMPATIBLE="yes"
        endif
        ifeq ($(shell [ "$(MINVER)" = "2" ] || echo notfound),)
            DISTRO_COMPATIBLE="yes"
            BNX2FC_SUP = -D__BNX2FC_RHEL62__
            export BNX2FC_SUP
        endif
    endif
endif

ifeq ($(DISTRO), "SLES")
    ifeq ($(shell [ "$(MAJVER)" = "11" ] || echo notfound),)
        ifeq ($(shell [ "$(MINVER)" = "1" ] || echo notfound),)
            DISTRO_COMPATIBLE="yes"

	    # In the future we might need to look at MINVER before setting this
            BNX2FC_SUP = -D__BNX2FC_SLES11SP1__ -I$(FC2_INCLUDE)
            export BNX2FC_SUP
        endif
        ifeq ($(shell [ "$(MINVER)" = "2" ] || echo notfound),)
            DISTRO_COMPATIBLE="yes"

	    # In the future we might need to look at MINVER before setting this
            BNX2FC_SUP = -D__BNX2FC_SLES11SP2__
            export BNX2FC_SUP
        endif
    endif
endif

# For upstream there is no distro info. So RHEL or SLES is not detected. Set it
# based on the environment variable.  Run "BNX2FC_KERNEL_OVERRIDE=1 make"
ifeq ($(shell [ "$(DISTRO_COMPATIBLE)" = "no" ] || echo notfound),)
    ifeq ($(shell [ "$(BNX2FC_KERNEL_OVERRIDE)" = "1" ] || echo notfound),)
        DISTRO_COMPATIBLE="yes"
    else
        $(warning "Cannot compile bnx2fc on $(DISTRO) $(KVER)")
    endif
endif

ifeq ($(DISTRO_COMPATIBLE)$(KERNEL_COMPATIBLE), "yes""yes")
    BCM_BNX2FC_PFC=bnx2fc_pfc
    BCM_BNX2FC_BUILD=bnx2fc_build
    BCM_BNX2FC_CLEAN=bnx2fc_clean
    BCM_BNX2FC_INSTALL=bnx2fc_install
endif

default: build

ifneq ($(KERNELRELEASE),)
bnx2fc-objs := bnx2fc_fcoe.o bnx2fc_hwi.o bnx2fc_io.o bnx2fc_tgt.o bnx2fc_els.o
obj-m += bnx2fc.o
EXTRA_CFLAGS += ${BRCM_FLAGS} ${BNX2FC_SUP}
else # ($(KERNELRELEASE),)
bnx2fc_build:
	make -C $(LINUX) SUBDIRS=$(shell pwd) modules INCDIR=$(INCDIR)
endif

else # ifeq ($(BCM_KVER),2.6)
  $(error bnx2fc is not supported on 2.4 kernel)
endif # ifeq ($(BCM_KVER),2.6)

bnx2fc_pfc:
	$(MAKE) PFC=1

bnx2fc_install:
	mkdir -p $(PREFIX)/lib/modules/$(KVER)/kernel/drivers/scsi;
	install -m 444 $(BCM_DRV) $(PREFIX)/lib/modules/$(KVER)/updates;
	@if [ "$(PREFIX)" = "" ]; then /sbin/depmod -a ;\
	else echo " *** Run '/sbin/depmod -a' to update the module database.";\
	fi

.PHONY: all clean install

bnx2fc_clean:
	rm -f bnx2fc.o bnx2fc.mod.[co] bnx2fc_fcoe.o bnx2fc_fcoe.mod.[co]
	rm -rf .*.swp
	rm -rf bnx2fc_hwi.o bnx2fc_hwi.mod.[co] 
	rm -rf bnx2fc_els.o bnx2fc_els.mod.[co] 
	rm -rf bnx2fc_tgt.o bnx2fc_tgt.mod.[co] 
	rm -rf bnx2fc_io.o bnx2fc_io.mod.[co] 
	rm -f *.ko .*.cmd

pfc: $(BCM_BNX2FC_PFC)
build: $(BCM_BNX2FC_BUILD)
clean: $(BCM_BNX2FC_CLEAN)
install: build $(BCM_BNX2FC_INSTALL)


cscope:
	find . -name "*.[ch]" > cscope.files
	cscope -bp3

tags:
	ctags -R

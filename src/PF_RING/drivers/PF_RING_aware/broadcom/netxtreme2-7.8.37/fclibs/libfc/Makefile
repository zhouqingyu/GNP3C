#!/usr/bin/make
# Makefile for building Broadcom libfc parallel stack for SLES11SP1
# $id$
KVER=
ifeq ($(KVER),)
  KVER=$(shell uname -r)
endif

ifeq ($(FC2_INCLUDE),)
  # Obtain the current working directory.  $(PWD) doesn't work because this
  # makefile cannot override the $(PWD) definition of the parent makefile.
  BCMPWD = $(shell pwd)
  ifeq ($(shell test -e $(BCMPWD)/../include > /dev/null 2>&1 || echo notfound),)
    FC2_INCLUDE := $(BCMPWD)/../include
  else
      $(error bnx2/cnic package not found. $(BCMPWD))
  endif
  export FC2_INCLUDE
endif

PREFIX=


# Check distro/kernel compatibility
ifeq ($(INCDIR),)
    INCDIR:=$(CURDIR)/../../bnx2fc/driver
endif

include $(INCDIR)/version.mk
DISTRO_COMPATIBLE="no"

ifeq ($(DISTRO), "RHEL")
    ifeq ($(shell [ "$(MAJVER)" = "6" ] || echo notfound),)
        ifeq ($(shell [ "$(MINVER)" = "0" ] || [ "$(MINVER)" = "1" ] || echo notfound),)
            DISTRO_COMPATIBLE="no"
        endif
    endif
endif

ifeq ($(DISTRO), "SLES")
    ifeq ($(shell [ "$(MAJVER)" = "11" ] || echo notfound),)
        ifeq ($(shell [ "$(MINVER)" = "1" ] || echo notfound),)
          DISTRO_COMPATIBLE="yes"
        endif
    endif
endif

ifeq ($(DISTRO_COMPATIBLE)$(KERNEL_COMPATIBLE), "yes""yes")
    BCM_LIBFC_BUILD=libfc_build
    BCM_LIBFC_CLEAN=libfc_clean
    BCM_LIBFC_INSTALL=libfc_install
endif

default: build


ifneq ($(KERNELRELEASE),)
libfc2-objs :=  fc_libfc.o fc_disc.o fc_exch.o fc_elsct.o fc_frame.o \
		fc_lport.o fc_rport.o fc_fcp.o fc_npiv.o
obj-m += libfc2.o
EXTRA_CFLAGS += -ffast-math -mhard-float -I${FC2_INCLUDE} 
#$(error EXTRA_CFLAGS is defined as ${EXTRA_CFLAGS})
else
libfc_build:
	make -C $(LINUX) SUBDIRS=$(shell pwd) modules INCDIR=$(INCDIR)
endif

libfc_install: default
	mkdir -p $(PREFIX)/lib/modules/$(KVER)/updates
	install -m 444 libfc2.ko $(PREFIX)/lib/modules/$(KVER)/updates
	@if [ "$(PREFIX)" = "" ]; then /sbin/depmod -a $(KVER);\
	else echo " *** Run '/sbin/depmod -a' to update the module database.";\
	fi

.PHONEY: all clean install

libfc_clean:
	rm -f *.o *.mod.[co] *.ko .*.cmd

build: $(BCM_LIBFC_BUILD)
clean: $(BCM_LIBFC_CLEAN)
install: build $(BCM_LIBFC_INSTALL)

cscope:
	find . -name "*.[ch]" > cscope.files
	cscope -bp3

tags:
	ctags -R

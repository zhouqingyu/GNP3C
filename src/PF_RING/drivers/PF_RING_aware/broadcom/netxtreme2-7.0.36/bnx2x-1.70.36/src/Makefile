#!/usr/bin/make
# Makefile for building Linux Broadcom 10-Gigabit ethernet driver as a module.

KVER =
ifeq ($(KVER),)
    KVER = $(shell uname -r)
endif

# PREFIX may be set by the RPM build to set the effective root.
PREFIX =
ifeq ($(shell ls /lib/modules/$(KVER)/build > /dev/null 2>&1 && echo build),)
# SuSE source RPMs
    _KVER=$(shell echo $(KVER) | cut -d "-" -f1,2)
    _KFLA=$(shell echo $(KVER) | cut -d "-" -f3)
    _ARCH=$(shell file -b /lib/modules/$(shell uname -r)/build | cut -d "/" -f5)
    ifeq ($(_ARCH),)
        _ARCH=$(shell uname -m)
    endif
    ifeq ($(shell ls /usr/src/linux-$(_KVER)-obj > /dev/null 2>&1 && echo linux),)
        KERNEL_DIR=
    else
        KERNEL_DIR=/usr/src/linux-$(_KVER)-obj/$(_ARCH)/$(_KFLA)
        LINUXSRC=/usr/src/linux-$(_KVER)
    endif
else
    BCMPROC := $(shell uname -m)
    BCMCFGS := /lib/modules/$(KVER)/build \
               /usr/src/kernels/$(KVER)-$(BCMPROC) \
               /usr/src/linux-$(shell echo $(KVER) | sed "s|\(.*\)-\([a-z]*\)|\1-obj/$(BCMPROC)/\2|") \
               /usr/src/linux

    # Delete any entries that do not exist.
    BCMTSTDIR = $(shell if ls $(DIR) > /dev/null 2>&1; then echo $(DIR); fi)
    BCMCFGS := $(foreach DIR, $(BCMCFGS), $(BCMTSTDIR))

    ifeq ($(BCMCFGS),)
            $(error Linux kernel config directory not found)
    else
            KERNEL_DIR := $(firstword $(BCMCFGS))
    endif
endif

# paths
ifeq ($(shell ls /lib/modules/$(KVER)/updates > /dev/null 2>&1 && echo 1),1)
    DRV_DIR = updates
else
    ifeq ($(shell grep -q "search.*[[:space:]]updates" /etc/depmod.conf > /dev/null 2>&1 && echo 1),1)
        DRV_DIR = updates
    else
        ifeq ($(shell grep -q "search.*[[:space:]]updates" /etc/depmod.d/* > /dev/null 2>&1 && echo 1),1)
            DRV_DIR = updates
        else
            DRV_DIR = kernel/drivers/net
        endif
    endif
endif

MAN_DIR = $(PREFIX)/usr/share/man/man4

IDLE_CHK_C = bnx2x_self_test.c
REG_DUMP_H = bnx2x_dump.h
REG_HSI_H = bnx2x_reg.h bnx2x_fw_defs.h bnx2x_hsi.h
CNIC_INC = ../../bnx2/src/cnic_if.h
INIT_OPS_H = bnx2x_init.h bnx2x_init_ops.h
SP_VERBS = bnx2x_sp.c bnx2x_sp.h

SOURCES_PF = bnx2x_main.c bnx2x_cmn.[ch] bnx2x_link.c bnx2x.h bnx2x_link.h bnx2x_compat.h $(INIT_OPS_H) bnx2x_fw_file_hdr.h bnx2x_dcb.[ch] $(SP_VERBS) bnx2x_stats.[ch] bnx2x_ethtool.c $(IDLE_CHK_C)
SOURCES_VF = bnx2v_main.c bnx2x_cmn.[ch]              bnx2x.h              bnx2x_compat.h $(INIT_OPS_H)                     bnx2x_dcb.[ch] bnx2x_stats.[ch]                     bnx2x_ethtool.c	$(IDLE_CHK_C)
INIT_VAL_C = bnx2x_init_values_e1.c bnx2x_init_values_e1h.c bnx2x_init_values_e2.c
MODULE_NAME = bnx2x
ifeq ($(IOV),1)
	EXTRA_CFLAGS += -DBNX2X_IOV
	SOURCES_PF += bnx2x_sriov.[ch] bnx2x_vfpf.[ch]
endif
ifeq ($(NPA),1)
	EXTRA_CFLAGS += -D__VMKNPA__
endif

ifeq ($(VF),1)
	MODULE_NAME = bnx2v
	EXTRA_CFLAGS += -DBNX2X_VF
endif

EXTRA_CFLAGS += -DDRV_MODULE_NAME=\"$(MODULE_NAME)\"

obj-m +=  $(MODULE_NAME).o
bnx2x-objs = bnx2x_main.o bnx2x_link.o bnx2x_cmn.o $(INIT_VAL_C:%.c=%.o) bnx2x_dcb.o bnx2x_sp.o bnx2x_stats.o bnx2x_ethtool.o bnx2x_self_test.o
bnx2v-objs = bnx2v_main.o bnx2x_cmn.o bnx2x_dcb.o bnx2x_stats.o bnx2x_ethtool.o
ifeq ($(IOV),1)
bnx2x-objs += bnx2x_sriov.o bnx2x_vfpf.o
endif

EXTRA_CFLAGS += -Werror
ifeq ($(NX2_BOOT_DISK),1)
	EXTRA_CFLAGS += -DBNX2X_DRIVER_DISK
endif

sles_distro := $(wildcard /etc/SuSE-release)
ifneq ($(sles_distro),)
SLES_DISTRO_VER_TMP = $(shell cat /etc/SuSE-release | tr -s '\n' ' ' | cut -d"=" -f2-3 | cut -d" "  -f2,5 | tr -s ' ' '0')
SLES_DISTRO_VER = "0x$(SLES_DISTRO_VER_TMP)"
EXTRA_CFLAGS += -DSLES_DISTRO=$(SLES_DISTRO_VER)
endif

ifeq ($(SOE),1)
EXTRA_CFLAGS += -DBNX2X_STOP_ON_ERROR
endif

# targets and rules
.PHONY: all modules_install docs_install clean install

all default: $(obj-m)

vf:
	$(MAKE) VF=1

iov:
	$(MAKE) IOV=1

soe:
	$(MAKE) SOE=1

fcoe_next:
	$(MAKE) OLD_FC=1

$(obj-m): $(SOURCES_PF) $(SOURCES_VF) $(INIT_VAL_C) $(REG_DUMP_H) $(REG_HSI_H) $(CNIC_INC)
	$(MAKE) -C $(KERNEL_DIR) M=`pwd` modules

modules_install: $(obj-m)
	make -C $(KERNEL_DIR) M=`pwd` INSTALL_MOD_PATH=$(PREFIX) INSTALL_MOD_DIR=$(DRV_DIR) modules_install
	@if [ "$(PREFIX)" = "" ] ;\
		then /sbin/depmod -a ;\
		else echo " *** Run '/sbin/depmod -a' to update the module database." ;\
	fi

docs_install:
	gzip -c bnx2x.4 > bnx2x.4.gz
	install -m 644 bnx2x.4.gz $(MAN_DIR)

clean:
	make -C $(KERNEL_DIR) M=`pwd` clean
	@rm -f *.fw *.ihex

install: modules_install docs_install

# generate the include files
-include Makefile.gen

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


DISTRO=
KERNEL_COMPATIBLE="no"
# Check for the existence of version.h
ifneq ($(shell ls $(LINUX)/include/linux/version.h > /dev/null 2>&1 && echo version),)
    KERNEL_VERSION := $(shell grep "LINUX_VERSION_CODE" $(LINUX)/include/linux/version.h | sed -e 's/.*LINUX_VERSION_CODE \([0-9]\)/\1/')

    # 2.6.32 is the earliest supported kernel
    ifeq ($(shell [ $(KERNEL_VERSION) -ge 132640 ] || echo notfound),)
        KERNEL_COMPATIBLE="yes"
    endif


    ifneq ($(shell grep "RHEL" $(LINUX)/include/linux/version.h > /dev/null 2>&1 && echo rhel),)
        MAJVER := $(shell grep "MAJOR" $(LINUX)/include/linux/version.h | sed -e 's/.*MAJOR \([0-9]\)/\1/')
        MINVER := $(shell grep "MINOR" $(LINUX)/include/linux/version.h | sed -e 's/.*MINOR \([0-9]\)/\1/')
        DISTRO="RHEL"
    else
        ifeq ($(shell test -f /etc/SuSE-release > /dev/null 2>&1 || echo notfound),)
          MAJVER := $(shell grep VERSION /etc/SuSE-release | sed -e 's/.*= //')
          MINVER := $(shell grep PATCHLEVEL /etc/SuSE-release | sed -e 's/.*= //')
          DISTRO="SLES"
        endif
    endif
else
    # We don't have version.h to verify. Assume compatible
    KERNEL_COMPATIBLE="yes"
    #Only use the /etc/redhat or SuSE -release if the version.h doesn't exist
    ifeq ($(shell test -f /etc/redhat-release > /dev/null 2>&1 || echo notfound),)
      MAJVER := $(shell sed -e 's/.*release \([0-9]\).*/\1/' /etc/redhat-release)
      MINVER := $(shell sed -e 's/.*\.\([0-9]\)*.*/\1/' /etc/redhat-release)
      DISTRO="RHEL"
    endif
    ifeq ($(shell test -f /etc/SuSE-release > /dev/null 2>&1 || echo notfound),)
      MAJVER := $(shell grep VERSION /etc/SuSE-release | sed -e 's/.*= //')
      MINVER := $(shell grep PATCHLEVEL /etc/SuSE-release | sed -e 's/.*= //')
      DISTRO="SLES"
    endif
endif



%{!?disable_offload:%define disable_offload 0}
%{!?disable_toecore:%define disable_toecore 0}
%{!?disable_bonding:%define disable_bonding 0}
%{!?release:%define release 0}
%{!?kversion:%define kversion %(uname -r)}

## Summary offload string define.
%if %{disable_offload}
%define offload ""
%else
%define offload "Offload "
%endif
Summary: Chelsio Terminator 3 %{offload}driver for Linux
Name:    %{name}
Version: %{version}
Release: %{release}
License: GPL
Group:   System Environment/Kernel
URL:     http://www.chelsio.com
Vendor:  Chelsio Communications, Inc.
Packager:Chelsio Communications, Inc. <http://www.chelsio.com>

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-%{kversion}-root
#BuildRequires: kernel-devel
ExclusiveArch: %{ix86} x86_64 ia64 ppc ppc64 powerpc
ExclusiveOS: linux

%if %{disable_offload}
%define conflict_name %{name}toe
%else
%define conflict_name %(echo %{name} | %{__sed} 's/toe//')
%endif
Provides: %{name}
Provides: %{name}-%{version}
Conflicts: %{conflict_name}

%define drvbase /lib/modules/%{kversion}/updates/kernel
%define fwdir /lib/firmware/cxgb3
%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt

%description
The Chelsio Terminator 3 Ethernet Adapter driver for Linux kernel (%{kversion}).

%prep
## cxgb3 driver
%{__mkdir} -p %{name}-%{version}/cxgb3/
%{__cp} -a %{srcdir}/cxgb3/cxgb3.ko %{name}-%{version}/cxgb3/
echo "%{drvbase}/drivers/net/cxgb3/cxgb3.ko" > %{rpmfiles}

## firmware
%{__mkdir} -p %{name}-%{version}/firmware/
%{__cp} -a %{srcdir}/firmware/*.bin %{name}-%{version}/firmware/
for file in $(/bin/ls %{_topdir}/BUILD/%{name}-%{version}/firmware/*.bin 2>/dev/null); do
  echo "%{fwdir}/$(basename $file)" >> %{rpmfiles}
done

## protosram
%{__mkdir} -p %{name}-%{version}/protosram/
%{__cp} -a %{srcdir}/protosram/*.bin %{name}-%{version}/protosram/
for file in $(/bin/ls %{_topdir}/BUILD/%{name}-%{version}/protosram/*.bin 2>/dev/null); do
  echo "%{fwdir}/$(basename $file)" >> %{rpmfiles}
done

## offload drivers
if ((!%{disable_offload})); then
  %{__mkdir} -p %{name}-%{version}/t3_tom/
  %{__cp} -a %{srcdir}/t3_tom/t3_tom.ko %{name}-%{version}/t3_tom/
  echo "%{drvbase}/drivers/net/offload/t3_tom/t3_tom.ko" >> %{rpmfiles}
  if ((!%{disable_toecore})); then
    %{__mkdir} -p %{name}-%{version}/toecore/
    %{__cp} -a %{srcdir}/toecore/toecore.ko %{name}-%{version}/toecore/
    echo "%{drvbase}/drivers/net/offload/toecore.ko" >> %{rpmfiles}
  fi
  if ((!%{disable_bonding})); then
    %{__mkdir} -p %{name}-%{version}/bonding/
    %{__cp} -a %{srcdir}/bonding/bonding.ko %{name}-%{version}/bonding/
    echo "%{drvbase}/drivers/net/bonding/bonding.ko" >> %{rpmfiles}
  fi
fi


%build
## Nothing to do here.

%pre

%post
## Workaround for auto-loading infiniband drivers.
file=/etc/modprobe.d/libcxgb3.conf
lines=`grep -n "^install cxgb3 " $file 2>/dev/null | sed 's/:.*//g' | sort -gr`
string="# Disabled by Chelsio Makefile on `date`"
for i in $lines; do
  sed -i "$i"'s/^install cxgb3\s/#install cxgb3 /' $file
  let i-=1
  sed -i "$i"'a'"$string" $file
done
## Generate new module dependencies.
depmod
exit 0

%postun
## Workaround for auto-loading infiniband drivers.
file=/etc/modprobe.d/libcxgb3.conf
string="# Disabled by Chelsio Makefile"
lines=`grep -n "^$string" $file 2>/dev/null | sed 's/:.*//g' | sort -gr`
for i in $lines; do
  sed -i "$i"'d' $file
  sed -i "$i"'s/^#//' $file
done
## Update module dependencies.
depmod
exit 0

%install
cd %{_topdir}/BUILD/%{name}-%{version}
%{__install} -D -v cxgb3/cxgb3.ko %{buildroot}/%{drvbase}/drivers/net/cxgb3/cxgb3.ko

for file in $(/bin/ls %{_topdir}/BUILD/%{name}-%{version}/firmware/*.bin 2>/dev/null); do
  %{__install} -D -v $file %{buildroot}/%{fwdir}/$(basename $file)
done
for file in $(/bin/ls %{_topdir}/BUILD/%{name}-%{version}/protosram/*.bin 2>/dev/null); do
  %{__install} -D -v $file %{buildroot}/%{fwdir}/$(basename $file)
done

if ((! %{disable_offload})); then
  %{__install} -D -v t3_tom/t3_tom.ko %{buildroot}/%{drvbase}/drivers/net/offload/t3_tom/t3_tom.ko
  if ((! %{disable_toecore})); then
    %{__install} -D -v toecore/toecore.ko %{buildroot}/%{drvbase}/drivers/net/offload/toecore.ko
  fi
  if ((! %{disable_bonding})); then
    %{__install} -D -v bonding/bonding.ko %{buildroot}/%{drvbase}/drivers/net/bonding/bonding.ko
  fi
fi

%files -f %{_builddir}/%{name}-%{version}/rpmfiles.txt
%defattr(744,root,root)

%clean
%{__rm} -rf %{buildroot}

%changelog

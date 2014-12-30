#!/bin/bash
#
# PERFTUNE.SH - A Linux performance tuning script for Chelsio 10Gb Ethernet
#               adapters and TOE (TCP Offload Engine). Supports all Chelsio
#               10Gb Ethernet adapters (T1, T2, and T3).
#
# Copyright (c) 2004-2006 Chelsio Communications. All rights reserved.
#
# Written by Scott Bardone <sbardone@chelsio.com>
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. This program may be distributed but used
# only with Chelsio Ethernet adapters.

# $Date: 2008-07-07 22:57:18 $ $RCSfile: perftune.sh,v $ $Revision: 1.43 $ 

# DEFAULT SETTINGS #############################################################
# Modify appropriately.                                                        #
# The number indicates the first CPU to use for assignment of the smp_affinity.#
# Each subsequent interfaces will set smp_affinity on the next physical CPU.   #
# New smp_affinity values will not take affect until the first interrupt!      #
cpu_affinity_index=0                                                           #
################################################################################

# SCRIPT SETTINGS ##############################################################
column_width=60                                                                #
use_colors=1                                                                   #
tune_sysctl_enable=1                                                           #
tune_pci_enable=1                                                              #
tune_tom_enable=1                                                              #
tune_iface_enable=1                                                            #
tune_cpumask_enable=1                                                          #
enable_amd_workaround=1                                                        #
enable_pci_latency=1                                                           #
enable_pci_burstsplit=0                                                        #
disable_irqbalance=1                                                           #
write_sysctls=0                                                                #
enable_ht_smp_affinity=1                                                       #
################################################################################

# TOM TUNEABLES ################################################################
# tom_max_tx_pages should be set to 8 if doing a single connection             #
# performance test. For multiconnection tests, use a lower value.              #
# This is only used on Terminator 2 cards. (default 2)                         #
tom_max_tx_pages=8                                                             #
# Terminator 2 tom_mss_size should be set to 12272.                            #
tom_mss_size[2]="12272"                                                        #
# Terminator 3 tom_mss_size should use the default, 1048576.                   #
tom_mss_size[3]=""                                                             #
                                                                               #
# Disable TCP timestamps for TOM.                                              #
tom_tcp_timestamps=0                                                           #
                                                                               #
# Terminator 3 specific options.                                               #
tom_delayed_ack=2                                                              #
tom_ddp=1                                                                      #
# Max number of work requests, default 15.                                     #
tom_max_wr=""                                                                  #
#                                                                              #
zcopy_tweak=32768                                                              #
                                                                               #
################################################################################

# PCI TUNEABLES ################################################################
# Register Addresses.                                                          #
PCIX_CMD_ADDR[2]=0x60                                                          #
PCIX_CMD_ADDR[3]=0x74                                                          #
PCIX_LAT_TMR_ADDR[2]=0x0c                                                      #
PCIX_LAT_TMR_ADDR[3]=0x0c                                                      #
PCIX_CFG_MODE_ADDR[2]=0xfc                                                     #
PCI_BAR_REG[3]=0x10                                                            #
PCIX_MODE_OFFSET[3]=0x8c                                                       #
PCIE_LINK_STAT[3]=0x68                                                         #
PCIE_LINK_CAP[3]=0x64                                                          #
                                                                               #
# PCI outstanding transaction and data burst length on most systems is         #
# default to 8 transactions, 2k bytes. AMD-8131 (rev 12) chipset has a         #
# bug and this should be set to 2 transactions 1k bytes, however this will     #
# totally kill performance. It is possible to run with the higher numbers,     #
# but we have seen the interface hang at times, depending on the traffic.      #
# load and the machine. AMD-8131 chipset rev 13 is supposed to be fixed.       #
# This has been taken care of by most BIOS vendors, but there still are        #
# a few that have not been updated.                                            #
SAFE_PCIX_SPLIT_TRAN=0x1 # 2 split transactions.                               #
SAFE_PCIX_BURST_SIZE=0x1 # 1024 byte burst size.                               # 
# The PERF_PCIX values may be overwritten by host-bridge negotatiation.        #
PERF_PCIX_SPLIT_TRAN=0x7 # 32 split transactions.                              #
PERF_PCIX_BURST_SIZE=0x3 # 4096 byte burst size.                               #
                                                                               #
# PCI Latency timer value should be set to 0xF8                                #
SAFE_PCI_LAT_TMR=0xf8                                                          #
PERF_PCI_LAT_TMR=0xf8                                                          #
################################################################################

# SYSCTL TUNABLES ##############################################################
# Linux core, ipv4, and tcp tuning paramters,                                  #
# Setting any of these values to "" will skip writing of the sysctl.           #
                                                                               #
core_rmem_max=16777216 # Increase maximum read socket buffer size.             #
core_wmem_max=16777216 # Increase maximum write socket buffer size.            #
tcp_timestamps=0       # Disable timestamps to increase throughput.            #
tcp_sack=""            # Disable SACK to increase throughput.                  #
tcp_low_latency=""                                                             #
tcp_adv_win_scale=""                                                           #
moderate_rcvbuf=""                                                             #
                                                                               #
# TCP read buffer (min/default/max), default 4096 87380 174760.                #
ipv4_tcp_rmem="4096 262144 16777216" # overrides net.core.rmem_default.        #
# TCP write buffer (min/default/max), default 4096 16384 131072.               #
ipv4_tcp_wmem="4096 262144 16777216" # overrides net.core.wmem_default.        #
                                                                               #
# TCP memory allocation (min/pressure/max).                                    #
# default values are calculated by the kernel at boot time and depend          #
# on the amount of physical memory.                                            #
ipv4_tcp_mem=""                                                                #
                                                                               #
# max length of iovec or ancilliary data.                                      #
optmem_max=524288     # default 20480.                                         #
                                                                               #
# log length of network packets. kernel will drop unprocessed packets          #
# beyond this. simple algorithm for throughput:                                #
# <backlog> * 100(HZ) * <avg bytes/packet> = throughput bytes/second.          #
netdev_max_backlog=200000 # log length of network packets.                     #
                                                                               #
# Allows control over what percentage of the congestion window can be          #
# consumed by a single TSO frame. Default is 3 on older kernels, 8 on new.     #
tso_win_divisor=""                                                             #
                                                                               #
# TOE SYSCTLS TUNEABLES ########################################################
                                                                               #
################################################################################
# sysctl config file                                                           #
sysctl_conf_file="/etc/sysctl.conf"                                            #
# sysctl_data array, need to include the sysctl name and the data variable.    #
# Comma delimited.                                                             #
sysctl_data=(                                                                  #
    "net.core.wmem_max,$core_wmem_max"                                         #
    "net.core.rmem_max,$core_rmem_max"                                         #
    "net.ipv4.tcp_timestamps,$tcp_timestamps"                                  #
    "net.ipv4.tcp_sack,$tcp_sack"                                              #
    "net.ipv4.tcp_low_latency,$tcp_low_latency"                                #
    "net.ipv4.tcp_adv_win_scale,$tcp_adv_win_scale"                            #
    "net.ipv4.tcp_moderate_rcvbuf,$moderate_rcvbuf"                            #
    "net.ipv4.tcp_rmem,$ipv4_tcp_rmem"                                         #
    "net.ipv4.tcp_wmem,$ipv4_tcp_wmem"                                         #
    "net.ipv4.tcp_mem,$ipv4_tcp_mem"                                           #
    "net.core.optmem_max,$optmem_max"                                          #
    "net.core.netdev_max_backlog,$netdev_max_backlog"                          #
    "net.ipv4.tcp_tso_win_divisor,$tso_win_divisor"                            #
)                                                                              #
################################################################################

# DO NOT MODIFY BEYOND THIS POINT! #############################################
self='perftune.sh'                                                             #
mmapr32cksum="1466576699 5134"                                                 #
mmapr64cksum="911177960 5559"                                                  #
mmapr32md5="40d20ce1a3f9dd619affe4437d09dc5e"                                  #
mmapr64md5="61a5195259e8b8725c54bb118c6eb852"                                  #
SELFCKSUM="923829129 57779"                                                    #
REVISION="$Revision: 1.43 $"                                                   #
HARDSTART=$LINENO                                                              #
# FILE CHECKSUM STARTS AT THIS LINE ############################################
CHELSIO_PCI_VID='1425'                                                         #
AMD_PCI_VID='1022'                                                             #
AMD_8131_DEVID='7450'                                                          #
AMD_8131_BUG_REV=18     # 0x12                                                 #
T3_LLD_MODULE='cxgb3'                                                          #
T3_TOE_MODULE='toecore'                                                        #
T3_TOM_MODULE='t3_tom'                                                         #
################################################################################

# FUNCTIONS. ###################################################################

# function _set_color(), next print will be in color.
# _set_color pass|fail|warn|norm
_set_color() {
  if (( $use_colors )); then
    pass="echo -en \\033[1;32m"
    fail="echo -en \\033[1;31m"
    warn="echo -en \\033[1;33m"
    norm="echo -en \\033[0;39m"
    eval \$$1
  fi
}

# function _set_column(), column width for print status.
# Uses globally defined variable 'column'.
# _set_column <number of columns>
_set_column() {
  [ -n "$column_width" ] && echo -en "\\033[${column_width}G"
}

# function _print_stat(), call to print the status.
# _print_stat "<message>"
_print_stat() {
  _set_color norm
  echo -n "[ "
  _set_color $1
  echo -n $2
  _set_color norm
  echo " ]"
}

# function not(). negate value for double parentheses testing.
# (( $(not <value>) ))
not() {
  if [ -n "$1" ] && (( $1 )); then
    echo 0
  else
    echo 1
  fi
}

# function dbg().
# dbg <var> | @<var> | *<var>[index]
dbg() {
  : # stub
}

# function dbg_msg().
# dbg_msg "<message>"
dbg_msg() {
  : #stub
}

# function Print(), prints a message.
# Print "<message>"
Print() {
  [ -n "$1" ] && prev_print="$1"
  (( $quiet )) && return
  (( $silent )) && return
  [ -n "$1" ] && echo -en " > $1"
}

# function Info(), prints an info message.
# Info "<message>"
Info() {
  (( $quiet )) && return
  (( $silent )) && return
  [ -n "$1" ] && echo -e " [ $1 ]"
}

# function Pass(), prints pass status.
# Pass
Pass() {
  [ -n "$1" ] && prev_print=$1
  (( $quiet )) && return
  (( $silent )) && return
  [ -n "$1" ] && echo -n " > $1"
  _set_column
  _print_stat pass PASS
}

# function Fail(), prints fail status.
# Fail
Fail() {
  local out=$1
  (( $silent )) && prev_print=$out && return
  if (( $quiet )); then
    [ -z "$out" ] && [ -n "$prev_print" ] && out=$prev_print
  fi
  [ -n "$out" ] && echo -n " * $out"
  _set_column
  _print_stat fail FAIL
  prev_print=$out
}

# function Warn(), prints (optional) message and warn status.
# Warn "<message>"
Warn() {
  local out=$1
  (( $silent )) && prev_print=$out && return
  if (( $quiet )); then
    [ -z "$out" ] && [ -n "$prev_print" ] && out=$prev_print
  fi
  [ -n "$out" ] && echo -n " > $out"
  _set_column
  _print_stat warn WARN
  prev_print=$out
}

Say() {
  [ -n "$1" ] && prev_print="$1"
  (( $quiet )) && return
  (( $silent )) && return
  [ -n "$1" ] && echo -en "$1"
}

# function restore_if_state().
# restore_if_state <list>
restore_if_state() {
  unset IFS
  for interface in $@; do
    Print "Restore interface $interface state."
    $ifconfig $interface down >/dev/null &&
      Pass || Fail
  done
}

# function Exit(), prints (optional) exit message and runs restore_if_state,
# if needed, then exits. Uses local array 'term_temp_ifup'.
# Exit "<message>"
Exit() {
  [ -n "$1" ] && echo -e "$1" >&2
  [ ${#term_temp_ifup[@]} -gt 0 ] && restore_if_state ${term_temp_ifup[@]}
  exit 1
}

# function Convert_base(), converts data from hex to bin or bin to hex.
# Convert_base [hex2bin|bin2hex] <data>
# returns <converted data>
Convert_base() {
  local bintbl
  local indata
  local indata_len
  local cntr
  local outdata
  local chunk
  bintbl=( 0000 0001 0010 0011 \
           0100 0101 0110 0111 \
           1000 1001 1010 1011 \
           1100 1101 1110 1111 )
  indata=$(echo $2 | tr '[a-z]' '[A-z]')
  indata=${indata#0X}
  indata=$(echo $indata | sed 's/^0*//')
  [ ${#indata} -lt 1 ] && indata=0
  indata_len=${#indata}
  cntr=0
  unset outdata
  while [ $cntr -lt $indata_len ]; do
    if [ "$1" == "bin2hex" ]; then
      chunk=${indata:$cntr:4}
      outdata="$outdata`printf %x $((2#$chunk))`"
      let "cntr += 4"
    elif [ "$1" == "hex2bin" ]; then
      chunk=$(printf %d "0x${indata:$cntr:1}")
      outdata="$outdata${bintbl[$chunk]}"
      (( cntr++ ))
    fi
  done
  echo $outdata
}

# function Get_bits(), returns bit or bit-range from supplied bitstream.
# Get_bits <bitstream> <upper:lower>|<single bit>
# returns <bits> 
Get_bits() {
  local data=$1
  local start_bit=$(( ${#data} - 1 - ${2%%:*} ))
  local stop_bit=$(( ${#data} - 1 - ${2##*:} ))
  local length=$(( stop_bit - start_bit + 1 ))
  echo ${data:$start_bit:$length}
}

# function Change_bits(), modifies certain bits of a bitstream with hex data.
# Change_bits <bitstream> <upper:lower>|<single bit> <hex data>
# returns <bitstream> 
Change_bits() {
  local data=$1
  local start_bit=$(( ${#data} - 1 - ${2%%:*} ))
  local stop_bit=$(( ${#data} - 1 - ${2##*:} ))
  local bit_length=$(( stop_bit - start_bit + 1 ))
  local stream_hi=${data:0:$start_bit}
  local stream_lo=${data:$(( stop_bit + 1 )):$(( ${#data} - 1 ))}
  local new_bits=$(Convert_base hex2bin $3)
  new_bits=$(printf "%"$bit_length"s" \
    $(echo $new_bits | sed 's/^0*//') | sed 's/ /0/g')
  echo "$stream_hi$new_bits$stream_lo"
}

# function Check_util(), verifies the specified utility exists, returns the
# path/utility name if the utility is found, if not, returns error.
# var=$(Check_util <utility> [<path>])
Check_util() {
  local util=$1
  local util_path
  shift
  util_path=$(builtin type -P $util 2>/dev/null)
  if [ -z "$util_path" ]; then
    while [ ${#@} -gt 0 ]; do
      [ -e "$1" ] && util_path=$1 && break
      shift
    done
  fi
  [ -z "$util_path" ] && return 1
  echo $util_path
  return 0
}

hexdump2bin() {
	perl -e 'while ($stream=<>) { chomp $stream; print STDOUT (pack("H" . length($stream), $stream)); }'
}
bin2hexdump() {
	perl -e 'while ($stream=<>) { print STDOUT (unpack("H*", $stream)); }'
}

Extract_mmap() {
  # mmapr utility is not present on FC5 systems and would assume RHEL5 as well.
  # Included my own mmapr (data at end of script).
  local arch
  local hex_data
  local checksum
  local cksum_util

  Info "The mmapr utility is missing from this system."

  # Get tmp file location.
  if [ -e "/var/tmp" ]; then
    temp_dir="/var/tmp"
  else
    if [ ! -e "$PWD/.perftune" ]; then
      mkdir -p "$PWD/.perftune" || return 1
    fi
    if [ -d "$PWD/.perftune" ]; then
      temp_dir="$PWD/.perftune"
    else
      return 1
    fi
  fi

  # Get architecture.
  arch=$($uname -m | sed 's/i.86/x86/')

  case $arch in
    x86_64 ) arch=64;;
    x86 )    arch=32;;
    * )      arch=0
             dbg_msg "Unsupported architecture"
             return 1;;
  esac

  Print "Extract internal utility to $temp_dir/mmapr$arch."

  if [ -n "$md5sum" ]; then
    cksum_util="$md5sum | awk '{print \$1}'"
    cksum_value=$(eval echo \$mmapr$arch"md5")
  elif [ -n "$cksum" ]; then
    cksum_util="$cksum"
    cksum_value=$(eval echo \$mmapr$arch"cksum")
  else
    return 1
  fi
  checksum=$(cat $0 |\
     sed -n '/: <<MMAPR'$arch'/,/MMAPR'$arch'/{/: <<MMAPR'$arch'/b;
      /MMAPR'$arch'/b;p}' |\
      eval $cksum_util)
  if [ "$checksum" != "$cksum_value" ]; then
    return 1
  fi

  # Generate the binary file.
  cat $0 |\
  sed -n '/: <<MMAPR'$arch'/,/MMAPR'$arch'/{/: <<MMAPR'$arch'/b;
   /MMAPR'$arch'/b;p}' |\
   hexdump2bin > $temp_dir/mmapr$arch.gz ||
    return 1

  # Extract the file.
  $gzip -d -f "$temp_dir/mmapr$arch.gz" || return 1

  # Change file permissions.
  chmod +x "$temp_dir/mmapr$arch" || return 1

  # Set mmapr_internal command.
  mmapr_internal="$temp_dir/mmapr$arch"

  Pass
  return 0
}

memmapread() {
  local address=$1
  if [ -n "$mmapr" ]; then
    echo $($mmapr /dev/mem $address 1 2>/dev/null | bin2hexdump)
  elif [ -n "$mmapr_internal" ]; then
    echo $($mmapr_internal $address 1 2>/dev/null | bin2hexdump)
  else
    echo
  fi
}

ShowVersion() {
  echo -n "$self version"
  echo $REVISION | sed 's/[:$]//g'
  exit 0
}

Help() {
  echo "usage: $self [options]|-h"
  echo "Options:"
  echo " -A         Disable AMD-8131 Data Corruption bug workaround for PCI-X."
  echo "            WARNING: Applying the workaround will have a severe impact on"
  echo "            the performance! Set this option to disable the workaround, but"
  echo "            be warned, the bus could hang if the bug is encountered. See"
  echo "            AMD-8131 HT PCI-X Tunnel Revision Guide 26310, section 56, for"
  echo "            info on the \"133-MHz Mode Split Completion Data Corruption\" bug."
  echo " -b         Force PCI split transaction/burst tuning parameters."
  echo "            WARNING: The PCI bridge will auto-negotiate to the best supported"
  echo "            split/burst parameters. Forcing parameters which have not been"
  echo "            negotiated by the bridge may not always provide optimal performance."
  echo "            which would be revealed when setting burst size greater than 512."
  echo " -C         Disable binding IRQs to CPUs (smp_affinity mask)."
  echo " -c <CPU>   Set the base CPU for applying the smp_affinity mask."
  echo "            The affinity_mask will be applied to each interrupt of each"
  echo "            interface in a round-robin order, starting at the first interface"
  echo "            encountered. The first interface will be set to the base CPU, the"
  echo "            second interface will be set to the next CPU (<value> * 2), etc."
  echo " -d <value> Enable or disable DDP on Terminator 3 devices. Enable=1, Disable=0."
  echo " -D         Do not disable IRQ balance daemon." 
  echo " -H         Do not set IRQ smp_affinity to Hyperthreaded (SMT) CPUs."
  echo " -I         Do not temporarily enable interfaces for tuning."
  echo " -L         Disable PCI latency tuning parameters."
  echo " -m <value> Set the TOM mss_size to <value>."
  echo "            WARNING: This is not the MSS for the network interface!"
  echo " -n         Auto load NIC driver module."
  echo "            The LLD (cxgb3) driver module will be automatically loaded. Only"
  echo "            applies to Terminator3 devices."
  echo " -o         Auto load NIC and TOE driver modules."
  echo "            The LLD (cxgb3), TOE (toecore), and TOM (t3_tom) driver modules"
  echo "            will automatically be loaded. Do not use this if any additional"
  echo "            tuning parameters are required to be set prior to enabling offload."
  echo "            Once offload is enabled, some options cannot be modified."
  echo "            Only applies to Terminator3 devices."
  echo " -P         Disable PCI tuning parameters."
  echo " -q         Be somewhat quiet. Use a second time to be silent."
  echo " -S         Disable sysctl tuning parameters."
  echo " -s         Only run sysctl tuning parameters, do not perform other tuning."
  echo " -T         Disable TOM tuning parameters."
  echo " -t <value> Set the TOM max_tx_pages to <value>."
  echo "            WARNING: Only for Terminator2 devices."
  echo " -v         Show version."
  echo " -w <value> Set the TOM max_wr to <value>."
  echo " -W         Write sysctls to /etc/sysctl.conf file. This does not write any"
  echo "            TOE/TOM specific sysctls to the file."
  echo " -x         Do not use terminal colors."
  echo " -Z         Enable debugging."
  echo " -g         Generate self checksum."
  echo " -h         Help."
  Exit
}

[ -e "functions.sh" ] && source "functions.sh"
################################################################################

# This script should only be run by root.
if [ $UID -ne 0 ]; then
  Exit "Must be root user (UID 0) to run this script!"
fi

# Command-line options.
Options="AbCc:Dd:HILm:noPqSsTt:vWw:xZgh"

# Get options.
while getopts $Options option; do
  case $option in
    A ) enable_amd_workaround=0;; # Disable AMD-8131 bug workaround.
    b ) enable_pci_burstsplit=1;; # Enable PCI burst/split trans tuning.
    C ) tune_cpumask_enable=0;;   # Disable CPU mask.
    c ) cpu_affinity_index=$OPTARG;;
    d ) ddp_state=$OPTARG;;       # Set DDP.
    D ) disable_irqbalance=0;;
    H ) enable_ht_smp_affinity=0;;# Don't set smp_affinity on Hyperthread CPUs.
    I ) tune_iface_enable=0;;     # Do not temporarily enable interfaces.
    L ) enable_pci_latency=0;;    # Disable PCI latency tuning.
    m ) tom_mss_size=$OPTARG;;
    n ) autoload_nic=1;;          # Autoload NIC (T3) driver.
    o ) autoload_nic=1            # Autoload both NIC and TOE (T3) drivers.
        autoload_toe=1;;
    P ) tune_pci_enable=0;;       # Disable PCI tuning.
    q ) (( quiet++ ));;           # Be quiet.
    S ) tune_sysctl_enable=0;;    # Disable sysctl tuning.
    s ) tune_sysctl_only=1        # Only perform sysctls, disable others.
        disable_irqbalance=0
        tune_tom_enable=0
        tune_iface_enable=0;;
    T ) tune_tom_enable=0;;       # Disable TOM tuning.
    t ) tom_max_tx_pages=$OPTARG;;
    v ) ShowVersion;;
    W ) write_sysctls=1;;         # Write sysctls to /etc/sysctl.conf file.
    w ) tom_max_wr=$OPTARG;;
    x ) use_colors=0;;            # Do not use terminal colors.
    Z ) debug=1;;
    g ) generate_self_checksum=1;;
    * ) Help;;
  esac
done

if (( $tune_sysctl_only )); then
  tune_pci_enable=0               # Disable PCI tuning.
  tune_tom_enable=0               # Disable TOM tuning.
  tune_cpumask_enable=0           # Disable CPU mask.
  tune_iface_enable=0             # Don't enable interfaces.
fi

# Option error checking.
# tom_max_tx_pages can only be a decimal value.
tom_max_tx_pages=${tom_max_tx_pages//*[^0-9]*/X}
# cpu_affinity_index input should be an integer
# no larger than the number of CPUs on the system.
cpu_affinity_index=${cpu_affinity_index//*[^0-9]*/X}
# tom_mss_size can only be decimal values.
tom_mss_size=${tom_mss_size//*[^0-9]*/X}
# ddp_state can only be on or off (1 or 0).
ddp_state=${ddp_state//*[^0-1]*/X}
tom_max_tx_pages=${tom_max_tx_pages//*[^0-9]*/X}
if [ -n "$tom_mss_size" ]; then
  # This variable will later be copied to the correct element in the
  # array after determining the board type.
  if [ "$tom_mss_size" == "X" ]; then
    echo "-m: tom_mss_size must be an integer value." >&2
    (( args_failed++ ))
  fi
  if [ $tom_mss_size -eq 0 ]; then
    echo "-m: tom_mss_size must not be 0 value." >&2
  fi
fi
if [ -n "$tom_max_tx_pages" ]; then
  if [ "$tom_max_tx_pages" == "X" ] || 
     (( tom_max_tx_pages < 2 | tom_max_tx_pages > 16 )); then
    echo "-t: tom_max_tx_pages must be an integer between 2 and 16." >&2
    (( args_failed++ ))
  fi
fi
if [ -n "$tom_max_wr" ]; then
  if [ "$tom_max_wr" == "X" ] ||
     (( tom_max_wr < 1 | tom_max_wr > 16 )); then
    echo "-w: tom_max_wr must be an integer between 1 and 16." >&2
    (( args_failed++ ))
  fi
fi
if [ -n "$cpu_affinity_index" ]; then
  if [ "$cpu_affinity_index" == "X" ]; then
    echo "-c: cpu_affinity_index must be an integer." >&2
    (( args_failed++ ))
  fi
fi
if [ -n "$ddp_state" ]; then
  if [ "$ddp_state" == "X" ]; then
    echo "-d: ddp must be 1 or 0 (enabled or disabled)." >&2
    (( args_failed++ ))
  fi
fi
(( $args_failed )) && Exit "ERROR: Failed arguments."

(( $quiet )) && [ $quiet -gt 1 ] && silent=1

# Trap INT signal.
trap 'Exit "Exit on signal INT."' TERM INT

# Make sure the required utilities are available.
lspci=$(Check_util lspi /sbin/lspci /usr/bin/lspci) ||
  { Fail "Can't locate lspci utility!"; (( fail_util++ )); }
setpci=$(Check_util setpci /sbin/setpci /usr/bin/setpci) ||
  { Fail "Can't locate setpci utility!"; (( fail_util++ )); }
uname=$(Check_util uname /bin/uname) ||
  { Fail "Can't locate uname utility!"; (( fail_util++ )); }
sysctl=$(Check_util sysctl /sbin/sysctl) ||
  { Fail "Can't locate sysctl utility!"; (( fail_util++ )); }
ifconfig=$(Check_util ifconfig /sbin/ifconfig) ||
  { Fail "Can't locate ifconfig utility!"; (( fail_util++ )); }
cp=$(Check_util cp /bin/cp) ||
  { Fail "Can't locate cp utility!"; (( fail_util++ )); }
mv=$(Check_util mv /bin/mv) ||
  { Fail "Can't locate mv utility!"; (( fail_util++ )); }
grep=$(Check_util grep /bin/grep /usr/bin/grep) ||
  { Fail "Can't locate grep utility!"; (( fail_util++ )); }
cat=$(Check_util cat /bin/cat) ||
  { Fail "Can't locate cat utility!"; (( fail_util++ )); }
cksum=$(Check_util cksum /usr/bin/cksum) ||
  { Warn "Can't locate cksum utility!"; }
gzip=$(Check_util gzip /bin/gzip) ||
  { Warn "Can't locate gzip utility!"; }
md5sum=$(Check_util md5sum /usr/bin/md5sum) ||
  { Warn "Can't locate md5sum utility!"; }
chkconfig=$(Check_util chkconfig /sbin/chkconfig) ||
  { Warn "Can't locate chkconfig utility!"; }
modprobe=$(Check_util modprobe /sbin/modprobe) ||
  { Print "Can't locate modprobe utility!"; 
    (( $autoload_nic )) && { Fail; (( fail_util++ )); } \
    || Warn; }
lsmod=$(Check_util lsmod /sbin/lsmod) ||
  { Print "Can't locate lsmod utility!"; 
    (( $autoload_nic )) && { Fail; (( fail_util++ )); } \
    || Warn; }
if (( $fail_util )); then
  Exit "Cannot proceed with missing system utilities."
fi

if (( $(not tune_sysctl_only) )); then
  mmapr=$(Check_util mmapr /usr/X11R6/bin/mmapr) ||
   { Extract_mmap || {
    tune_pci_enable=0;
    tune_iface_enable=0;
    Fail "Problem using memory map utility."; };
   }
fi

# Perform self check.
if (( $generate_self_checksum )); then
  echo $(tail -n +$HARDSTART $0 | $cksum)
  exit 0
fi
checksum=$(tail -n +$HARDSTART $0 | $cksum)
if [ "$checksum" != "$SELFCKSUM" ]; then
  Warn "This script has been modified from the original!"
fi

# Set system variables.
[ -d '/proc' ] || Exit "ERROR: No /proc filesystem found!"
term_if_count=0
smp_kernel=$($uname -v | $grep SMP)
num_cpus=$(cat /proc/cpuinfo | $grep -c "^processor")
[ -z "$tom_tcp_timestamps" ] && tom_tcp_timestamps=$tcp_timestamps
[ -n "$ddp_state" ] && tom_ddp=$ddp_state

# Define the name of the userspace IRQ balance daemon.
# This name is different on various distributions.
daemon_check=/etc/init.d/irq*
for irqbalance in $daemon_check; do
  echo $irqbalance | $grep "irq" | $grep "balance" >/dev/null && break;
done

if $irqbalance status 1>/dev/null 2>&1; then
  if (( $disable_irqbalance )); then
    Print "Disabling IRQ balance daemon."
    $irqbalance stop 1>/dev/null 2>&1 &&
    Pass || { Fail; }
  else
    Warn "IRQ Balance daemon is running."
  fi
else
  Print "IRQ Balance daemon is not running." && Pass
fi

# If using a kernel which exports the thread_siblings to sysfs,
# I can determine which CPUs are Hyperthreaded (SMT) and not
# bind those to an interrupt vector, otherwise, I need to assume
# that all CPUs are "real".
[ -e '/sys/devices/system/cpu/cpu0/topology/thread_siblings' ] &&
 (( thread_sib++ ))

 # Disable setting SMT smp_affinity if commanded to do so.
(( $(not $enable_ht_smp_affinity) )) && thread_sib=0

# Get the number of processors.
if [ -n "$smp_kernel" ] && (( $thread_sib )); then

  # Populate the sibling map for each CPU.
  for ((i=0; i < $num_cpus; i++)); do
    sib_map[$i]="$(cat /sys/devices/system/cpu/cpu$i/topology/thread_siblings)"
  done

  for ((i=0; i < $num_cpus; i++)); do
    for ((j=0; j < $num_cpus; j++)); do
      # Skip same CPUs.
      if [ $i -ne $j ] && (( $(not ${ht_cpu[$i]}) )); then
        # Hyperthreaded CPUs have the same thread_sibling string.
        if [ "${sib_map[$i]}" == "${sib_map[$j]}" ]; then
          ht_cpu[$j]=1
          break
        fi
      fi
    done
  done
  # Setup the affinity mask.
  for ((i=0; i < $num_cpus; i++)); do
    if (( $(not ${ht_cpu[$i]}) )); then
      affinity_mask[${#affinity_mask[@]}]=$(printf "%x" $(echo $(( 2 ** $i ))))
      phys_cpus[${#phys_cpus[@]}]=$i
      (( num_phys_cpus++ ))
    fi
  done

elif [ -n "$smp_kernel" ]; then
  # All CPUs will be treated as real.
  for ((i=0; i < $num_cpus; i++)); do
    affinity_mask[${#affinity_mask[@]}]=$(printf "%x" $(echo $(( 2 ** $i ))))
    phys_cpus[${#phys_cpus[@]}]=$i
    (( num_phys_cpus++ ))
  done

else
  # This is a single CPU, affinity does not apply.
  num_phys_cpus=1
fi

if [ $cpu_affinity_index -gt $(( num_phys_cpus - 1 )) ]; then
  Warn "Invalid CPU index $cpu_affinity_index, using 0 instead."
  cpu_affinity_index=0
fi

# Autoload drivers before tuning.
if (( $autoload_nic )); then
  # Check if the LLD module is loaded.
  if $lsmod | $grep "$T3_LLD_MODULE " 1>/dev/null 2>&1; then
    Info "Terminator 3 LLD ($T3_LLD_MODULE) already loaded."
  else
    # Check if the LLD module is installed.
    if $modprobe -n $T3_LLD_MODULE 1>/dev/null 2>&1; then
      # Try to load the module since it's installed.
      if $modprobe $T3_LLD_MODULE 1>/dev/null 2>&1; then
        Pass "Loaded Terminator 3 LLD ($T3_LLD_MODULE)."
      else
        Fail "Failed to load Terminator 3 LLD ($T3_LLD_MODULE)."
      fi
    else
      Warn "Terminator 3 LLD ($T3_LLD_MODULE) not installed."
      (( driver_not_installed++ ))
    fi
  fi
fi
if (( $autoload_toe )); then
  # Check if the TOE module is loaded.
  if $lsmod | $grep "$T3_TOE_MODULE " 1>/dev/null 2>&1; then
    Info "Chelsio TOE module ($T3_TOE_MODULE) already loaded."
  else
    # Check if the TOE module is installed.
    if $modprobe -n $T3_TOE_MODULE 1>/dev/null 2>&1; then
      # Try to load the module since it's installed.
      if $modprobe $T3_TOE_MODULE 1>/dev/null 2>&1; then
        Pass "Loaded Chelsio TOE module ($T3_TOE_MODULE)."
      else
        Fail "Failed to load Chelsio TOE module ($T3_TOE_MODULE)."
      fi
    else
      Warn "Chelsio TOE module ($T3_TOE_MODULE) not installed."
      # TOECORE could be part of the kernel.
    fi
  fi
  if $lsmod | $grep "$T3_TOM_MODULE " 1>/dev/null 2>&1; then
    Info "Terminator 3 TOM ($T3_TOM_MODULE) already loaded."
  else
    # Check if the TOM module is installed.
    if $modprobe -n $T3_TOM_MODULE 1>/dev/null 2>&1; then
      # Try to load the module since it's installed.
      if $modprobe $T3_TOM_MODULE 1>/dev/null 2>&1; then
        Pass "Loaded Terminator 3 TOM ($T3_TOM_MODULE)."
      else
        Fail "Failed to load Terminator 3 TOM ($T3_TOM_MODULE)."
      fi
    else
      Warn "Terminator 3 TOM ($T3_TOE_MODULE) not installed."
      # TOM could be part of the kernel.
    fi
  fi
fi

# Get the correct TOM devices path.
if [ -e '/proc/net/toe/devices' ]; then
  tom_device_path="/proc/net/toe"
elif [ -e '/proc/net/offload/devices' ]; then
  tom_device_path="/proc/net/offload"
fi

# Get the PCI slots for the Chelsio card(s).
IFS=$'\n'
term_pci_device=($($lspci -m -n -d $CHELSIO_PCI_VID: | awk '{print $1}'))
unset IFS

# Get architecture.
arch=$($uname -m | sed 's/i.86/x86/')
case $arch in
  x86_64 ) arch=64;;
  x86 )    arch=32;;
  ia64)    (( tune_sysctl_only++ ));;
  * )      arch=0;;
esac

# Main PCI device loop.
(( $(not $tune_sysctl_only) )) &&
for (( idx=0; idx < ${#term_pci_device[@]}; idx++ )); do
  # On some versions of lspci, the domain is printed first [xxxx:].
  # Remove it so that everything is standard.
  term_pci_bus_pri[$idx]=$(echo ${term_pci_device[$idx]} |
                           sed 's/\([0-9a-zA-Z]\)\{4\}://' |
                           sed 's/:.*//')

  # Get the data for each slot.
  IFS=$'\n'
  data=($($lspci -n -vv -s ${term_pci_device[$idx]}))

  # Get the interface data for all interfaces, split on paragraphs.
  iface_data=($($ifconfig -a | awk 'BEGIN { FS="\n"; RS=""; ORS="" };\
                                    { x=1;
                                      while ( x<NF ) { print $x " "; x++ }\
                                    print $NF "\n" }'))
  unset IFS

  # Get the device ID (board ID) of the card(s) and
  # remove any leading/trailing whitespace.
  term_dev_id[$idx]=$(echo ${data[0]} | \
                      awk "{split(\$0,a,\"$CHELSIO_PCI_VID:\");\
                            print a[2]}" |\
                      sed 's/^[ \t]*//;s/[ \t]*$//')

  # Test the board ID's and define the type(s).
  # term_dev_id should not contain non-hex characters.
  echo ${term_dev_id[$idx]} | $grep -q '[^0-9a-fA-F]' && term_dev_id[$idx]=0
  [ $(printf %i 0x${term_dev_id[$idx]}) -ge 32 ] && term_type[$idx]=3
  [ $(printf %i 0x${term_dev_id[$idx]}) -lt 32 ] && term_type[$idx]=2
  [ $(printf %i 0x${term_dev_id[$idx]}) -eq 0 ] && term_type[$idx]=0

  # Set the register address based on board type.
  PCIX_CMD_ADDR=${PCIX_CMD_ADDR[${term_type[$idx]}]}
  PCIX_CFG_MODE_ADDR=${PCIX_CFG_MODE_ADDR[${term_type[$idx]}]}
  PCIX_MODE_OFFSET=${PCIX_MODE_OFFSET[${term_type[$idx]}]}
  PCI_BAR_REG=${PCI_BAR_REG[${term_type[$idx]}]}
  PCIX_LAT_TMR_ADDR=${PCIX_LAT_TMR_ADDR[${term_type[$idx]}]}
  PCIE_LINK_STAT=${PCIE_LINK_STAT[${term_type[$idx]}]}
  PCIE_LINK_CAP=${PCIE_LINK_CAP[${term_type[$idx]}]}

  if [ ${term_type[$idx]} -eq 2 ]; then
    pcix_mode_data=$($setpci -s ${term_pci_device[$idx]} $PCIX_CFG_MODE_ADDR.b)
    pcix_mode_data=$(Convert_base hex2bin $pcix_mode_data)
    pcix_mode_data=$(Convert_base bin2hex ${pcix_mode_data:3:3})

    # All T2's are PCI-X, except for device 15.
    term_board_id=$(printf %i 0x${term_dev_id[$idx]})

    if [ $term_board_id -ne 15 ]; then
      term_pcix[$idx]=1
    else
      unset term_pcix[$idx]
    fi

    # Identify multi-port cards.
    case $term_board_id in 12 | 13 | 15 | 16 ) term_multiport[$idx]=1;;
      * ) term_multiport[$idx]=0;;
    esac
  fi

  if [ ${term_type[$idx]} -eq 3 ]; then
    term_pcix[$idx]=$($setpci -s ${term_pci_device[$idx]} $PCIX_CMD_ADDR.b | sed 's/0//g')
    if (( ${term_pcix[$idx]} )); then
      # PCI/PCI-X
      bar_addr="0x$($setpci -s ${term_pci_device[$idx]} $PCI_BAR_REG.l)"
      bar_addr=$(printf 0x%x $(echo $(( bar_addr & 0xfffffff0 )) ))
      pcix_mode_addr=$(printf 0x%x $(echo $(( bar_addr + PCIX_MODE_OFFSET )) ))
      pcix_mode_data=$(memmapread $pcix_mode_addr)
      if [ -n "$pcix_mode_data" ]; then
        pcix_mode_data=$(Convert_base hex2bin $pcix_mode_data)
        pcix_mode_data=$(Convert_base bin2hex ${pcix_mode_data:0:2})
      else
        Fail "Could not get data at memory address $pcix_mode_addr!"
        Warn "Skip PCI-X tuning."
        tune_pci_enable=0
      fi
    else
      # PCI-Express.
      # Capability.
      cap_data="0x$($setpci -s ${term_pci_device[$idx]} $PCIE_LINK_CAP.l)"
      cap_width=$(Get_bits $(Convert_base hex2bin $cap_data) 9:4)
      pcie_bus_cap=$(Convert_base bin2hex $cap_width)
      # Linked.
      link_data="0x$($setpci -s ${term_pci_device[$idx]} $PCIE_LINK_STAT.l)"
      link_width=$(Get_bits $(Convert_base hex2bin $link_data) 25:20)
      pcie_bus_width=$(Convert_base bin2hex $link_width)
    fi
      
  fi

  # Set speed values based on register settings.
  if (( ${term_pcix[$idx]} )); then
    case $pcix_mode_data in
      3 ) term_pcix_speed[$idx]=133;;
      2 ) term_pcix_speed[$idx]=100;;
      1 ) term_pcix_speed[$idx]=66;;
      0 ) term_pcix_speed[$idx]=33;;
      * ) term_pcix_speed[$idx]=0;;
    esac
  else
    case $pcie_bus_width in
      1  ) term_pcie_width[$idx]=1;;
      2  ) term_pcie_width[$idx]=2;;
      4  ) term_pcie_width[$idx]=4;;
      8  ) term_pcie_width[$idx]=8;;
      16 ) term_pcie_width[$idx]=16;;
      32 ) term_pcie_width[$idx]=32;;
    esac
    case $pcie_bus_cap in
      1  ) term_pcie_cap[$idx]=1;;
      2  ) term_pcie_cap[$idx]=2;;
      4  ) term_pcie_cap[$idx]=4;;
      8  ) term_pcie_cap[$idx]=8;;
      16 ) term_pcie_cap[$idx]=16;;
      32 ) term_pcie_cap[$idx]=32;;
    esac
  fi

  # Get the Terminator card host bridge device.
  IFS=$'\n'
  lspci_data=($($lspci -v | awk 'BEGIN { FS="\n"; RS=""; ORS="" }; \
                                 { x=1; while ( x<NF ) { print $x " "; x++ }\
                                   print $NF "\n" }'))
  for device in ${lspci_data[@]}; do
    unset IFS
    if $(echo $device |
         $grep "Bus:.*secondary=${term_pci_bus_pri[$idx]}" >/dev/null); then
      term_host_bridge[$idx]=$(echo $device |\
                               awk '{print $1}' |\
                               sed 's/\([0-9a-zA-Z]\)\{4\}://')
    fi
  done
  unset IFS

  # The term devices are given an interrupt from the kernel at bootup.
  # Then, the interrupt vector is replaced, but the original interrupt
  # is used in ifconfig. If there are two cards in the system, they both
  # may get the same interrupt, and this IRQ may not even show up in
  # /proc/interrupts! This requires another method of identifying the
  # device in the ifconfig list. MAC address cannot be used, since it
  # could not be programmed yet (internal use).
  # The device base (Region 0) memory address should be sufficient to
  # uniquely identify a device in the ifconfig list based on the data from
  # lspci.

  # Get memory address used by the device.
  term_mem_addr[$idx]=$(echo ${data[@]} |
                        awk '{split($0,a,"Region 0: Memory at "); print a[2]}' |
                        sed 's/ .*//;/^$/d')

  [ -z "${term_mem_addr[$idx]}" ] && term_mem_addr[$idx]='none'
  unset data

  # Get the card interface (based on memory address).
  # Record interface up/down status.
  IFS=$'\n'
  for data in ${iface_data[@]}; do
    unset IFS
    if echo $data | $grep "Memory:${term_mem_addr[$idx]}" >/dev/null; then
      interface=$(echo $data | awk '{print $1}')
      # If the interface is up, assign term_iface_up.
      # A card may have more than one interface.
      if echo $data | $grep -q 'UP' >/dev/null; then
        term_iface_up[$idx]="$(echo ${term_iface_up[$idx]} $interface |
                               sed 's/^[ \t]*//;s/[ \t]*$//')"
        (( term_if_count++ ))
      else
        # If the interface is down...
        if (( $tune_iface_enable )); then
          # Bring interface up without configuring it and assign term_iface_up.
          # Flag the interfaces which were brought up w/o configuring.
          # Need to bring these down later.
          term_temp_ifup[$idx]="$(echo ${term_temp_ifup[$idx]} $interface |
                                  sed 's/^[ \t]*//;s/[ \t]*$//')"
          Print "Enable interface $interface."
          $ifconfig $interface up >/dev/null &&
            Pass || { Fail &&
              Exit "Failed to enable interface $interface for tuning."; }
          (( term_if_count++ ))
          term_iface_up[$idx]="$(echo ${term_iface_up[$idx]} $interface |
                                 sed 's/^[ \t]*//;s/[ \t]*$//')"
        else
          # Skip it and print warning.
          Warn "Skip tuning interface $interface, it's not up!"
          skip_down_interfaces[$idx]="$(echo ${skip_down_interfaces[$idx]} \
                                         $interface |
                                        sed 's/^[ \t]*//;s/[ \t]*$//')"
          unset term_iface_up[$idx]
        fi
      fi

      # These are the interfaces assigned to the Chelsio card(s).
      term_iface[$idx]="$(echo ${term_iface[$idx]} $interface |
                          sed 's/^[ \t]*//;s/[ \t]*$//')"
    fi
  done
  unset iface_data
  unset IFS

  # Get the interrupt data.
  IFS=$'\n'
  intr_data=($(cat /proc/interrupts))
  unset IFS

  # Identify the interrupts (MSI/MSI-X) assigned to the interface.
  for interface in ${term_iface[$idx]}; do
    IFS=$'\n'
    for data in ${intr_data[@]}; do
      unset IFS
      if [ -z "${term_card_intr[$idx]}" ]; then
        term_card_intr[$idx]=$(echo $data |\
                               $grep $interface |\
                               $grep -v queue 1>/dev/null 2>&1)
      fi

      if echo $data | $grep $interface | $grep queue 1>/dev/null 2>&1; then
        qset=$(echo $data | $grep $interface | $grep queue |
               sed 's/.*(queue //;s/).*//')
        # term_qset unused for now.
        term_qset[$idx]="$(echo ${term_qset[$idx]} $qset)"
        intr="$(echo $data | awk '{print $1}' |
                sed 's/://'):$interface"
      else
        unset intr
      fi
      if echo $data | $grep $interface 1>/dev/null 2>&1; then
        if [ ${term_type[$idx]} == 3 ] && [ -z "$qset" ]; then
          :
        else
           term_intr[$idx]="$(echo ${term_intr[$idx]} \
                             $(echo $intr | sed 's/^[ \t]*//;s/[ \t]*$//'))"
        fi
      fi
    done
  done

  # Get TOM module for interface, if this is a TOE card/driver.
  if [ -n "$tom_device_path" ]; then
    IFS=$'\n'
    tom_devices=($(cat $tom_device_path/devices | sed '/Device/d'))
    unset IFS
    for interface in ${term_iface[$idx]}; do
      IFS=$'\n'
      for data in ${tom_devices[@]}; do
        unset IFS
        offload_interfaces=$(echo $data |
                             awk '{for(field=3; field<=NF; field++) \
                                   print $field}')
        if echo $offload_interfaces | $grep $interface >/dev/null; then
          term_tom_module[$idx]=$(echo $data | awk '{print $1}')
          # Assign TOM name if loaded.
          term_tom_loaded[$idx]=$(echo $data | awk '{print $2}' | sed 's/<none>//i')
        fi
      done
      unset data
    done
    unset IFS
  fi
done

# Exit if all interfaces down.
if [ $term_if_count -lt 1 ] && (( $(not $tune_sysctl_only) )); then
  Fail "All Chelsio network interfaces are down!"
  if (( $tune_iface_enable )); then
    if (( $driver_not_installed )); then
      Info "The LLD is not installed."
    else
      Info "Be sure the driver is loaded."
    fi
  else
    Info "Denied access to enable network interfaces."
  fi
  Exit
fi

# Device loop, perform tuning.
(( $(not $tune_sysctl_only) )) &&
for (( idx=0; idx < ${#term_pci_device[@]}; idx++ )); do
  # Warn about PCI-X bus speed.
  if (( ${term_pcix[$idx]} )); then
    if [ ${term_pcix_speed[$idx]} -lt 133 ]; then
      for iface in ${term_iface[$idx]}; do
        Warn "$iface: PCI-X speed is ${term_pcix_speed[$idx]}Mhz."
      done
    else
      for iface in ${term_iface[$idx]}; do
        Pass "$iface: PCI-X speed is ${term_pcix_speed[$idx]}Mhz."
      done
    fi
  fi
  # Warn about PCI-E bus width.
  if (( $(not ${term_pcix[$idx]}) )); then
    if [ ${term_pcie_width[$idx]} -lt ${term_pcie_cap[$idx]} ]; then
      for iface in ${term_iface[$idx]}; do
        Print "$iface: PCI-E x${term_pcie_cap[$idx]} device "
        Say "running in x${term_pcie_width[$idx]} slot."
        Warn
      done
    else
      for iface in ${term_iface[$idx]}; do
        Print "$iface: PCI-E x${term_pcie_width[$idx]} device "
        Say "using all lanes."
        Pass
      done
    fi
  fi

# PCI TUNING ###################################################################
  if (( ${term_pcix[$idx]} )) && (( $tune_pci_enable )) &&
     [ -n "${term_host_bridge[$idx]}" ]; then
    dbg_msg "PCI-X device ${term_dev_id[$idx]} running at ${term_pcix_speed[$idx]}Mhz.\n"
    # Check for AMD-8131 PCI-X bridge "133Mhz Mode Split Completion Data Corruption" bug.
    host_bridge_venid[$idx]=$($setpci -s ${term_host_bridge[$idx]} 0x00.w \
                              2>/dev/null)
    host_bridge_devid[$idx]=$($setpci -s ${term_host_bridge[$idx]} 0x02.w \
                              2>/dev/null)
    host_bridge_rev[$idx]="0x$($setpci -s ${term_host_bridge[$idx]} 0x08.b \
                               2>/dev/null)"
    host_bridge_rev[$idx]=$(printf %i ${host_bridge_rev[$idx]})
    # AMD-8131 running at 133Mhz.
    if [ "${host_bridge_venid[$idx]}" == "$AMD_PCI_VID" ] &&
       [ "${host_bridge_devid[$idx]}" == "$AMD_8131_DEVID" ] &&
       [ ${host_bridge_rev[$idx]} -le $AMD_8131_BUG_REV ] &&
       [ ${term_pcix_speed[$idx]} -eq 133 ]; then
      dbg_msg "Going to fix AMD PCI-X bug for card ${term_pci_device[$idx]}."
      # Found an AMD-8131 bridge and the device is running at 133Mhz,
      # there's a chance of hitting 8131 data corruption bug.
      # Get PCIX CMD data.
      pcix_cmd_data=$(Convert_base hex2bin \
                      $($setpci -s ${term_pci_device[$idx]} \
                        $PCIX_CMD_ADDR.l) \
                        2>/dev/null)
      # Get current PCIX Split Transaction.
      pcix_current_split_trans="0x$(Convert_base bin2hex \
                                    $(Get_bits $pcix_cmd_data 22:20))"
      # Get current PCIX Burst Size.
      pcix_current_rd_byte_cnt="0x$(Convert_base bin2hex \
                                    $(Get_bits $pcix_cmd_data 19:18))"
      # Conditions in which the AMD-8131 bug would NOT be present:
      # max_split_trans = 0x0 (1)  max_rd_byte_cnt = 0x2 (2048b)
      # max_split_trans = 0x1 (2)  max_rd_byte_cnt = 0x1 (1024b)
      # max_split_trans = 0x2 (3)  max_rd_byte_cnt = 0x0 (512b)
      if [ $(echo $(( pcix_current_split_trans + \
                      pcix_current_rd_byte_cnt )) ) -gt 2 ]; then
        # This configuration would cause the data corruption bug!
        pcix_cmd_data=$(Change_bits $pcix_cmd_data 22:20 $SAFE_PCIX_SPLIT_TRAN)
        pcix_cmd_data=$(Change_bits $pcix_cmd_data 19:18 $SAFE_PCIX_BURST_SIZE)
        pcix_cmd_data="0x$(Convert_base bin2hex $pcix_cmd_data)"

        iface_bug=$(echo ${term_iface[$idx]} | sed 's/ /, /')
        Warn "Found AMD-8131 bug on interface(s) $iface_bug."
        if (( $enable_amd_workaround )); then
          Print "AMD-8131 bug workaround for interface(s) $iface_bug."
          # Apply the workaround values, this will degrade performance a bit.
          $setpci -s ${term_pci_device[$idx]} \
                     "$PCIX_CMD_ADDR.l=$pcix_cmd_data" \
           >/dev/null 2>&1 &&
           Pass || Fail
        else
          Warn "Skip workaround for AMD-8131 bug!"
        fi
      fi
    else # not AMD-8131 running at 133Mhz.
      if (( $enable_pci_burstsplit )); then
        # Tune the PCI burst size and outstanding split transactions reg.
        dbg_msg "Going to crank up PCI-X bus settings for dev ${term_pci_device[$idx]}."
        pcix_cmd_data=$(Convert_base hex2bin \
                        $($setpci -s ${term_pci_device[$idx]} \
                          $PCIX_CMD_ADDR.l) \
                        2>/dev/null)
        pcix_cmd_data=$(Change_bits $pcix_cmd_data 22:20 $PERF_PCIX_SPLIT_TRAN)
        pcix_cmd_data=$(Change_bits $pcix_cmd_data 19:18 $PERF_PCIX_BURST_SIZE)
        pcix_cmd_data="0x$(Convert_base bin2hex $pcix_cmd_data)"
        Print "Set PCI-X split/burst parameters."
        $setpci -s ${term_pci_device[$idx]} \
                   "$PCIX_CMD_ADDR.l=$pcix_cmd_data" \
         >/dev/null 2>&1 &&
         Pass || Fail
      fi
    fi

# PCI LATENCY ##################################################################
    if (( $enable_pci_latency )); then
      # Tune the PCI Latency Timer.
      pcix_lat_tmr_data=$(Convert_base hex2bin \
                          $($setpci -s ${term_pci_device[$idx]} \
                            $PCIX_LAT_TMR_ADDR.l) \
                          2>/dev/null)
      pcix_lat_tmr_data=$(Change_bits $pcix_lat_tmr_data 15:8 $PERF_PCI_LAT_TMR)
      pcix_lat_tmr_data="0x$(Convert_base bin2hex $pcix_lat_tmr_data)"
      Print "Set PCI-X latency timer parameters."
      $setpci -s ${term_pci_device[$idx]} \
                 "$PCIX_LAT_TMR_ADDR.l=$pcix_lat_tmr_data" \
       >/dev/null 2>&1 &&
       Pass || Fail
    fi
  elif (( ${term_pcix[$idx]} )); then 
    Warn "Skip PCI-X tuning!"
  fi # end PCI-X tuning.

  # Tuning for interfaces which are up.
  interfaces=${term_iface_up[$idx]}
  if [ -n "$interfaces" ]; then
# SMP AFFINITY #################################################################
    if ((tune_cpumask_enable)); then
      for iface in ${interfaces[@]}; do
        for interrupt_data in ${term_intr[$idx]}; do
          associated_iface=${interrupt_data##*:}
          interrupt=${interrupt_data%:*}
          # Only set smp_affinity for SMP systems.
          if [ $num_phys_cpus -gt 1 ]; then
            if [ "$associated_iface" == "$iface" ]; then
              Print "$iface: Set IRQ $(printf "%3d" $interrupt)"
              Say " smp_affinity to CPU${phys_cpus[$cpu_affinity_index]}."
              echo ${affinity_mask[$cpu_affinity_index]} \
               2>/dev/null > /proc/irq/$interrupt/smp_affinity &&
               Pass || { Fail && (( failed++ )); }
            fi
            (( cpu_affinity_index++ ))
            if [ $cpu_affinity_index -ge $num_phys_cpus ]; then
              cpu_affinity_index=0
            fi
          fi
        done
      done
    fi

    if (( $tune_tom_enable )); then
# TOM TUNING ###################################################################
      if [ -n "${term_tom_module[$idx]}" ]; then
        if [ -n "${term_tom_loaded[$idx]}" ]; then
          # Terminator 2 specific.
          if [ ${term_type[$idx]} -eq 2 ] && [ ${term_multiport[$idx]} -ne 1 ]; then
            # max_tx_pages
            if [ -n "$tom_max_tx_pages" ]; then
              Print "TOM(${term_tom_module[$idx]}): Set 'max_tx_pages=$tom_max_tx_pages'."
              $sysctl -w \
               "toe.${term_tom_module[$idx]}_tom.max_tx_pages=$tom_max_tx_pages"\
               >/dev/null 2>&1 &&
               Pass || { Fail && (( failed_tom_sysctl++ )); }
            fi
          fi

          # Terminator 3 specific.
          if [ ${term_type[$idx]} -eq 3 ]; then
            # ddp
            if [ -n "$tom_ddp" ]; then
              (( $tom_ddp )) && action="Enable" || action="Disable"
              Print "TOM(${term_tom_module[$idx]}): $action DDP."
              $sysctl -w \
               "toe.${term_tom_module[$idx]}_tom.ddp=$tom_ddp" \
               >/dev/null 2>&1 &&
               Pass || { Fail && (( failed_tom_sysctl++ )); }
            fi
            # max_wr
            if [ -n "$tom_max_wr" ]; then
              Print "TOM(${term_tom_module[$idx]}): Set 'max_wr=$tom_max_wr'."
              $sysctl -w \
               "toe.${term_tom_module[$idx]}_tom.max_wr=$tom_max_wr" \
               >/dev/null 2>&1 &&
               Pass || { Fail && (( failed_tom_sysctl++ )); }
            fi
            # delayed_ack
            if [ -n "$tom_delayed_ack" ]; then
              Print "TOM(${term_tom_module[$idx]}): "
              Say "Set 'delayed_ack=$tom_delayed_ack'."
              $sysctl -w \
               "toe.${term_tom_module[$idx]}_tom.delayed_ack=$tom_delayed_ack" \
               >/dev/null 2>&1 &&
               Pass || { Fail && (( failed_tom_sysctl++ )); }
            fi
            # tcp_timestamps
            for iface in ${term_iface[$idx]}; do
              if [ -e "/sys/class/net/$iface/tcp_timestamps" ]; then
                (( $tom_tcp_timestamps )) && action="Enable" || action="Disable"
                Print "TOM(${term_tom_module[$idx]})[$iface]: $action TCP timestamps."
                echo "$tom_tcp_timestamps" \
                 1> "/sys/class/net/$iface/tcp_timestamps" 2>/dev/null &&
                 Pass || { Fail && (( failed_tom_sysctl++ )); }
              fi
            done
            # zcopy
            # Increase zcopy_sendmsg_partial_copy if on 32-bit arch and using
            # a PCI-X card or PCI-Express x4 or slower.
            if [ -n "$zcopy_tweak" ] && [ $arch -le 32 ] &&
               ( [ -n "${term_pcix[$idx]}" ] ||
                 ( [ -n "${term_pcie_width[$idx]}" ] &&
                   [ ${term_pcie_width[$idx]} -le 4 ] ) ); then
              Print "TOM(${term_tom_module[$idx]}): "
              Say "Set 'zcopy_sendmsg_partial_copy=$zcopy_tweak'."
              $sysctl -w \
               "toe.${term_tom_module[$idx]}_tom.zcopy_sendmsg_partial_copy=$zcopy_tweak" \
               >/dev/null 2>&1 &&
               Pass || { Fail && (( failed_tom_sysclt++ )); }
            fi
          fi

          # Global or non-Terminator version specific.
          if [ -n "$tom_mss_size" ]; then
            # Override the in-script tom_mss_size with supplied parameter.
            tom_mss_size[${term_type[$idx]}]=$tom_mss_size
          fi
          if [ -n "${tom_mss_size[${term_type[$idx]}]}" ]; then
            Print "TOM(${term_tom_module[$idx]}): Set 'tom.mss' to ${tom_mss_size[${term_type[$idx]}]}."
            $sysctl -w \
             "toe.${term_tom_module[$idx]}_tom.mss=${tom_mss_size[${term_type[$idx]}]}" \
             >/dev/null 2>&1 &&
             Pass || { Fail && (( failed_tom_sysclt++ )); }
          fi

          (( $failed_tom_sysctl )) &&
           Warn "Some TOM sysctls failed, system may not be tuned!"
        else
          Warn "TOM(${term_tom_module[$idx]}): offload disabled, skip tuning!"
        fi # end TOM loaded.
      else
        Warn "TOM driver not loaded, skip tuning!"
      fi # end TOM tuning enabled.
    else
      Warn "Skip TOM tuning!"
    fi # end Tuning for TOM.
  fi # end Tuning for interfaces which are up.


  # Tuning which does not require an interface to be up, loop per device.
  if [ ${term_type[$idx]} -eq 2 ]; then
    :
  fi

  if [ ${term_type[$idx]} -eq 3 ]; then
    :
  fi
done

restore_if_state ${term_temp_ifup[@]}

# SYSCTL TUNING ################################################################
if (( $tune_sysctl_enable )); then
  Info "Set sysctls..."
  if (( $write_sysctls )); then
    Info "Writing sysctl entries to $sysctl_conf_file."
    # Create a backup file.
    if [ ! -e "$sysctl_conf_file.perftune.bak" ]; then
      $cp -fa $sysctl_conf_file "$sysctl_conf_file.perftune.bak"
    fi
  fi
  IFS=$'\n'
  for control in ${sysctl_data[@]}; do
    unset IFS
    sysctl_param=${control%%,*}
    sysctl_param=$(echo $sysctl_param | sed 's/^[ \t]*//;s/[ \t]*$//')
    data=${control##*,}
    data=$(echo $data | sed 's/^[ \t]*//;s/[ \t]*$//')
    [ -z "$data" ] && continue
    unset failed_sysctl

    if $sysctl $sysctl_param >/dev/null 2>&1; then
      Print "Set $sysctl_param=\"$data\""
      $sysctl -w "$sysctl_param=$data" >/dev/null 2>&1 && Pass ||
       { (( failed_sysctl++ )); Fail; }
      if (( $write_sysctls )) && (( $(not $failed_sysctl_file) )); then
        if ! $grep $sysctl_param $sysctl_conf_file >/dev/null 2>&1; then
          echo "$sysctl_param = $data" >> $sysctl_conf_file ||
           (( failed_sysctl_file++ ))
        else
          # Entry already exists, overwrite it!
          $cat $sysctl_conf_file |
           sed "s/$sysctl_param.*/$sysctl_param = $data/" \
            > "$sysctl_conf_file.tmp" ||
            (( failed_sysctl_file++ ))
          if (( $(not $failed_sysctl_file) )); then
            $mv -f "$sysctl_conf_file.tmp" $sysctl_conf_file
          fi
        fi
      fi
    else
      Warn "$sysctl_param not valid for this system."
    fi
  done
  unset IFS
  (( $failed_sysctl )) && Warn "Some sysctls failed, system may not be tuned!"
  (( $failed_sysctl_file )) && Fail "Unable to write to $sysctl_conf_file."
else
  unset IFS
  Warn "Skip sysctl tuning!"
fi

Info "System tuning is complete."
exit

# MEMMAPREAD DATA ##############################################################
: <<MMAPR32
1f8b080845a0884400036d6d617072333200dd586f6c14c7159f3d9f7d86183813971882d4ab00c9
a6e1b0a99d3a94aa067bf1199df9634c4a046273dcad7de7debfdcedf2a7152af448a2cbc5aaa37e
80484885b6523ea452ab962a55f2c58e29942a8a4e1152aa36486e45a4734d2347a5c48928d7df9b
99bddb5ba052be76ed77b3bf796fde7b33f3e6edccfc500dee541485598f8bd53142fd67dd8d5d28
7b968afa2ee6631ed6c6d6b2d5ac8163d069c88066f14e540f7283ea402d50d272c6dd48f438f0e3
92a748e20fda12f57860c723da33afe0f3ba73e0815a51b11ed420f92e1441f083e011fd1198a841
da206a837c1b6c13f9807d36debe8f8d087bc863b5df1c8f1ddd1c8f6c8ac792e6097f36e5df22ea
bdd2f781dd07e45809aa977d5e066a02c135b6c4a1dbea739d6d9c1a64fb46100df3630ff1e96559
be005a093a28f10589bb25de2a7140e2c312fb417bcfbb1bc95e337b826d93fc75926f4a7c53e27d
12bf2df12868fdcb56fbe54c93fc1945f0ab9123c6f82b0eccb45dc7b4617d2c9635f44c5f3c94cd
ea59a66963895452cb1aa18ca1690cc31da6617e9a658d48ca3458c24c26426936a61be9d0989e8d
7d5f072763a4cc789ca5d27af2e92e9680008ad1e39998a1336d700fb4456249cdccea11e8279552
7f22144bb2703c95d5d9407070479fb6c5df5979eb604cc4bcabf247f1ef9273e662eb9998777a9a
63b165348313b2cecbb18b9d93fc168c73439318ef7a4cf27a941e8a432aa1f2292a11001d546240
bba84410f45089a0d9462582a1974a04c481fcc7b9db8da569a82ed17a2a6d46e3eb33acdcbd1612
e50d3efc92ddf206b214a5d7b9d9329e0d64314abcb922c764394a2ecf4d714c1e445b09ff9a63f2
244ad335779163f228da46789263f22c4a6335779a63f230da43380dd8f9cf23f9bfe56e2dec1d19
8e5e78099c007ef63d1bbd8d1c52fa1504ee4c4ea22ffb4be4e1a133336f20190c1772f7c07971ca
70958b070f5d9f99e432e8efe96f8f50bf8c15f35f9d38c67253ee9f07a9b71f5ca2a2e07df10373
fe6a3d8928d767f277459b4b01a401e85afd7b3281176fee7653942acbc5dc152ff490012edb0347
b9546e6a05fea74beee95977fb956bea22555e53ef89e23605f655f5afca35f5461be2bfa036c195
02cbabc5dca922339baea9ef91c8dc7d5275db3dcec659d92c962ede2f976131af2ee60fdc936ae0
20316f947e6b316773a766d9c98a0e5a6ca56360e6d58f0aea479ffdf9f5fcf4baa1c5fcd042beb8
4ebd9757efa0b6706051799773bf56fcbaba90574b305b36ef94cd85b2393bae8c2b65b334ce4af7
ff43467c79f516c6009cd24d5ee1cd9dba5536974893f3bb0a07160a437726d4c576efea80bba0de
aa53175f613f3b4863dd4d114c1aa3044b4dc26d740316cae6add29b422374d16015d4f7aecf606c
bffbec7e58b426f9dd66f4692b0427723e4cf4c44fe837af2eb4173bef4e2fba9eb99a5d95ff307f
b7dcf29bc2d042fbe73ba73f773df37efe8bcc27b92b4d878e68726ea1d352f802144a5defd06ffb
22d4c0e044ba3c5f3f596e796b77ee7ed9fcac4419cfd221e26ef81dfa8a5ca29ff9a51453f3ee72
b150975bc4e851e8d963f33158d95bcac0efe7c011f99af2c0e6887e6c73424f58b98d9681bd6432
1752bea06fc0859cbb91be076e993b03f80e51de7ffe47c81128278129e75f6222ef7b6db9936cb6
62e0290bf5525ee1b997217b23af432fbd0751ae94ede8db4a8b1dd3945a8b7ab894225f1650ba72
22477cd987beabd6fb9fa0e32fa07f80be002dc5ba5e03da08da7ab62ad74f6d06fafab6fadaf089
6cf77dc3dfe5eff66de9e8e8eedcd2d1e96b1bd623be40c810f59bb6b4b3ff7f617ff664c2081d45
89ef172fa3d65b2c892f629af9932943f76fdf31b8c9088d317f34948d327fe464120d456964987f
2c69fa8fe9996c2c95ac011a78193d4e72e2251d3748730cbf867e02bfa30060a5222123c4fc7a54
1bcd84123af3878d54260b03a2180f67b8b1502216868194c17f8436d1f2681662e15422a1278d2f
13474f32b12e2896f97e5011f16a3dd6fe81f6231e29c7f76d8adc3fc8c72dcb4e26f64f24476b2a
a0883d8fdb2647f44d26d615c9d15a9b845c51b65558753ff71d26d61bc9d1da7cde25d6a4d3bf01
c6d77a8aeff9b0065c68b4c666d7da0b8e30b10ee99dd6e25afade3becd21366628fc8f7b2900bd6
097fecfda08515b7c9d1da3f5c2772825bf6cf9233a57eca2d947b2ed4897ce11cbfb44dee32e42e
436ed22147f4039b1c9d05fa5139e57a50df199b1ccf751e312e4eb99759350e7c90f379444e73ca
fdd826d705b92e4f9567977b5dcad1dcf17382478c8353eea24dae1772bd8f907bc32647fb86c023
ecfe52f695e4f8f9c323ce1ef53639d2ff3b9b3eda17b6343ea88fe86d9b1ce5fc56c83df510b919
9b5c3fe4fa1bc577c6e9df75699fe4e82bbef71172efb3dabd3bc92db75558afcd5297f51c41307e
c81e94b3e6cc7ace2fc799d02dd6ff26565d6f4b1cfa4e20195cb535b4fbe47c287f30de5e48b555
b05010a8606161b28245af697d0b2c66cbfa36d68993255faf027b380e56b08898c3152c4e77172a
581c922f57b038c9f59fb5b098015a1f022fe3d857c1cb39eeaae0151cf79cb3b03881f456b05839
810a5e29fcad6091615bce5bb885e3d60a163b8dfe0a5ec5f1de0ab6670ec2ad0ebcda81d738f093
7c86a2b2ff2ef4bf76ad7f5a5e6beb9f82fe6db4f54f81748fad7f0afaa752ffce5b78151b44c90f
011c3fc1e844feaacddef7504efd0ffbc7516eb3d93fcbe4fe45da7f8d55e743c17cfcd4e1cf9b28
675faaea9f76e8a7f575d0e6df0d569d9f66cccf4d296b9deb3f61221eac73f6bf6de3e3757d5a6e
900bc33af7d39d48408e47b36b15db004c67af1d9cdfc4ba956a7cae447c7e4bb6b7ee098624b6ee
09424aed3d4156f2ad7b8257946a3c93fed7945aff7e41fec0feb0e45f56aaf1e4c5784c01d379f0
b022f87f90faad7b87bf3bf4fd4ba9c6a70ff37d5fa9ae9f95583f6e9933ac7b8a55aedaf61b5db5
f63b5dd5f86f46fc0f001fb6f1838ef69aabf6de2329ed59f71ea75d55ffbcf06fc296c37ca04b0e
7d6f39f82c1c8ac76dd7202c9c31b286393aea0f334deb1bd933ac0507f78f681a507f0ddad55701
697f07c39e2c1dd70d3de2ef043392d2c6e2a9a3a1b8c677765ac83cc1f88e4f8b9889c4494bb5ba
bbbfaad9023b87b70fa9154466acf7aad670452bce4289503aa38722f098f6884799d6ffdceeed43
837de2b6a5b7b77ac9a28da6b5e87168a2eda816ca644227353d1991b7385549de856c4a8b869291
b86edde384b3266fc834beb315b74376f5d6e5506d1d5d25d96b6cd74935be89f1aff1cdaaaa98e7
86350dbb60c9e3b74a0fdc33d5e8e58d6c9da541b234f3ee88abacdade63441dcd349defc0b581e0
9e1ddb83da9e9d3bf7ab23dac8f61d411573c325ec96a481da0b31714d56eb9ddd9d87ded1d5ba62
0d49cdcddd7f010586df723e160000
MMAPR32
: <<MMAPR64
1f8b08080aa0884400036d6d617072363400e5597d6c5b5715bf7e8e53e7a3a95bba35b441f2a8cb
92a2b88969433b567092ba792e5eeba6c9e880edd5b15f12337f613fb7e9a4c024b3a9c6cb642490
fa170bd2248240d07ff8d884dab4699714a429dd102a5f53049de62803a5da24220633e7be77eef3
7bd736adf8837fb8967d7c7eeffcce3df7be7bcfbdefddaffb0247058b85b02290cf12aa391abdaa
ee45dcd1a69b007690d8e1f76364276904dd66b0f312af49cea36b26ed6867856f83562156ec35c9
0e8499b418a48d188bd724ef34119384c8751e8db58478a92968923d18875730f304e4399a116d0e
9a6411032b72ed6bc06f07faeb60ed42e9443ba7c19e96e0db4a84feefc4383b9bbc26e9423b17c7
3b09bc4672ff85c5b92f161debdbbf2f16e98e4513d9a9eea9837ddd7dfbdd99a4dba3faa6bd409b
36747c54b5170c75d242ef632b7c5b88765f3671f508686331f01ab17edac4e67bc4390edf6d06fd
f7284f727810fbff510edf8152e2f043682f72f853280f70f8c3284f73f85e94531c9e42e986ef56
d24eda5bb5f1c2fa9d56ef24d5e5813a38918e9d9586e589684691d383b15026236788244dc49309
29a384d28a2411b895617ae7fa48468924b30a896713f1508a4cc84a2a342167a2cfc87025ad24b3
b11849a6e444df7e12070310e3e7d251450687d4073a8c87a209128e253332190af80706258fdbe3
a6fd22547d2ac5021f3a361da86777469b28e36ba8cfb668fd40c7408b81c7fa878ea126033e8ff6
9b482507d0b264c08df52f1b70ab01bf6dc08de377c5801bf34ac9801be7d5ba01378ef50d036e37
e062ee5d7be94dead003e1979eb452e8ba7da17cc0d3e820e53dfbe1b708a5bc87ea9394b2ba5286
b2672fd56993579755fde354a74d5d9d57f59d54a74d5cbda4eadba84e9bb63aabeacd54a74d5a2d
aaba4075da94d56755fd1f36d069b8ab2950f5787bffeacfdf7a4accff59ccdd590f8ef817e78b76
2f1117aff6a86271091686d27160bc5fa46d130bb627c091f8dcbc229497d5a6158de5d9c3afc065
322ae6df561c6b2ee0ccdbc5bced3b0096df00f20b945c7088cfbd91bdf39a6d0634cbcd85f1f1f1
a2f62d8e8ab9c392153c50070ffe420d11ea6abd628704eccf2fdcec2fffe52654492b8078cee4a7
ff29e6b3ebe2a2afa4da2efa6ed33e7ccd77c502ff2f75401a150bbe75358c0238f5cd89b9e93992
6d5df4bdac76b61d7ec5c2f4dcab947e591d0ab31f96cb605962cee0f225f58a1a4ee9245ccefbae
e7a6af93f3ba9babf4ca907a65bee09bfffb6df1a2b81b5ce47d2ba08292bf265a474becd243cbe2
277d2b707519a25b298c5e170bd9657ffe6a7f7ef915eaef55fa7345adcea345b35498be5eeaa3ff
73d34be56c1356bcf679b130ba22ce40555d0ef05512adbea52d3f23176c7d0db4a737ef06a17abb
acba74c1bc2bfde45fe0062a84862d95ae8102ce685d05dfcb37cdb7b328e6bfec2a05f211d74660
66cff72de0321f734177bedbdefb87d216ea67c6560438d0b5225eddb08a8716325bc4fc8dfef2f6
3f8ae505f1d05afa7db1d0e1120b31973d5088b81c3064daf1866bf77bc616a46e67bafd5474954e
a97e664e97e9705bdb541ef91311cbbf16731f94b3efd1f1f6a527573f07b1627c741c9c121717e8
ba8ee3d3027ed61c5885985bb3c3382d58c5dc46397b577540dba8ced313347e3a8469ae11c8be88
7c765f5c8ed3aeb0ecb27ec685396516ccbc749ec32ca0797f12e4459c3fdb51421e9c72b46eb2b3
7d41077e97705ff545c4fbdb1ccf0b839b1b75de33c39469d9855cc6bb0077fa716a70ec0521d710
6c733e6fd5fdd2356f09ae1fd21d0eb7b5e7ac813667250f95b1d4d359613996ed2f5a519eb16971
6f46dd8efb11964bbd82a6b31c3a67d574963b2fe075b6de7f13255b03da513ec0c5c372f81ce657
96ebe751b27e63b998adf7b30d5e139e429de5e61e946cad61f5433726a90ca27d1975d62feba87b
f0faffaab0fd265f5ec4fbf25d943f467919e5eb28df42f937941fa2ac2aac9ea1c1c1479c9db0ed
eb727ecabddf7dc0e9e9e939d0ebe9e975760ecb11a7185234bcdbd3f57f60ecce9c8f2ba13190b0
7f52e524fb174dc08e2c45dc89a422bbfb07fcdd4a6882b827439949e28e9c4f0051934a9ab82712
59f759399d8926132645826b693916a286f82f1553a8ef28fc2af214fc8e8302d792919012226e79
521a4f87e2b23419495734e20e2bc974062ad4c457c269b5f2503c1a860a938afaa3f9d6fc8c65c0
2c9c8cc7e584f2df8fce4ad945b4b9a2efc9041c67ec3988b3b770fa6e62ded3559e9b34ddc9d937
707a2fd17210e37b91cf9eeb8e703c3ba77f9a683989f159debac0eac7806d183be3b3fc419722ab
81cff2e01c263296f758e1db3f44b49cc3f82ccf781accf5b078054e8e102d87319de5b120129ca4
76fcac84d137e3b3bc99423ecb9b7cffb1b8e21c9fe5e15924cc1bf82d35f8e748e5599d16b6ee9c
b199ed58e1ef7f9ae34f217f0af9c53a7cf6bc32cdf1d97b1007021bc6870d038f951cc767eba41d
179a36ce9e8f3f4fccf3a71df9edc8dfccd9f3fc6f71fccafb034d7771f63cff258e1f447e10f9df
e6ecf9f1f303e4b375bbf29e45d3f9fee2f99738fe06f237ee93ff738e6fc7f5ccde5cdb9ed77f49
b47bc7f895f73d9a5e34cc7f239fc57583ab9f3defceb6fce7fa99fc15c767fb9e39e49fbe07ff4d
8e4ff0b99a6de4f8f9c3c7f33bc4189f3d97b723ff5efdff16a9ce69467e1b7791b7dd4acccfedac
7c0207fe3b1ccef34d6b8fa104716319c40d215d87e8bb193eff34d5a97f1617ae5b9cf35a6dad57
acd45af0d6c0057d9d33e3567dfd32e30dfaba64c66dfa7a63c61b6bee57adb0d2066be2763def9b
f1263d9f9bf1663d4f9bf1163dff9af1563daf9af1cd7abe34e36d7a1e34e35bf4fc66c61d7ade32
e35bf57c64c6b7e979c68c7f44cf1f667c7bcdfdb8159e5ed87c37e30feaf3d88cefa8cc4f135e79
5f68c63f5a8569f8ce3af8ae3a38bf0b63f3a6953ccadd173a1f1bc8ddaae7c40e9553dd9f7b55bc
ba3f0faa78757ffa547c077170edf5ab783b7122cee6d928c679868bf369c467ef33fe7318ff3a17
e737307ec2c5a9adab0eb2c28dab97eab4eb8718cfb2dd6c7fb54e3caf637b5d5c7b7f436abfff7e
8fd47effbdc942db5c3d3e1d803b84bb65fe7e3d64a9fdbefc11ea47d841ecdc7d1952ed5b4911db
7508f12f586abf5f7f5ac5abf3c357d10f9f07a62cb5dfc7bf5827feef596abfa7ff29faefc1381f
47fc06f503fdcfcfaf5b68cfbf9ff96d9d7adfb1d43e07f8c042f7d8d5f3ba51a0f6d5f9ad55a8ed
df29d48ef36181dedfea7c7218ed3b39fb01a1f6b9c4689d7a2755ff957ccbf687e784dae71805b5
deeaf65e146a9f63fca84ebdd7ead893702816331c7390705ac928d9f171779848d2e0c8896129e0
3f352249a01d3169c7067525e5ee21f08c9b8ac98a1c71f7c2c548529a8825c74231497d529642d9
29a23d4f47b2f1f879e6da77fc48c533538e0ef73fe6d3355a0dfb5ff11ad6bdc6657ac492964311
88983e738f559fb278bdc60316ed64c68c49479e38deff987f10b8f43d80144aa743e7253911311e
ee70142992494a93a14424a61fec843359958fe73d1c417ddb80ddccce89789f86da3543ed8c8937
d36bd37c4a63990cb3a7a74a928a1b5aa11d4399bdd0ce429216b424413f72444956df6348438113
03fd01e9c4d1a3a77c23d248ff40c00777845aa827587c7c062f5883ff04fc8b441352362347f000
adaa430d11d53c8e33c78796e643ba7f03b1adade7711f0000
MMAPR64

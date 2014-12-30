#!/bin/bash
usage() {
	echo "Usage: $0 <interface> <eeprom_file>"
}
error() {
	echo -e "ERROR: $1" >&2
	echo "Failed to update EEPROM!" >&2
	exit 1
}

# This script should only be run by root.
if [ $UID -ne 0 ]; then
  error "Must be root (UID 0) to run $0!"
fi

ethtool=$(builtin type -P ethtool 2>/dev/null) || error "Cannot find ethtool utility."
ifconfig=$(builtin type -P ifconfig 2>/dev/null) || error "Cannot find ifconfig utility."
lspci=$(builtin type -P lspci 2>/dev/null) || error "Cannot find lspci utility."
stat=$(builtin type -P stat 2>/dev/null) || error "Cannot find stat utility."
od=$(builtin type -P od 2>/dev/null) || error "Cannot find od utility."

BINSIZE=2116
TXTSIZE=6336
MAGIC=0x38E2F10C
OFFSET=4096

MACOID='00:07:43'
VENDID='1425'
MIN_DEVID=0x30
MAX_DEVID=0x35

interface=$1
file=$2

# Check interface.
if [ -z "$interface" ]; then
	usage
	exit 1
fi
# Check file exists.
if [ ! -e "$file" ]; then
	usage
	exit 1
fi

# Need to ensure we don't update something that doesn't belong to us.
# Check if the cxgb3 driver is loaded (module or in-kernel) and if the
# interface belongs to the driver.
if ! $ethtool -i $interface | grep cxgb3 >/dev/null; then
	error "Wrong interface or driver is not loaded."
fi
# Check MAC OID (Chelsio only).
if ! $ifconfig $interface | grep -i "hwaddr $MACOID" >/dev/null; then
	error "Not a Chelsio device, refusing to update EEPROM on $interface."
fi

# Check Dev ID (T3B only).
businfo=$($ethtool -i $interface | grep "bus-inf" | sed 's/bus-info:\s*//')
devid=0x$($lspci -s $businfo -n | sed "s/.*$VENDID://" | sed 's/^0*//')
if [ $(( devid )) -lt $(( MIN_DEVID )) -o $(( devid )) -gt $(( MAX_DEVID )) ]; then
	error "Unsupported device (DEVID $devid)."
fi

# Check the filesize before attempting to load EEPROM contents.
filesize=$($stat -c "%s" $file)
if file -b $file | grep -c "ASCII" >/dev/null; then
	if [ $filesize -ne $TXTSIZE ]; then
		error "Invalid EEPROM file - $file"
	fi
	data=$(cat $file)
else
	# Must assume binary file.
	if [ $filesize -ne $BINSIZE ]; then
		error "Invalid EEPROM file - $file"
	fi
	# Generate data command, removing the CRC checksum data.
	data=$($od -An -tx1 -w1 -v -N $(( BINSIZE - 4 )) $file)
fi

# Write the EEPROM.
echo -n "Updating EEPROM, Please Wait "
for val in $data; do
	$ethtool -E $interface magic $MAGIC offset $OFFSET value 0x$val
	if [ $? -gt 0 ]; then
		echo
		error "Failed to update EEPROM!\nSRAM image in EEPROM may be corrupt!"
	fi
	if [ $(( $OFFSET % 64 )) -eq 0 ]; then
		echo -n "."
	fi
	(( OFFSET++ ))
done
echo
echo "EEPROM update successful! Reboot required for changes to take effect."

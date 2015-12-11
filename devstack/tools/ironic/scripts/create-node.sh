#!/usr/bin/env bash

# **create-nodes**

# Creates baremetal poseur nodes for ironic testing purposes

set -ex

# Keep track of the DevStack directory
TOP_DIR=$(cd $(dirname "$0")/.. && pwd)

NAME=$1
CPU=$2
MEM=$(( 1024 * $3 ))
# Extra G to allow fuzz for partition table : flavor size and registered size
# need to be different to actual size.
DISK=$(( $4 + 1))
ARCH=$5
BRIDGE=$6
EMULATOR=$7
LOGDIR=$8
NODES_FILE=$9


LIBVIRT_NIC_DRIVER=${LIBVIRT_NIC_DRIVER:-"e1000"}
LIBVIRT_STORAGE_POOL=${LIBVIRT_STORAGE_POOL:-"default"}
LIBVIRT_CONNECT_URI=${LIBVIRT_CONNECT_URI:-"qemu:///system"}

export VIRSH_DEFAULT_CONNECT_URI=$LIBVIRT_CONNECT_URI

if ! virsh pool-list --all | grep -q $LIBVIRT_STORAGE_POOL; then
    virsh pool-define-as --name $LIBVIRT_STORAGE_POOL dir --target /var/lib/libvirt/images >&2
    virsh pool-autostart $LIBVIRT_STORAGE_POOL >&2
    virsh pool-start $LIBVIRT_STORAGE_POOL >&2
fi

pool_state=$(virsh pool-info $LIBVIRT_STORAGE_POOL | grep State | awk '{ print $2 }')
if [ "$pool_state" != "running" ] ; then
    [ ! -d /var/lib/libvirt/images ] && sudo mkdir /var/lib/libvirt/images
    virsh pool-start $LIBVIRT_STORAGE_POOL >&2
fi

if [ -n "$LOGDIR" ] ; then
    mkdir -p "$LOGDIR"
fi

PREALLOC=
if [ -f /etc/debian_version ]; then
    PREALLOC="--prealloc-metadata"
fi

if [ -n "$LOGDIR" ] ; then
    VM_LOGGING="--console-log $LOGDIR/${NAME}_console.log"
else
    VM_LOGGING=""
fi
VOL_NAME="${NAME}.qcow2"

if ! virsh list --all | grep -q $NAME; then
    virsh vol-list --pool $LIBVIRT_STORAGE_POOL | grep -q $VOL_NAME &&
        virsh vol-delete $VOL_NAME --pool $LIBVIRT_STORAGE_POOL >&2
    virsh vol-create-as $LIBVIRT_STORAGE_POOL ${VOL_NAME} ${DISK}G --format qcow2 $PREALLOC >&2
    volume_path=$(virsh vol-path --pool $LIBVIRT_STORAGE_POOL $VOL_NAME)
    # Pre-touch the VM to set +C, as it can only be set on empty files.
    sudo touch "$volume_path"
    sudo chattr +C "$volume_path" || true
    $TOP_DIR/scripts/configure-vm.py \
        --bootdev network --name $NAME --image "$volume_path" \
        --arch $ARCH --cpus $CPU --memory $MEM --libvirt-nic-driver $LIBVIRT_NIC_DRIVER \
        --emulator $EMULATOR --network $BRIDGE $VM_LOGGING >&2
fi

# Send node info to NODES_FILE
mac_address=$(virsh dumpxml $NAME | grep "mac address" | head -1 | cut -d\' -f2)
switch_id=$(ip link show dev $BRIDGE | egrep -o "ether [A-Za-z0-9:]+"|sed "s/ether\ //")
echo "[$NAME]" >> $NODES_FILE
echo "mac_address=$mac_address" >> $NODES_FILE
echo "switch_info=$BRIDGE" >> $NODES_FILE
echo "port_id=$NAME" >> $NODES_FILE
echo "switch_id=$switch_id" >> $NODES_FILE
echo ""

===================
Ironic and DevStack
===================

This is a guide to configuration parameters that devstack accepts regarding
the Ironic service.

It is not yet a complete list, and only includes sections for Neutron
integration and the use / enrollment of external hardware.
Other sections will be added later.

Build User Image with DIB
=========================

diskimage-builder is a flexible suite of components for building a wide-range
of disk images, filesystem images and ramdisk images for use with OpenStack.
To build user image with DIB use IRONIC_BUILD_USER_IMAGE flag.
Additional options can be passed with DISK_IMAGE_BUILDER_OPTS,
space separated options list. Image will be uploaded to glance with
IRONIC_USER_IMAGE_NAME. If it is not set default name will be used
ir-user-$IRONIC_DEPLOY_DRIVER name.


::

    IRONIC_BUILD_USER_IMAGE=True

    IRONIC_USER_IMAGE_BUILD_OPTS="baremetal ubuntu vm"

    IRONIC_USER_IMAGE_NAME="user-image-name"


Hardware node registration in Ironic
====================================

Hardware nodes can be automatically enrolled in Ironic during devstack setup,
if the IRONIC_IPMI_NODES_FILE variable is set and refers to a valid
INI-formatted file. In this file, each section represents an Ironic Node,
and options in that section define the properties of that Node.
Here is an example:

::

    IRONIC_IPMI_NODES_FILE=/opt/stack/ironic_ipmi_nodes

and ``/opt/stack/ironic_ipmi_nodes``:

::

    [node-1]
    ipmi_address=1.2.3.4
    mac_address=aa:bb:cc:dd:ee:ff
    ipmi_username=ipmi_user
    ipmi_password=ipmi_password
    cpus=2
    memory_mb=16000
    local_gb=100
    cpu_arch=x86_64
    # Link Local Connection info
    switch_info=sw-hostname
    port_id=Gig0/3
    switch_id=00:14:f2:8c:93:c1



Link Local Connection
=====================

If Ironic is configured as above (to use a separate neutron provider network
for provisioning), and you wish to use a local virtualized switch (as opposed
to a separate physical switch) to emulate and test Neutron provider networks
with Ironic, then you should set this variable.

::

    IRONIC_USE_LINK_LOCAL=True


Ironic provision network
========================

A separate Neutron network may be used during instance provisioning. It will
be created on Devstack if the following variables are set. Ironic provision
network id will be added to ``/etc/ironic/ironic.conf`` and
``network_provider`` will be set to ``neutron_plugin``. There is an example
of ``local.conf``:

::


    # Ironic provision network name
    IRONIC_PROVISION_NETWORK_NAME=ironic-provision

    # Provision network provider type. Can be flat of vlan.
    IRONIC_PROVISION_PROVIDER_NETWORK_TYPE=vlan

    # If provider type is vlan. VLAN_ID may be specified. If it is not set,
    # vlan will be allocated dynamically.
    IRONIC_PROVISION_SEGMENTATION_ID=110

    # Allocation network pool for provision network
    IRONIC_PROVISION_ALLOCATION_POOL=start=10.0.5.10,end=10.0.5.100

    # Ironic provision subnet name. If it is not set
    # ${IRONIC_PROVISION_NETWORK_NAME}-subnet will be used
    IRONIC_PROVISION_PROVIDER_SUBNET_NAME=provision-subnet

    # Ironic provision subnet gateway. Gateway ip will be configured on
    # $OVS_PHYSICAL_BRIDGE.$IRONIC_PROVISION_SEGMENTATION_ID vlan subinterface
    # if IRONIC_PROVISION_PROVIDER_NETWORK_TYPE=='vlan'. Otherwise gateway ip
    # will be configured directly on $OVS_PHYSICAL_BRIDGE
    IRONIC_PROVISION_SUBNET_GATEWAY=10.0.5.1

    # Ironic provision subnet prefix
    IRONIC_PROVISION_SUBNET_PREFIX=10.0.5.0/24

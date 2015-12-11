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

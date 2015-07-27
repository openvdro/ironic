# Copyright 2013 UnitedStack Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import datetime

from oslo_utils import uuidutils
import pecan
from pecan import rest
from six.moves import http_client
import wsme
from wsme import types as wtypes

from ironic.api.controllers import base
from ironic.api.controllers import link
from ironic.api.controllers.v1 import collection
from ironic.api.controllers.v1 import types
from ironic.api.controllers.v1 import utils as api_utils
from ironic.api import expose
from ironic.common import exception
from ironic.common.i18n import _
from ironic import objects


_DEFAULT_RETURN_FIELDS = ('uuid', 'address')


def hide_fields_in_newer_versions(obj):
    # if requested version is < 1.16, hide portgroup fields
    if not api_utils.allow_portgroups():
        obj.portgroup_uuid = wsme.Unset
        obj.pxe_enabled = wsme.Unset
        obj.local_link_connection = wsme.Unset


class Port(base.APIBase):
    """API representation of a port.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of a port.
    """

    _node_uuid = None
    _portgroup_uuid = None

    def _get_node_uuid(self):
        return self._node_uuid

    def _set_node_uuid(self, value):
        if value and self._node_uuid != value:
            try:
                # FIXME(comstud): One should only allow UUID here, but
                # there seems to be a bug in that tests are passing an
                # ID. See bug #1301046 for more details.
                node = objects.Node.get(pecan.request.context, value)
                self._node_uuid = node.uuid
                # NOTE(lucasagomes): Create the node_id attribute on-the-fly
                #                    to satisfy the api -> rpc object
                #                    conversion.
                self.node_id = node.id
            except exception.NodeNotFound as e:
                # Change error code because 404 (NotFound) is inappropriate
                # response for a POST request to create a Port
                e.code = http_client.BAD_REQUEST  # BadRequest
                raise e
        elif value == wtypes.Unset:
            # NOTE(jroll) wtypes.Unset is falsy, block above doesn't cover it
            self._node_uuid = wtypes.Unset

    def _get_portgroup_uuid(self):
        return self._portgroup_uuid

    def _set_portgroup_uuid(self, value):
        if value and self._portgroup_uuid != value:
            if not api_utils.allow_portgroups():
                self._portgroup_uuid = wtypes.Unset
                return
            try:
                portgroup = objects.Portgroup.get(pecan.request.context, value)
                if portgroup.node_id != self.node_id:
                    raise exception.BadRequest(_('Port can not be added to a '
                                                 'portgroup belonging to a '
                                                 'different node.'))
                self._portgroup_uuid = portgroup.uuid
                # NOTE(lucasagomes): Create the portgroup_id attribute
                #                    on-the-fly to satisfy the api ->
                #                    rpc object conversion.
                self.portgroup_id = portgroup.id
            except exception.PortgroupNotFound as e:
                # Change error code because 404 (NotFound) is inappropriate
                # response for a POST request to create a Port
                e.code = http_client.BAD_REQUEST  # BadRequest
                raise e
        elif value == wtypes.Unset:
            self._portgroup_uuid = wtypes.Unset
        elif value is None and api_utils.allow_portgroups():
            # This is to output portgroup_uuid field if API version allows this
            self._portgroup_uuid = None

    uuid = types.uuid
    """Unique UUID for this port"""

    address = wsme.wsattr(types.macaddress, mandatory=True)
    """MAC Address for this port"""

    extra = {wtypes.text: types.jsontype}
    """This port's meta data"""

    node_uuid = wsme.wsproperty(types.uuid, _get_node_uuid, _set_node_uuid,
                                mandatory=True)
    """The UUID of the node this port belongs to"""

    portgroup_uuid = wsme.wsproperty(types.uuid, _get_portgroup_uuid,
                                     _set_portgroup_uuid, mandatory=False)
    """The UUID of the portgroup this port belongs to"""

    pxe_enabled = types.boolean
    """Indicates whether pxe is enabled or disabled on the node."""

    local_link_connection = types.locallinkconnectiontype
    """The port binding profile for each portgroup"""

    links = wsme.wsattr([link.Link], readonly=True)
    """A list containing a self link and associated port links"""

    def __init__(self, **kwargs):
        self.fields = []
        fields = list(objects.Port.fields)
        # NOTE(lucasagomes): node_uuid is not part of objects.Port.fields
        #                    because it's an API-only attribute
        fields.append('node_uuid')
        # NOTE: portgroup_uuid is not part of objects.Port.fields
        #                    because it's an API-only attribute
        fields.append('portgroup_uuid')
        for field in fields:
            # Add fields we expose.
            if hasattr(self, field):
                self.fields.append(field)
                setattr(self, field, kwargs.get(field, wtypes.Unset))

        # NOTE(lucasagomes): node_id is an attribute created on-the-fly
        # by _set_node_uuid(), it needs to be present in the fields so
        # that as_dict() will contain node_id field when converting it
        # before saving it in the database.
        self.fields.append('node_id')
        setattr(self, 'node_uuid', kwargs.get('node_id', wtypes.Unset))

        # NOTE: portgroup_id is an attribute created on-the-fly
        # by _set_portgroup_uuid(), it needs to be present in the fields so
        # that as_dict() will contain portgroup_id field when converting it
        # before saving it in the database.
        self.fields.append('portgroup_id')
        setattr(self, 'portgroup_uuid', kwargs.get('portgroup_id',
                                                   wtypes.Unset))

    @staticmethod
    def _convert_with_links(port, url, fields=None):
        # NOTE(lucasagomes): Since we are able to return a specified set of
        # fields the "uuid" can be unset, so we need to save it in another
        # variable to use when building the links
        port_uuid = port.uuid
        if fields is not None:
            port.unset_fields_except(fields)

        # never expose the node_id attribute
        port.node_id = wtypes.Unset

        # never expose the portgroup_id attribute
        port.portgroup_id = wtypes.Unset

        port.links = [link.Link.make_link('self', url,
                                          'ports', port_uuid),
                      link.Link.make_link('bookmark', url,
                                          'ports', port_uuid,
                                          bookmark=True)
                      ]
        return port

    @classmethod
    def convert_with_links(cls, rpc_port, fields=None):
        port = Port(**rpc_port.as_dict())

        if fields is not None:
            api_utils.check_for_invalid_fields(fields, port.as_dict())

        hide_fields_in_newer_versions(port)

        return cls._convert_with_links(port, pecan.request.public_url,
                                       fields=fields)

    @classmethod
    def sample(cls, expand=True):
        sample = cls(uuid='27e3153e-d5bf-4b7e-b517-fb518e17f34c',
                     address='fe:54:00:77:07:d9',
                     extra={'foo': 'bar'},
                     created_at=datetime.datetime.utcnow(),
                     updated_at=datetime.datetime.utcnow(),
                     pxe_enabled=True,
                     local_link_connection={
                         'switch_info': 'host', 'port_id': 'Gig0/1',
                         'switch_id': 'aa:bb:cc:dd:ee:ff'})
        # NOTE(lucasagomes): node_uuid getter() method look at the
        # _node_uuid variable
        sample._node_uuid = '7ae81bb3-dec3-4289-8d6c-da80bd8001ae'
        sample._portgroup_uuid = '037d9a52-af89-4560-b5a3-a33283295ba2'
        fields = None if expand else _DEFAULT_RETURN_FIELDS
        return cls._convert_with_links(sample, 'http://localhost:6385',
                                       fields=fields)


class PortPatchType(types.JsonPatchType):
    _api_base = Port


class PortCollection(collection.Collection):
    """API representation of a collection of ports."""

    ports = [Port]
    """A list containing ports objects"""

    def __init__(self, **kwargs):
        self._type = 'ports'

    @staticmethod
    def convert_with_links(rpc_ports, limit, url=None, fields=None, **kwargs):
        collection = PortCollection()
        collection.ports = [Port.convert_with_links(p, fields=fields)
                            for p in rpc_ports]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection

    @classmethod
    def sample(cls):
        sample = cls()
        sample.ports = [Port.sample(expand=False)]
        return sample


class PortsController(rest.RestController):
    """REST controller for Ports."""

    from_portgroups = False
    """A flag to indicate if the requests to this controller are coming
    from the top-level resource Portgroups."""

    from_nodes = False
    """A flag to indicate if the requests to this controller are coming
    from the top-level resource Nodes."""

    _custom_actions = {
        'detail': ['GET'],
    }

    invalid_sort_key_list = ['extra', 'local_link_connection']

    portgroup_fields = ['portgroup_uuid', 'pxe_enabled',
                        'local_link_connection']

    def _get_ports_collection(self, node_or_portgroup_ident, address,
                              portgroup_ident, marker, limit, sort_key,
                              sort_dir, resource_url=None, fields=None):
        if self.from_nodes and not node_or_portgroup_ident:
            raise exception.MissingParameterValue(
                _("Node identifier not specified."))

        if self.from_portgroups:
            if not api_utils.allow_portgroups():
                raise exception.NotFound()
            # Note(vdrok): This is a workaround for the case when
            # GET /portgroups/ident/ports is called. In this case portgroup
            # ident is still written to node parameter.
            if not node_or_portgroup_ident:
                raise exception.MissingParameterValue(
                    _("Portgroup identifier not specified."))
            if portgroup_ident:
                # NOTE(vdrok): this happens in the case of
                # GET /portgroups/ident/ports?portgroup=other_ident
                raise exception.Invalid(_(
                    'Portgroup identifier should be specified only once!'))
            portgroup_ident = node_or_portgroup_ident
            # NOTE(vdrok): node will be overwritten, so requests like
            # GET /portgroups/ident/ports?node=node_ident won't work properly
            # (they don't make much sense anyway)
            node_ident = None
        else:
            node_ident = node_or_portgroup_ident

        limit = api_utils.validate_limit(limit)
        sort_dir = api_utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.Port.get_by_uuid(pecan.request.context,
                                                  marker)

        if sort_key in self.invalid_sort_key_list:
            raise exception.InvalidParameterValue(
                _("The sort_key value %(key)s is an invalid field for "
                  "sorting") % {'key': sort_key})

        if node_ident:
            # FIXME(comstud): Since all we need is the node ID, we can
            #                 make this more efficient by only querying
            #                 for that column. This will get cleaned up
            #                 as we move to the object interface.
            node = api_utils.get_rpc_node(node_ident)
            ports = objects.Port.list_by_node_id(pecan.request.context,
                                                 node.id, limit, marker_obj,
                                                 sort_key=sort_key,
                                                 sort_dir=sort_dir)
        elif portgroup_ident:
            # FIXME: Since all we need is the portgroup ID, we can
            #                 make this more efficient by only querying
            #                 for that column. This will get cleaned up
            #                 as we move to the object interface.
            portgroup = api_utils.get_rpc_portgroup(portgroup_ident)
            ports = objects.Port.list_by_portgroup_id(pecan.request.context,
                                                      portgroup.id, limit,
                                                      marker_obj,
                                                      sort_key=sort_key,
                                                      sort_dir=sort_dir)
        elif address:
            ports = self._get_ports_by_address(address)
        else:
            ports = objects.Port.list(pecan.request.context, limit,
                                      marker_obj, sort_key=sort_key,
                                      sort_dir=sort_dir)

        return PortCollection.convert_with_links(ports, limit,
                                                 url=resource_url,
                                                 fields=fields,
                                                 sort_key=sort_key,
                                                 sort_dir=sort_dir)

    def _get_ports_by_address(self, address):
        """Retrieve a port by its address.

        :param address: MAC address of a port, to get the port which has
                        this MAC address.
        :returns: a list with the port, or an empty list if no port is found.

        """
        try:
            port = objects.Port.get_by_address(pecan.request.context, address)
            return [port]
        except exception.PortNotFound:
            return []

    @expose.expose(PortCollection, types.uuid_or_name, types.uuid,
                   types.macaddress, types.uuid_or_name, types.uuid, int,
                   wtypes.text, wtypes.text, types.listtype)
    def get_all(self, node=None, node_uuid=None, address=None, portgroup=None,
                marker=None, limit=None, sort_key='id', sort_dir='asc',
                fields=None):
        """Retrieve a list of ports.

        Note that the 'node_uuid' interface is deprecated in favour
        of the 'node' interface

        :param node: UUID or name of a node, to get only ports for that
                           node.
        :param node_uuid: UUID of a node, to get only ports for that
                           node.
        :param address: MAC address of a port, to get the port which has
                        this MAC address.
        :param portgroup: UUID or name of a portgroup, to get only ports
                           for that portgroup.
        :param marker: pagination marker for large data sets.
        :param limit: maximum number of resources to return in a single result.
        :param sort_key: column to sort results by. Default: id.
        :param sort_dir: direction to sort. "asc" or "desc". Default: asc.
        :param fields: Optional, a list with a specified set of fields
            of the resource to be returned.
        :raises: NotAcceptable
        """
        api_utils.check_allow_specify_fields(fields)
        if portgroup and not api_utils.allow_portgroups():
            raise exception.NotAcceptable()
        if (fields and not api_utils.allow_portgroups() and
                set(fields).intersection(self.portgroup_fields)):
            raise exception.NotAcceptable()

        if fields is None:
            fields = _DEFAULT_RETURN_FIELDS

        if not node_uuid and node:
            # We're invoking this interface using positional notation, or
            # explicitly using 'node'.  Try and determine which one.
            # Make sure only one interface, node or node_uuid is used
            if (not api_utils.allow_node_logical_names() and
                    not uuidutils.is_uuid_like(node)):
                raise exception.NotAcceptable()

        return self._get_ports_collection(node_uuid or node, address,
                                          portgroup, marker, limit, sort_key,
                                          sort_dir, fields=fields)

    @expose.expose(PortCollection, types.uuid_or_name, types.uuid,
                   types.macaddress, types.uuid_or_name, types.uuid, int,
                   wtypes.text, wtypes.text)
    def detail(self, node=None, node_uuid=None, address=None, portgroup=None,
               marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of ports with detail.

        Note that the 'node_uuid' interface is deprecated in favour
        of the 'node' interface

        :param node: UUID or name of a node, to get only ports for that
                     node.
        :param node_uuid: UUID of a node, to get only ports for that
                          node.
        :param address: MAC address of a port, to get the port which has
                        this MAC address.
        :param portgroup: UUID or name of a portgroup, to get only ports
                           for that portgroup.
        :param marker: pagination marker for large data sets.
        :param limit: maximum number of resources to return in a single result.
        :param sort_key: column to sort results by. Default: id.
        :param sort_dir: direction to sort. "asc" or "desc". Default: asc.
        :raises: NotAcceptable, HTTPNotFound
        """

        if portgroup and not api_utils.allow_portgroups():
            raise exception.NotAcceptable()

        if not node_uuid and node:
            # We're invoking this interface using positional notation, or
            # explicitly using 'node'.  Try and determine which one.
            # Make sure only one interface, node or node_uuid is used
            if (not api_utils.allow_node_logical_names() and
                    not uuidutils.is_uuid_like(node)):
                raise exception.NotAcceptable()

        # NOTE(lucasagomes): /detail should only work against collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "ports":
            raise exception.HTTPNotFound

        resource_url = '/'.join(['ports', 'detail'])
        return self._get_ports_collection(node_uuid or node, address,
                                          portgroup, marker, limit, sort_key,
                                          sort_dir, resource_url)

    @expose.expose(Port, types.uuid, types.listtype)
    def get_one(self, port_uuid, fields=None):
        """Retrieve information about the given port.

        :param port_uuid: UUID of a port.
        :param fields: Optional, a list with a specified set of fields
            of the resource to be returned.
        :raises: NotAcceptable
        """
        if self.from_nodes or self.from_portgroups:
            raise exception.OperationNotPermitted

        api_utils.check_allow_specify_fields(fields)

        rpc_port = objects.Port.get_by_uuid(pecan.request.context, port_uuid)
        return Port.convert_with_links(rpc_port, fields=fields)

    @expose.expose(Port, body=Port, status_code=http_client.CREATED)
    def post(self, port):
        """Create a new port.

        :param port: a port within the request body.
        :raises: NotAcceptable
        """
        if self.from_nodes or self.from_portgroups:
            raise exception.OperationNotPermitted

        pdict = port.as_dict()
        if not api_utils.allow_portgroups():
            if set(pdict).intersection(self.portgroup_fields):
                raise exception.NotAcceptable()

        new_port = objects.Port(pecan.request.context,
                                **pdict)

        new_port.create()
        # Set the HTTP Location Header
        pecan.response.location = link.build_url('ports', new_port.uuid)
        return Port.convert_with_links(new_port)

    @wsme.validate(types.uuid, [PortPatchType])
    @expose.expose(Port, types.uuid, body=[PortPatchType])
    def patch(self, port_uuid, patch):
        """Update an existing port.

        :param port_uuid: UUID of a port.
        :param patch: a json PATCH document to apply to this port.
        """
        if self.from_nodes or self.from_portgroups:
            raise exception.OperationNotPermitted
        if not api_utils.allow_portgroups():
            for field in self.portgroup_fields:
                if api_utils.get_patch_value(patch, '/%s' % field):
                    raise exception.NotAcceptable()

        rpc_port = objects.Port.get_by_uuid(pecan.request.context, port_uuid)
        try:
            port_dict = rpc_port.as_dict()
            # NOTE(lucasagomes):
            # 1) Remove node_id because it's an internal value and
            #    not present in the API object
            # 2) Add node_uuid
            port_dict['node_uuid'] = port_dict.pop('node_id', None)
            # NOTE(vsaienko):
            # 1) Remove portgroup_id because it's an internal value and
            #    not present in the API object
            # 2) Add portgroup_uuid
            port_dict['portgroup_uuid'] = port_dict.pop('portgroup_id', None)
            port = Port(**api_utils.apply_jsonpatch(port_dict, patch))
        except api_utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # no exception handling needed as you know that portgroup_uuid
        # attr exists
        new_portgroup_uuid = port.portgroup_uuid
        if new_portgroup_uuid == wsme.Unset:
            rpc_port.portgroup_id = None
        else:
            new_portgroup = objects.Portgroup.get_by_uuid(
                pecan.request.context,
                new_portgroup_uuid)
            if rpc_port.portgroup_id != new_portgroup.id:
                rpc_port.portgroup_id = new_portgroup.id

        # Update only the fields that have changed
        for field in objects.Port.fields:
            try:
                patch_val = getattr(port, field)
            except AttributeError:
                # Ignore fields that aren't exposed in the API
                continue
            if patch_val == wtypes.Unset:
                patch_val = None
            if rpc_port[field] != patch_val:
                rpc_port[field] = patch_val

        rpc_node = objects.Node.get_by_id(pecan.request.context,
                                          rpc_port.node_id)
        topic = pecan.request.rpcapi.get_topic_for(rpc_node)

        new_port = pecan.request.rpcapi.update_port(
            pecan.request.context, rpc_port, topic)

        return Port.convert_with_links(new_port)

    @expose.expose(None, types.uuid, status_code=http_client.NO_CONTENT)
    def delete(self, port_uuid):
        """Delete a port.

        :param port_uuid: UUID of a port.
        """
        if self.from_nodes or self.from_portgroups:
            raise exception.OperationNotPermitted
        rpc_port = objects.Port.get_by_uuid(pecan.request.context,
                                            port_uuid)
        rpc_node = objects.Node.get_by_id(pecan.request.context,
                                          rpc_port.node_id)
        topic = pecan.request.rpcapi.get_topic_for(rpc_node)
        pecan.request.rpcapi.destroy_port(pecan.request.context,
                                          rpc_port, topic)

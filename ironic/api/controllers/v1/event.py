# Copyright 2018 Mirantis Inc
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

from oslo_log import log

import pecan
from pecan import rest
import six
from six.moves import http_client
from wsme import types as wtypes

from ironic.api.controllers.v1 import collection
from ironic.api.controllers.v1 import types
from ironic.api.controllers.v1 import utils as api_utils
from ironic.api import expose
from ironic.common import exception
from ironic import objects
from ironic.drivers import base as drivers_base

LOG = log.getLogger(__name__)


class Evt(wtypes.Base):
    interface = wtypes.wsattr(
        wtypes.Enum(six.text_type, *drivers_base.ALL_INTERFACES),
        mandatory=True)
    payload = wtypes.wsattr({wtypes.text: types.jsontype}, mandatory=True)
    identifier = wtypes.wsattr(types.uuid, mandatory=True)

    # port_id = wtypes.wsattr(types.uuid, mandatory=True)
    # device_id = wtypes.wsattr(types.uuid, mandatory=True)
    # status = wtypes.wsattr(
    #     wtypes.Enum(six.text_type,
    #                 'ACTIVE', 'DOWN', 'ERROR', 'BUILD', 'DELETED'),
    #     mandatory=True)
    # mac_address = wtypes.wsattr(types.macaddress, mandatory=True)
    # event_type = wtypes.wsattr(six.text_type, mandatory=True)

    def as_dict(self):
        return {'interface': self.interface, 'payload': self.payload}


class EvtCollection(collection.Collection):

    events = [Evt]


class EventsController(rest.RestController):

    @expose.expose(None, body=EvtCollection, status_code=http_client.ACCEPTED)
    def post(self, evts):
        LOG.debug("Recieved external events: %s" % evts)
        for event in evts.events:
            identifier = event.identifier
            for method in ('get_by_uuid', 'get_by_instance_uuid'):
                try:
                    rpc_node = getattr(objects.Node, method)(
                        pecan.request.context, identifier)
                    break
                except exception.NodeNotFound:
                    rpc_node = None
            if not rpc_node:
                return
            topic = pecan.request.rpcapi.get_topic_for(rpc_node)
            pecan.request.rpcapi.process_event(
                pecan.request.context, rpc_node.uuid, event.as_dict(), topic)

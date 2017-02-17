# Copyright 2016 Mirantis Inc
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

from oslo_config import cfg
from oslo_log import log

import pecan
from pecan import rest
import six
from six.moves import http_client
from wsme import types as wtypes

from ironic.api.controllers.v1 import types
from ironic.api.controllers.v1 import utils as api_utils
from ironic.api import expose

CONF = cfg.CONF
LOG = log.getLogger(__name__)


class Evt(wtypes.Base):
    port_id = wtypes.wsattr(types.uuid, mandatory=True)
    device_id = wtypes.wsattr(types.uuid, mandatory=True)
    status = wtypes.wsattr(
        wtypes.Enum(six.text_type, 'ACTIVE', 'DOWN', 'ERROR', 'BUILD'),
        mandatory=True)
    mac_address = wtypes.wsattr(types.macaddress, mandatory=True)

    def as_dict(self):
        return {'port_id': self.port_id, 'device_id': self.device_id,
                'status': self.status, 'mac_address': self.mac_address}


class EventsController(rest.RestController):

    @expose.expose(None, body=[Evt], status_code=http_client.ACCEPTED)
    def post(self, events):
        LOG.debug("Recieved external events: %s" % events)
        for net_event in events:
            mac_address = net_event.mac_address
            try:
                node = pecan.request.dbapi.get_node_by_port_addresses(
                    [mac_address])
                rpc_node = api_utils.get_rpc_node(node.uuid)
            except Exception:
                return
            topic = pecan.request.rpcapi.get_topic_for(rpc_node)
            pecan.request.rpcapi.process_network_event(
                pecan.request.context, rpc_node.uuid, net_event.as_dict(), topic)

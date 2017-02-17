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


class NeutronEventHandler(object):

    def configure_tenant_networks(self, port_list):
        # At least one should be ACTIVE
        for port in port_list:
            if port.internal_info['network_status'] == 'ACTIVE':
                return True
        return False

    def unconfigure_tenant_networks(self, port_list):
        # All should be DOWN
        for port in port_list:
            if port.internal_info['network_status'] == 'ACTIVE':
                return False
        return True

    def add_provisioning_network(self, port_list):
        # At least one should be ACTIVE
        for port in port_list:
            if port.internal_info['network_status'] == 'ACTIVE':
                return True
        return False

    def remove_provisioning_network(self, port_list):
        """All should be deleted/DOWN"""

    def add_cleaning_network(self, port_list):
        # At least one should be ACTIVE
        for port in port_list:
            if port.internal_info['network_status'] == 'ACTIVE':
                return True
        return False

    def remove_cleaning_network(self, port_list):
        """All should be deleted/DOWN"""

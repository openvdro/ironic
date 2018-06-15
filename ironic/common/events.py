import eventlet
from oslo_log import log
from oslo_concurrency import lockutils

from ironic.common import exception
from ironic.conf import CONF
from ironic import objects

LOG = log.getLogger(__name__)
NEUTRON_SEMAPHORES = {}


def cleanup_network_status(task):
    """Cleanup network port and portgroup status.

    :param task: A TaskManager instance.
    """
    for obj in task.ports + task.portgroups:
        internal_info = obj.internal_info
        internal_info.pop('network_status', None)
        obj.internal_info = internal_info
        obj.save()


def get_network_status(task, port_like_objects, desired_status='ACTIVE',
                       success_strategy='all'):
    """Returns network status for ports and port groups.

    :param port_like_objects: List of ports and port groups.
    :returns: A list with port/port group objects that failed to update.
    """
    failures = []
    for obj in port_like_objects:
        obj.refresh()
        network_status = obj.internal_info.get('network_status', None)
        LOG.debug("Network status for port %(port_id)s is %(status)s",
                  {'port_id': obj.uuid, 'status': network_status})
        if network_status != desired_status:
            failures.append(obj.uuid)
        elif success_strategy == 'any':
            return []
    return failures


def create_network_status_semaphore_for_node(node_uuid, vif_count, vif_ids, desired_status):
    """Creates a network status semaphore object for node.

    :param node_uuid: UUID of ironic node.
    :param vif_count: number of ports we're waiting for to change.
    """
    net_status = {'semaphore': eventlet.semaphore.Semaphore(0),
                  'waiting_for': vif_count,
                  'waiting_for_ids': vif_ids,
                  'desired_status': desired_status,
                  'error_ids': set()}
    NEUTRON_SEMAPHORES[node_uuid] = net_status
    return net_status


class EventWaiter(object):

    def __init__(self, desired_status, success_strategy, filter_function):
        self.desired_status = desired_status
        self.success_strategy = success_strategy
        self.filter_function = filter_function

    @staticmethod
    def validate_event_payload(payload):
        pass

    @staticmethod
    def process_incoming_event(task, context, node_uuid, payload):
        pass

    @staticmethod
    def validate_wait(task):
        pass

    def pre_wait(self, task):
        pass

    def wait(self, task, waiter):
        pass

    def post_wait(self, task):
        pass

    def on_wait_error(self, task, error):
        pass


class NeutronEventWaiter(EventWaiter):

    @staticmethod
    def validate_event_payload(payload):
        required_fields = ['mac_address', 'status', 'port_id']
        for field in required_fields:
            if field not in payload:
                raise exception.NetworkError('Some fields in event payload missing')

    @staticmethod
    def process_incoming_event(task, context, node_uuid, payload):
        port = [p for p in task.ports if p.address == payload['mac_address']][0]
        LOG.debug("Received external event for port %(port_id)s with "
                  "status %(status)s. Current VIF is %(vif)s",
                  {'port_id': port.uuid, 'status': payload['status'],
                   'vif': task.driver.network.get_current_vif(task, port)})
        semaphore = NEUTRON_SEMAPHORES.get(node_uuid)
        if semaphore and semaphore['waiting_for'] > 0:
            if semaphore.get('join_future'):
                semaphore['join_future'].result()
            port.refresh()

            @lockutils.synchronized('neutron-event-%s' % node_uuid)
            def _synchronized_processing():
                if payload['status'] == semaphore['desired_status']:
                    if (task.driver.network.get_current_vif(task, port) == payload['port_id'] or
                            payload['port_id'] in semaphore['waiting_for_ids']):
                        LOG.debug('we are waiting for this event! port %(port)s status set, '
                                  'internal info is %(info)s', {'port': port.uuid, 'info': port.internal_info})
                        semaphore['waiting_for'] -= 1
                        try:
                            semaphore['error_ids'].remove(payload['port_id'])
                        except KeyError:
                            pass
                else:
                    semaphore['error_ids'].add(payload['port_id'])
                if semaphore['waiting_for'] == 0:
                    semaphore['semaphore'].release()

            _synchronized_processing()

    @staticmethod
    def validate_wait(task):
        return CONF.neutron.events_enabled

    def pre_wait(self, task):
        self.filtered_objects = self.filter_function(task)
        if self.filter_function.__name__ == 'tenant_net_unbind_async_filter':
            #import rpdb; rpdb.set_trace()
            pass
        vif_ids = [task.driver.network.get_current_vif(task, obj) for obj in self.filtered_objects]
        n_status = create_network_status_semaphore_for_node(
            task.node.uuid, len(vif_ids), vif_ids, self.desired_status)
        return n_status

    def wait(self, task, waiter):
        LOG.debug("Waiting for Neutron port status change.")
        events_timeout = CONF.neutron.events_timeout
        if waiter['waiting_for']:
            task.process_event('wait')
            waiter['semaphore'].acquire(timeout=events_timeout)

    def process_event_join(self, waiter, future):
        waiter['join_future'] = future

    def post_wait(self, task):
        #import rpdb; rpdb.set_trace()
        objs = self.filtered_objects
        semaphore = NEUTRON_SEMAPHORES.pop(task.node.uuid)
        failures = semaphore['error_ids']
        if len(semaphore['error_ids']) < len(objs) and self.success_strategy == 'any':
            failures = []
        if not failures:
            if objs:
                task.process_event('resume')
        else:
            task.process_event('fail')
            raise exception.NetworkError('The following VIFs did not get to the '
                                         'desired status: %s' % failures)

    def on_wait_error(self, task, error):
        failures = NEUTRON_SEMAPHORES.pop(task.node.uuid, {}).get('error_ids')
        task.process_event('fail')
        if failures:
            error += ' The following VIFs did not get to the desired status: %s' % failures
        raise exception.NetworkError(error)

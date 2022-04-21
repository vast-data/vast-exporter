#!/usr/local/bin/python3
import argparse
import logging
import urllib3
import http
import json
import time
import os
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, Summary, Counter, REGISTRY
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--user', required=True)
    parser.add_argument('--password', required=True)
    parser.add_argument('--address', required=True)
    parser.add_argument('--cert-file', required=False)
    parser.add_argument('--cert-server-name', required=False)
    parser.add_argument('--port', default=8000, type=int)

    return parser.parse_args()

class RESTFailure(Exception): pass

class VASTClient(object):
    def __init__(self, user, password, address, cert_file=None, cert_server_name=None):
        self._user = user
        self._password = password
        self._address = address
        self._cert_file = cert_file
        self._cert_server_name = cert_server_name

    vms_latency = Summary('vast_collector_vms_latency', 'VAST VMS Request Time')

    def _request(self, method, url, params):
        if self._cert_file:
            pm = urllib3.PoolManager(ca_certs=self._cert_file, server_hostname=self._cert_server_name)
        else:
            pm = urllib3.PoolManager(cert_reqs='CERT_NONE')
        headers = urllib3.make_headers(basic_auth=self._user + ':' + self._password)
        with self.vms_latency.time():
            r = pm.request(method, 'https://{}/api/{}/'.format(self._address, url), headers=headers, fields=params)
        if r.status != http.HTTPStatus.OK:
            raise RESTFailure(f'Response failed with error {r.status} and message {r.data}')
        return json.loads(r.data.decode('utf-8'))

    def get(self, url, params=None):
        return self._request('GET', url, params)

def extract_keys(obj, keys):
    return [str(obj[k]) for k in keys]

class MetricDescriptor(object):
    def __init__(self, class_name, properties=None, histograms=None, tags=None, time_frame='2m'):
        self.class_name = class_name
        self.time_frame = time_frame
        self.properties = properties or []
        self.histograms = histograms or []
        for i in self.histograms:
            self.properties.append(i + '__num_samples')
            self.properties.append(i + '__sum')
        self.tags = tags or []
        assert len(self.tags) <= 1, "Collection of multi-tag metrics isn't supported yet"
        self.property_to_fqn = {}
        self.fqn_to_tag_value = {}
        if self.tags:
            for i in self.properties:
                self.property_to_fqn[i] = l = []
                for tag, values in self.tags.items():
                    for value in values:
                        fqn = f'{class_name},{tag}={value},{i}'
                        l.append(fqn)
                        self.fqn_to_tag_value[fqn] = value
        else:
            for i in self.properties:
                self.property_to_fqn[i] = [f'{class_name},{i}']
        self.fqns = [i for l in self.property_to_fqn.values() for i in l]
        
# read_latency is internal because of a bug (to be fixed soon), meantime and until clusters catch up
# we must fetch it separately from the rest as we can't combine external+internal in a single query.
PROTO_METRICS_TAGS = {'proto_name': ['NFSCommon', 'NFS4Common', 'SMBCommon', 'S3Common', 'ProtoAll', 'ReplicationCommon']}
DESCRIPTORS = [MetricDescriptor(class_name='ProtoMetrics',
                                histograms=['read_latency'],
                                tags=PROTO_METRICS_TAGS),
               MetricDescriptor(class_name='ProtoMetrics',
                                histograms=['write_latency'],
                                tags=PROTO_METRICS_TAGS),
               MetricDescriptor(class_name='ProtoMetrics',
                                histograms=['read_size', 'write_size'], # don't add metrics here before 4.3, uwsgi accepts no more than 4k
                                tags=PROTO_METRICS_TAGS),
               MetricDescriptor(class_name='ProtoConnectionMetrics',
                                properties=['s3_conn_pool',
                                            's3_http_pool',
                                            's3_https_pool',
                                            'nfs3_tcp_pool',
                                            'nfs3_udp_pool',
                                            'smb_conn_pool',
                                            's3_conn_rejected',
                                            'nfs_conn_rejected',
                                            'smb_conn_rejected']),
               MetricDescriptor(class_name='S3Metrics',
                                time_frame='8m',
                                properties=['get_object',
                                            'put_object',
                                            'multi_part_upload',
                                            'multi_part_upload_fallback',
                                            'cmd_parse_failed',
                                            'cmd_not_supported',
                                            'cmd_errors',
                                            'bad_http_request',
                                            'bad_https_request']),
               MetricDescriptor(class_name='S3Metrics',
                                time_frame='8m',
                                histograms=['get_service',
                                            'put_bucket',
                                            'delete_bucket',
                                            'get_bucket',
                                            'get_bucket_location',
                                            'head_bucket',
                                            'delete_object',
                                            'delete_objects',
                                            'head_object',
                                            'put_bucket_acl',
                                            'put_object_acl',
                                            'get_bucket_acl',
                                            'get_object_acl',
                                            'put_object_copy',
                                            'initiate_mpu',
                                            'complete_mpu']),
               MetricDescriptor(class_name='NfsMetrics',
                                histograms=['nfs_create_latency',
                                            'nfs_mkdir_latency',
                                            'nfs_mknod_latency',
                                            'nfs_symlink_latency',
                                            'nfs_setattr_latency',
                                            'nfs_remove_latency',
                                            'nfs_rmdir_latency',
                                            'nfs_rename_latency',
                                            'nfs_link_latency',
                                            'nfs_commit_latency',
                                            'nfs_getattr_latency']),
               MetricDescriptor(class_name='NfsMetrics',
                                histograms=['nfs_getattr_latency',
                                            'nfs_lookup_latency',
                                            'nfs_access_latency',
                                            'nfs_readlink_latency',
                                            'nfs_readdir_latency',
                                            'nfs_readdirplus_latency',
                                            'nfs_fsstat_latency',
                                            'nfs_fsinfo_latency',
                                            'nfs_pathconf_latency',
                                            'nfs_read_latency',
                                            'nfs_write_latency'])]

class WrappedGauge(GaugeMetricFamily):
    def __init__(self, name, help_text, labels, cluster_name):
        super(WrappedGauge, self).__init__('vast_' + name, help_text, labels=['cluster'] + labels)
        self._cluster_name = cluster_name

    def add_metric(self, labels, value):
        labels = list(labels)
        labels.insert(0, self._cluster_name)
        return super(WrappedGauge, self).add_metric(labels, value)

class VASTCollector(object):
    def __init__(self, client):
        self._client = client
        self._cluster_name = None
        self._node_id_to_hostname = {'cnode':{}, 'dnode': {}}
        self._node_ip_to_hostname = {}

    collection_timer = Summary('vast_collector_latency', 'Total collection time')
    error_counter = Counter('vast_collector_errors', 'Errors raised during collection')

    def collect(self):
        with self.collection_timer.time():
            for collector in [self._collect_cluster(), # must be first, initializes the cluster name (required by all)
                              self._collect_physical(), # must be second, for collecting cnode host names (required by metrics)
                              self._collect_logical(),
                              self._collect_metrics()]:
                try:
                    yield from collector
                except Exception as e:
                    self.error_counter.inc()
                    logger.exception(f'caught exception while collecting metrics: {e}')

    def _describe_metrics(self):
        # metrics description
        print(self._client.get('metrics'))
        # all monitors
        print(self._client.get('monitors'))
        # example monitor
        print(self._client.get('monitors/2/query', {'granularity': 'seconds', 'time_frame': '2m'}))
    
    def _create_gauge(self, name, help_text, value):
        gauge = GaugeMetricFamily('vast_' + name, help_text, labels=['cluster'])
        gauge.add_metric([self._cluster_name], value)
        return gauge

    def _create_labeled_gauge(self, name, help_text, labels):
        return WrappedGauge(name, help_text, labels, self._cluster_name)

    def _get_metrics(self, scope, metric_names, time_frame):
        properties = [('prop_list', metric) for metric in metric_names]
        result = self._client.get('monitors/ad_hoc_query', [('object_type', scope),
                                                            ('time_frame', time_frame)] + properties)
        rows = result['data']
        # take the latest row per per object id
        index_of_id = result['prop_list'].index('object_id')
        seen = set()
        unique_rows = []
        for row in reversed(rows):
            if row[index_of_id] not in seen:
                seen.add(row[index_of_id])
                unique_rows.append(row)
        columns = zip(*unique_rows)
        return dict(zip(result['prop_list'], columns))
            
    def _collect_metrics(self):
        gauges = {}
        for descriptor in DESCRIPTORS:
            for scope in ['cluster', 'cnode']:
                table = self._get_metrics(scope, descriptor.fqns, descriptor.time_frame)
                if not table:
                    logger.error(f'Failed requesting metrics on {scope} for {descriptor.class_name}: {descriptor.fqns}')
                    self.error_counter.inc()
                    continue
                for prop, fqns in descriptor.property_to_fqn.items():
                    valid_name = f'{scope}_metrics_{descriptor.class_name}_{prop.replace("__", "_").replace("num_samples", "count")}'
                    try:
                        gauge = gauges[valid_name]
                    except KeyError:
                        labels = ['cnode_id', 'hostname'] if scope == 'cnode' else []
                        gauge = self._create_labeled_gauge(valid_name, '', labels=labels + list(descriptor.tags))
                        gauges[valid_name] = gauge
                    for fqn in fqns:
                        for (object_id, value) in zip(table['object_id'], table[fqn]):
                            labels = [str(object_id), self._node_id_to_hostname['cnode'].get(object_id, 'deleted')] if scope == 'cnode' else []
                            try:
                                labels.append(descriptor.fqn_to_tag_value[fqn])
                            except KeyError:
                                pass
                            gauge.add_metric(labels, value)
        
        yield from gauges.values()

    def _collect_cluster(self):
        cluster, = self._client.get('clusters')
        self._cluster_name = cluster['name']
        yield self._create_gauge('cluster_physical_space', 'Cluster Physical Space', cluster['physical_space'])
        yield self._create_gauge('cluster_logical_space', 'Cluster Logical Space', cluster['logical_space'])
        yield self._create_gauge('cluster_physical_space_in_use', 'Cluster Physical Space In Use', cluster['physical_space_in_use'])
        yield self._create_gauge('cluster_logical_space_in_use', 'Cluster Logical Space In Use', cluster['logical_space_in_use'])
        yield self._create_gauge('cluster_auxiliary_space_in_use', 'Cluster Auxiliary Space In Use', cluster['auxiliary_space_in_use'])
        yield self._create_gauge('cluster_drr', 'Cluster Data Reduction Ratio', cluster['drr'])
        yield self._create_gauge('cluster_online', 'Cluster Online', cluster['state'] == 'ONLINE')
        yield self._create_gauge('nvram_raid_healthy', 'Nvram RAID Healthy', cluster['nvram_raid_state'] in ['HEALTHY', 'REBALANCE'])
        yield self._create_gauge('ssd_raid_healthy', 'Ssd RAID Healthy', cluster['ssd_raid_state'] in ['HEALTHY', 'REBALANCE'])
        yield self._create_gauge('memory_raid_healthy', 'Memory RAID Healthy', cluster['memory_raid_state'] in ['HEALTHY', 'REBALANCE'])

    def _collect_physical(self):
        node_labels = ['name', 'guid', 'hostname', 'id']
        for node_type in ['cnode', 'dnode']:
            nodes = self._client.get(node_type + 's')
            node_active = self._create_labeled_gauge(node_type + '_active', node_type.capitalize() + ' Active', labels=node_labels)
            node_inactive = self._create_labeled_gauge(node_type + '_inactive', node_type.capitalize() + ' Inctive', labels=node_labels)
            node_failed = self._create_labeled_gauge(node_type + '_failed', node_type.capitalize() + ' Failed', labels=node_labels)
            for node in nodes:
                self._node_ip_to_hostname[node['ip']] = node['hostname']
                self._node_id_to_hostname[node_type][node['id']] = node['hostname']
                node_active.add_metric(extract_keys(node, node_labels), node['state'] in ('ACTIVE', 'ACTIVATING') or (node['is_mgmt'] and node['state'] == 'INACTIVE'))
                node_inactive.add_metric(extract_keys(node, node_labels), node['state'] in ('INACTIVE', 'DEACTIVATING') and not node['is_mgmt'])
                node_failed.add_metric(extract_keys(node, node_labels), node['state'] in ('FAILED', 'FAILED'))
            yield node_active
            yield node_inactive
            yield node_failed

        drive_labels = ['guid', 'title', 'sn']
        for drive_type in ['ssd', 'nvram']:
            drives = self._client.get(drive_type + 's')
            drive_active = self._create_labeled_gauge(drive_type + '_active', drive_type.upper() + ' Active', labels=drive_labels)
            drive_inactive = self._create_labeled_gauge(drive_type + '_inactive', drive_type.upper() + ' Inctive', labels=drive_labels)
            drive_failed = self._create_labeled_gauge(drive_type + '_failed', drive_type.upper() + ' Failed', labels=drive_labels)
            for drive in drives:
                drive_active.add_metric(extract_keys(drive, drive_labels), drive['state'] in ('ACTIVE', 'ACTIVATING'))
                drive_inactive.add_metric(extract_keys(drive, drive_labels), drive['state'] in ('INACTIVE', 'DEACTIVATING', 'PHASING_OUT', 'ENTER_PHASING_OUT', 'EXIT_PHASING_OUT'))
                drive_failed.add_metric(extract_keys(drive, drive_labels), drive['state'] in ('FAILED', 'FAILED'))
            yield drive_active
            yield drive_inactive
            yield drive_failed

        nics = self._client.get('nics')
        nic_active = self._create_labeled_gauge('nic_active', 'NIC Active', labels=['hostname', 'display_name'])
        for nic in nics:
            nic_active.add_metric((self._node_ip_to_hostname.get(nic['host'], 'deleted'), nic['display_name']), nic['state'] == 'up')
        yield nic_active
        
        fans = self._client.get('fans')
        fan_labels = ['box', 'location']
        fan_active = self._create_labeled_gauge('fan_active', 'Fan Active', labels=fan_labels)
        for fan in fans:
            fan_active.add_metric(extract_keys(fan, fan_labels), fan['state'] == 'OK')
        yield fan_active

        psus = self._client.get('psus')
        psu_labels = ['box', 'location']
        psu_active = self._create_labeled_gauge('psu_active', 'PSU Active', labels=psu_labels)
        for psu in psus:
            psu_active.add_metric(extract_keys(psu, psu_labels), psu['state'] == 'up')
        yield psu_active

    def _collect_logical(self):
        views = self._client.get('views')
        view_labels = ['path', 'name', 'guid']
        view_logical_capacity = self._create_labeled_gauge('view_logical_capacity', 'View Logical Capacity', labels=view_labels)
        view_physical_capacity = self._create_labeled_gauge('view_physical_capacity', 'View Physical Capacity', labels=view_labels)
        for view in views:
            view_logical_capacity.add_metric(extract_keys(view, view_labels), view['logical_capacity'])
            view_physical_capacity.add_metric(extract_keys(view, view_labels), view['physical_capacity'])
        yield view_logical_capacity
        yield view_physical_capacity

        for (provider_url, provider_name, provider_pretty) in [('nis', 'nis', 'NIS'),
                                                               ('ldaps', 'ldap', 'LDAP'),
                                                               ('activedirectory', 'activedirectory', 'Active Directory')]:
            objects = self._client.get(provider_url)
            if objects:
                yield self._create_gauge(provider_name + '_connected', provider_pretty + ' Connected', objects[0]['state'] == 'CONNECTED')

        native_targets = self._client.get('nativereplicationremotetargets')
        native_target_labels = ['name', 'peer_name']
        native_target_ok = self._create_labeled_gauge('native_replication_target_ok', 'Native Replication Target Is Okay', labels=native_target_labels)
        for native_target in native_targets:
            native_target_ok.add_metric(extract_keys(native_target, native_target_labels), native_target['status'] == 'OK')
        yield native_target_ok

        replication_targets = self._client.get('replicationtargets')
        replication_target_labels = ['name', 'bucket_name']
        replication_target_ok = self._create_labeled_gauge('s3_replication_target_ok', 'S3 Replication Target Is Okay', labels=replication_target_labels)
        for replication_target in replication_targets:
            replication_target_ok.add_metric(extract_keys(replication_target, replication_target_labels), replication_target['status'] == 'OK')
        yield replication_target_ok

def main():
    logging.basicConfig(format='[%(asctime)s] %(levelname)s: %(message)s', level=logging.INFO)
    os.environ['PROMETHEUS_DISABLE_CREATED_SERIES'] = 'True'

    args = parse_args()
    params = vars(args)
    port = params.pop('port')
    logger.info(f'VAST Exporter started running. Listening on port {port}')
    start_http_server(port=port)
    client = VASTClient(**params)

    REGISTRY.register(VASTCollector(client))

    while True: time.sleep(5)

if __name__ == '__main__':
    main()


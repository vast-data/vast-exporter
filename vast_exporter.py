#!/usr/local/bin/python3
import concurrent.futures
import argparse
import logging
import urllib3
import http
import json
import time
import sys
import pwd
import os
import re
from typing import Optional, Sequence, Union
from prometheus_client import make_wsgi_app
from wsgiref.simple_server import make_server
from prometheus_client.exposition import ThreadingWSGIServer, _SilentHandler, _get_best_family
import threading 
from prometheus_client.core import GaugeMetricFamily, Metric, Sample, Timestamp, Summary, Counter, REGISTRY
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

MISSING_USER_NAME_LABEL = 'NONE'
DELETED_OBJECT_LABEL = 'DELETED'

DEFAULT_PORT = 8000
VMS_CONCURRENT_REQUESTS = 4

def parse_args():
    parser = argparse.ArgumentParser()
    def add_argument(key, *args, **kwargs):
        if key in os.environ:
            kwargs['required'] = False
            kwargs['default'] = os.environ[key]
            parser.add_argument(*args, **kwargs)
        else:
            parser.add_argument(*args, **kwargs)

    add_argument('VAST_COLLECTOR_USER', '--user', required=True, help='VMS user name')
    add_argument('VAST_COLLECTOR_PASSWORD', '--password', required=True, help='VMS password')
    add_argument('VAST_COLLECTOR_ADDRESS', '--address', required=True, help='VMS address or host name')
    add_argument('VAST_COLLECTOR_BIND_ADDRESS', '--bind-address', default='0.0.0.0', help='IP address to bind on the host')
    add_argument('VAST_COLLECTOR_PORT', '--port', default=DEFAULT_PORT, type=int,
                 help='Port to listen to for incoming connections from Prometheus')
    add_argument('VAST_COLLECTOR_CERT_FILE', '--cert-file', help='Path to custom SSL certificate for VMS')
    add_argument('VAST_COLLECTOR_CERT_SERVER', '--cert-server-name', help='Address of custom SSL certificate authority')
    add_argument('VAST_COLLECTOR_COLLECT_TOP_USERS', '--collect-top-users', action='store_true',
                 help='Collect metrics data for top users (may cause a proliferation of distinct metrics)')
    add_argument('VAST_COLLECTOR_RESOLVE_UID', '--resolve-uid', action='store_true',
                 help='Resolve user ID using /etc/passwd in case the system is not able to resolve it')
    add_argument('VAST_COLLECTOR_DEBUG', '--debug', action='store_true', help='Drop into a debugger on error')
    add_argument('VAST_COLLECTOR_TEST', '--test', action='store_true',
                 help='Run the collector once and indicate whether it succeeded in the return code')
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
            logger.debug(f'Sending request with url={url} and parameters={params}')
            r = pm.request(method, 'https://{}/api/{}/'.format(self._address, url), headers=headers, fields=params)
        if r.status != http.HTTPStatus.OK:
            raise RESTFailure(f'Response for request {url} with {params} failed with error {r.status} and message {r.data}')
        return json.loads(r.data.decode('utf-8'))

    def get(self, url, params=None):
        return self._request('GET', url, params)
    
    def _unused_helpers(self):
        # metrics description
        print(self._client.get('metrics'))
        # all monitors
        print(self._client.get('monitors'))
        # example monitor
        print(self._client.get('monitors/2/query', {'granularity': 'seconds', 'time_frame': '2m'}))

def extract_keys(obj, keys):
    return [str(obj[k]) for k in keys]

class MetricDescriptor(object):
    def __init__(self, class_name, properties=None, histograms=None, tags=None, time_frame='2m',
                 scopes=['cnode', 'cluster'], custom_suffix=('num_samples', 'sum')):
        if custom_suffix is None:
            custom_suffix = []
        self.class_name = class_name
        self.time_frame = time_frame
        self.scopes = scopes
        self.properties = properties or []
        self.histograms = histograms or []
        for i in self.histograms:
            for suffix in custom_suffix:
                self.properties.append(f'{i}__{suffix}')
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
# we split metrics to small groups until 4.3, uwsgi accepts no more than 4k
PROTO_METRICS_TAGS = {'proto_name': ['NFSCommon', 'NFS4Common', 'SMBCommon', 'S3Common', 'ProtoAll', 'ReplicationCommon']}
DESCRIPTORS = [MetricDescriptor(class_name='ProtoMetrics',
                                histograms=['read_latency'],
                                tags=PROTO_METRICS_TAGS),
               MetricDescriptor(class_name='ProtoMetrics',
                                histograms=['write_latency'],
                                tags=PROTO_METRICS_TAGS),
               MetricDescriptor(class_name='ProtoMetrics',
                                histograms=['read_size', 'write_size'],
                                tags=PROTO_METRICS_TAGS),
               MetricDescriptor(class_name='ProtoMetrics',
                                properties=['rd_md_iops',
                                            'wr_md_iops',
                                            'md_iops',
                                            'rd_bw',
                                            'wr_bw'],
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
               MetricDescriptor(class_name='SchedulerMetrics',
                                scopes=['cnode'],
                                time_frame='10m',
                                histograms=['window_runtime'],
                                custom_suffix=('avg',)),
               MetricDescriptor(class_name='SchedulerMetrics',
                                scopes=['cnode'],
                                time_frame='10m',
                                histograms=['queue_latency_ns_fiber'],
                                tags={'histogram': ['1']},
                                custom_suffix=('avg',)),
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
                                            'nfs_commit_latency']),
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
                                            'nfs_write_latency']),
               MetricDescriptor(class_name='Nfs4Metrics',
                                histograms=['nfs4_write_req_latency', 'nfs4_read_req_latency',
                                            'nfs4_setattr_req_latency', 'nfs4_getattr_req_latency',
                                            'nfs4_free_stateid_req_latency', 'nfs4_secinfo_req_latency',
                                            'nfs4_lookupp_req_latency', 'nfs4_lookup_req_latency',
                                            'nfs4_commit_req_latency', 'nfs4_close_req_latency',
                                            'nfs4_savefh_req_latency', 'nfs4_readdir_req_latency',
                                            'nfs4_create_session_req_latency', 'nfs4_destroy_session_req_latency']),
               MetricDescriptor(class_name='Nfs4Metrics',
                                histograms=['nfs4_access_req_latency', 'nfs4_sequence_req_latency',
                                            'nfs4_remove_req_latency', 'nfs4_exchange_id_req_latency',
                                            'nfs4_destroy_clientid_req_latency', 'nfs4_create_req_latency',
                                            'nfs4_getfh_req_latency', 'nfs4_open_req_latency',
                                            'nfs4_putfh_req_latency', 'nfs4_putpubfh_req_latency',
                                            'nfs4_putrootfh_req_latency', 'nfs4_reclaim_complete_req_latency',
                                            'nfs4_restorefh_req_latency', 'nfs4_secinfo_no_name_req_latency',
                                            'nfs4_test_stateid_req_latency']),
               MetricDescriptor(class_name='Hardware',
                                scopes=['dbox'],
                                tags={'component': ['box']},
                                properties=['ambient_temp',
                                            'failed_ssd_slots']),
               MetricDescriptor(class_name='Hardware',
                                scopes=['cbox'],
                                tags={'component': ['box']},
                                properties=['ambient_temp']),
               MetricDescriptor(class_name='Hardware',
                                scopes=['cnode', 'dnode'],
                                tags={'component': ['node']},
                                properties=['cpu_temp',
                                            'cpu_utilization',
                                            'mem_percent',
                                            'pci_errors_count',
                                            'segments_retransmited',
                                            'total_ce',
                                            'total_ue']),
               MetricDescriptor(class_name='Hardware',
                                scopes=['dnode'],
                                tags={'component': ['node']},
                                properties=['pci_switch_errors']),
               MetricDescriptor(class_name='Hardware',
                                scopes=['psu'],
                                tags={'component': ['psu']},
                                properties=['v_in',
                                            'temperature',
                                            'input_power',
                                            'total_power']),
               # defrag metrics
               MetricDescriptor(class_name='RaidMetrics',
                                time_frame='8m',
                                histograms=['defrag_freed_capacity_mb']),
               MetricDescriptor(class_name='DefragMetrics',
                                time_frame='8m',
                                tags={'shard_type': ['1']},
                                histograms=['defrag_flash_read_size_kb']),
               # as of 4.4
               # MetricDescriptor(class_name='RaidMaintenanceMetrics',
               #                 time_frame='8m',
               #                 tags={'op': ['RaidMaintenanceManagerType.DEFRAG']},
               #                 histograms=['stripe_backlog', 'data_backlog_mb']),
               # migrate metrics
               # as of 4.4
               #MetricDescriptor(class_name='ParallelReaderMetrics',
               #                 time_frame='8m',
               #                 tags={'name': ["migrate"]},
               #                 histograms=['reader_nvram_read_size_kb']),
               MetricDescriptor(class_name='EStoreMigrateMetrics',
                                time_frame='8m',
                                tags={'name': ['migrate']},
                                histograms=['physical_size']),
               MetricDescriptor(class_name='ShardMdMetrics',
                                time_frame='8m',
                                histograms=['migrating_buffers_percent',
                                            'delete_snap_backlog']),
               # delete metrics
               MetricDescriptor(class_name='DeleteMetrics',
                                time_frame='8m',
                                histograms=['delete_element_backlog']),
               # utilization metrics
               MetricDescriptor(class_name='IOComposerMetrics',
                                time_frame='8m',
                                histograms=['substripe_fill_efficiency_percent']),
               MetricDescriptor(class_name='RaidMetrics',
                                time_frame='8m',
                                histograms=['stripe_available_percent']),
               # ingest metrics
               MetricDescriptor(class_name='IngestMetrics',
                                scopes=['cluster'],
                                time_frame='8m',
                                tags={'ingest_client_type': ['IngestClientType.INGEST']},
                                histograms=['stress_sleep_length'])]

class MetricFamily(Metric): # mostly copied from the client library
    TYPE = None
    def __init__(self,
                 name: str,
                 documentation: str,
                 value: Optional[float] = None,
                 labels: Optional[Sequence[str]] = None,
                 unit: str = '',
                 ):
        Metric.__init__(self, name, documentation, self.TYPE, unit)
        if labels is not None and value is not None:
            raise ValueError('Can only specify at most one of value and labels.')
        if labels is None:
            labels = []
        self._labelnames = tuple(labels)
        if value is not None:
            self.add_metric([], value)

    def add_metric(self, labels: Sequence[str], value: float, timestamp: Optional[Union[Timestamp, float]] = None) -> None:
        self.samples.append(Sample(self.name, dict(zip(self._labelnames, labels)), value, timestamp))

class WrappedMetric(MetricFamily):
    def __init__(self, name, documentation, cluster_name, labels=None, **kw):
        super(WrappedMetric, self).__init__(name='vast_' + name, documentation=documentation, labels=['cluster'] + (labels or []))
        self._cluster_name = cluster_name

    def add_metric(self, labels, value):
        labels = list(labels)
        labels.insert(0, self._cluster_name)
        return super(WrappedMetric, self).add_metric(labels, value)

class WrappedGauge(WrappedMetric):
    TYPE = 'gauge'

class WrappedHistogram(WrappedMetric):
    TYPE = 'histogram'

class VASTCollector(object):
    def __init__(self, client, resolve_uid=False, collect_top_users=False):
        self._client = client
        self._resolve_uid = resolve_uid
        self._should_collect_top_users = collect_top_users
        self._cluster_name = None
        self._node_id_to_hostname = {'cnode':{}, 'dnode': {}}
        self._node_ip_to_node_id_and_type = {} # 172.16.3.1 -> (1, 'cnode')

    collection_timer = Summary('vast_collector_latency', 'Total collection time')
    error_counter = Counter('vast_collector_errors', 'Errors raised during collection')

    def collect(self):
        with self.collection_timer.time():
            phase_1_collectors = [self._collect_cluster()] # must be first, initializes the cluster name (required by all metrics)
            phase_2_collectors = [self._collect_nodes()] # must be second, for collecting cnode host names and IPs (required by metrics)
            phase_3_collectors = [self._collect_physical(), self._collect_logical(), self._collect_views(), self._collect_quotas()]
            phase_3_collectors.extend(self._collect_perf_metrics(descriptor) for descriptor in DESCRIPTORS)

            if self._should_collect_top_users:
                phase_3_collectors.append(self._collect_users())

            with concurrent.futures.ThreadPoolExecutor(max_workers=VMS_CONCURRENT_REQUESTS) as executor:
                for collectors in [phase_1_collectors, phase_2_collectors, phase_3_collectors]:
                    futures = [executor.submit(list, g) for g in collectors]
                    for future in concurrent.futures.as_completed(futures):
                        try:
                            yield from future.result()
                        except Exception as e:
                            self.error_counter.inc()
                            logger.exception(f'Caught exception while collecting metrics: {e}')
    
    def _create_gauge(self, name, documentation, value):
        gauge = WrappedGauge(name=name, documentation=documentation, cluster_name=self._cluster_name)
        gauge.add_metric([], value)
        return gauge

    def _create_labeled_gauge(self, name, documentation, labels):
        return WrappedGauge(name=name, documentation=documentation, labels=labels, cluster_name=self._cluster_name)

    def _create_labeled_counter(self, name, documentation, labels):
        return WrappedHistogram(name=name, documentation=documentation, labels=labels, cluster_name=self._cluster_name)

    def _get_metrics(self, scope, metric_names, time_frame):
        properties = [('prop_list', metric) for metric in metric_names]
        result = self._client.get('monitors/ad_hoc_query', [('object_type', scope),
                                                            ('time_frame', time_frame)] + properties)
        rows = result['data']
        # take the latest row per per object id
        try:
            index_of_id = result['prop_list'].index('object_id')
        except ValueError:
            return {}
        seen = set()
        unique_rows = []
        for row in reversed(rows):
            if row[index_of_id] not in seen and row[-1] is not None:
                seen.add(row[index_of_id])
                unique_rows.append(row)
        columns = zip(*unique_rows)
        return dict(zip(result['prop_list'], columns))

    def _collect_perf_metrics(self, descriptor):
        for scope in descriptor.scopes:
            if scope == 'cnode':
                labels = ['cnode_id', 'hostname']
            else:
                labels = []
            table = self._get_metrics(scope, descriptor.fqns, descriptor.time_frame)
            if not table:
                logger.debug(f'Failed requesting metrics on {scope} for {descriptor.class_name}: {descriptor.fqns}')
                self.error_counter.inc()
                continue
            for prop, fqns in descriptor.property_to_fqn.items():
                valid_name = f'{scope}_metrics_{descriptor.class_name}_{prop.replace("__", "_").replace("num_samples", "count")}'
                factory = self._create_labeled_counter if prop.endswith(('__num_samples', '__sum')) else self._create_labeled_gauge
                metric = factory(valid_name, '', labels=labels + list(descriptor.tags))
                for fqn in fqns:
                    if fqn not in table:
                        logger.info("metric missing: " + fqn)
                        continue
                    for (object_id, value) in zip(table['object_id'], table[fqn]):
                        if scope == 'cnode':
                            label_values = [str(object_id), self._node_id_to_hostname['cnode'].get(object_id, DELETED_OBJECT_LABEL)]
                        else:
                            label_values = []
                        try:
                            label_values.append(descriptor.fqn_to_tag_value[fqn])
                        except KeyError: # untagged metric
                            pass
                        if value is not None:
                            metric.add_metric(label_values, value)
                yield metric

    def _collect_cluster(self):
        cluster, = self._client.get('clusters')
        self._cluster_name = cluster['name']
        self._cluster_version = tuple(map(int, cluster['sw_version'].split('.'))) # comes in as 4.3.0.1, stored as (4, 3, 0, 1)
        yield self._create_gauge('cluster_version', 'Cluster Version', int(''.join(str(i).zfill(2) for i in self._cluster_version))) # sent as 4030001
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

    def _collect_nodes(self):
        node_labels = ['name', 'guid', 'hostname', 'id']
        for node_type in ['cnode', 'dnode']:
            nodes = self._client.get(node_type + 's')
            node_active = self._create_labeled_gauge(node_type + '_active', node_type.capitalize() + ' Active', labels=node_labels)
            node_inactive = self._create_labeled_gauge(node_type + '_inactive', node_type.capitalize() + ' Inctive', labels=node_labels)
            node_failed = self._create_labeled_gauge(node_type + '_failed', node_type.capitalize() + ' Failed', labels=node_labels)
            for node in nodes:
                try:
                    self._node_ip_to_node_id_and_type[node['ip']] = (node['id'], node_type)
                    self._node_id_to_hostname[node_type][node['id']] = node['hostname']
                    is_mgmt = node['is_mgmt'] if node_type == 'cnode' else False
                    node_active.add_metric(extract_keys(node, node_labels), node['state'] in ('ACTIVE', 'ACTIVATING') or (is_mgmt and node['state'] == 'INACTIVE'))
                    node_inactive.add_metric(extract_keys(node, node_labels), node['state'] in ('INACTIVE', 'DEACTIVATING') and not is_mgmt)
                    node_failed.add_metric(extract_keys(node, node_labels), node['state'] in ('FAILED', 'FAILED'))
                except Exception as e:
                    logger.debug("Collect nodes failed to collect %s due to an error: %s", node, e)
                    continue
            yield node_active
            yield node_inactive
            yield node_failed

    def _collect_physical(self):
        psus = self._client.get('psus')
        psu_labels = ['box', 'location']
        psu_active = self._create_labeled_gauge('psu_active', 'PSU Active', labels=psu_labels)
        for psu in psus:
            psu_active.add_metric(extract_keys(psu, psu_labels), psu['state'] == 'up')
        yield psu_active

        if self._cluster_version >= (4, 3):
            subnetmanagers = self._client.get('subnetmanager')    
            if subnetmanagers:
                subnetmanager, = subnetmanagers
                yield self._create_gauge('subnetmanager_active', 'Subnet Manager Active', subnetmanager['state'] == 'ACTIVE')

    FLOW_METRICS = ['iops', 'md_iops', 'read_bw', 'read_iops', 'read_md_iops', 'write_bw', 'write_iops', 'write_md_iops']

    def _get_iodata(self):
        res = self._client.get('iodata', {'time_frame': '5m'})
        return [i for i in res['data'] if i['timestamp'] == res['timestamp']] # filter latest records
    
    def _get_view_metrics(self):
        rows = self._get_iodata()
        view_to_metrics = {}
        for row in rows:
            name = re.sub('(.+?) ?\(.+?\)', "\g<1>", row['view']) # default format is 'name (alias)'
            metrics = view_to_metrics.setdefault(name, {})
            for metric in self.FLOW_METRICS:
                metrics[metric] = metrics.get(metric, 0) + row[metric]

        return view_to_metrics

    def _collect_views(self):
        views = self._client.get('views')
        view_labels = ['path', 'name', 'guid']
        view_logical_capacity = self._create_labeled_gauge('view_logical_capacity', 'View Logical Capacity', labels=view_labels)
        view_physical_capacity = self._create_labeled_gauge('view_physical_capacity', 'View Physical Capacity', labels=view_labels)
        path_to_view = {}
        for view in views:
            path_to_view[view['path']] = view
            view_logical_capacity.add_metric(extract_keys(view, view_labels), view['logical_capacity'])
            view_physical_capacity.add_metric(extract_keys(view, view_labels), view['physical_capacity']) 
        yield view_logical_capacity
        yield view_physical_capacity

        view_metrics = self._get_view_metrics()
        for metric in self.FLOW_METRICS:
            gauge = self._create_labeled_gauge('view_' + metric, 'View ' + metric, labels=view_labels)
            for path, metrics in view_metrics.items():
                if not path in path_to_view:
                    continue
                gauge.add_metric(extract_keys(path_to_view[path], view_labels), metrics[metric])
            yield gauge

    def _collect_quotas(self):
        quotas = self._client.get('quotas')
        quota_labels = ['path', 'title', 'guid']
        quota_used_inodes = self._create_labeled_gauge('quota_used_inodes', 'Quota Used Inodes', labels=quota_labels)
        quota_used_capacity = self._create_labeled_gauge('quota_used_capacity', 'Quota Used Capacity', labels=quota_labels)
        quota_num_exceeded_users = self._create_labeled_gauge('quota_num_exceeded_users', 'Quota Number Of Exceeded Users', labels=quota_labels)
        quota_num_blocked_users = self._create_labeled_gauge('quota_num_blocked_users', 'Quota Number Of Blocked Users', labels=quota_labels)
        quota_soft_limit = self._create_labeled_gauge('quota_soft_limit', 'Quota Soft Limit', labels=quota_labels)
        quota_soft_limit_inodes = self._create_labeled_gauge('quota_soft_limit_inodes', 'Quota Inodes Soft Limit', labels=quota_labels)
        quota_hard_limit = self._create_labeled_gauge('quota_hard_limit', 'Quota Hard Limit', labels=quota_labels)
        quota_hard_limit_inodes = self._create_labeled_gauge('quota_hard_limit_inodes', 'Quota Inodes Hard Limit', labels=quota_labels)
        quota_ok = self._create_labeled_gauge('quota_ok', 'Quota State Is OK', labels=quota_labels)

        path_to_view = {}
        for quota in quotas:
            quota_ok.add_metric(extract_keys(quota, quota_labels), quota['state'] == 'OK')
            for metric, name in [(quota_used_inodes, 'used_inodes'),
                                 (quota_used_capacity, 'used_capacity'),
                                 (quota_num_exceeded_users, 'num_exceeded_users'),
                                 (quota_num_blocked_users, 'num_blocked_users'),
                                 (quota_soft_limit, 'soft_limit'),
                                 (quota_soft_limit_inodes, 'soft_limit_inodes'),
                                 (quota_hard_limit, 'hard_limit'),
                                 (quota_hard_limit_inodes, 'hard_limit_inodes')]:
                if quota[name] is not None:
                    metric.add_metric(extract_keys(quota, quota_labels), quota[name])
    
        yield quota_used_inodes
        yield quota_used_capacity
        yield quota_num_exceeded_users
        yield quota_num_blocked_users
        yield quota_soft_limit
        yield quota_soft_limit_inodes
        yield quota_hard_limit
        yield quota_hard_limit_inodes
        yield quota_ok

    def _collect_users(self):
        rows = self._get_iodata()
        user_metrics = {}
        for row in rows:
            if row['user'].startswith('('):
                name, uid = row['user'].split(') ')
                name = name.strip('(')
            else:
                uid = row['user']
                name = MISSING_USER_NAME_LABEL
                if self._resolve_uid:
                    try:
                        name = pwd.getpwuid(int(uid)).pw_name
                    except (KeyError, ValueError):
                        pass
            metrics = user_metrics.setdefault((name, uid), {})
            for metric in self.FLOW_METRICS:
                metrics[metric] = metrics.get(metric, 0) + row[metric]

        user_labels = ['name', 'id']
        for metric in self.FLOW_METRICS:
            gauge = self._create_labeled_gauge('user_' + metric, 'User ' + metric, labels=user_labels)
            for (name, uid), metrics in user_metrics.items():
                gauge.add_metric((name or 'none', uid), metrics[metric])
            yield gauge

    def _collect_logical(self):
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
            replication_target_ok.add_metric(extract_keys(replication_target, replication_target_labels), replication_target['state'] == 'ACTIVE')
        yield replication_target_ok

def create_httpd_server(port: str=DEFAULT_PORT, addr: str='0.0.0.0'):

    class TmpServer(ThreadingWSGIServer):
        """Copy of ThreadingWSGIServer to update address_family locally"""

    TmpServer.address_family, addr = _get_best_family(addr, port)

    metrics_app = make_wsgi_app()

    def app(environ, start_fn):
        if environ['PATH_INFO'] == '/vastmetrics':
            return metrics_app(environ, start_fn)

        start_fn('404 NOT_FOUND', [('', '')])
        return b''

    httpd = make_server(addr, port, app, TmpServer, handler_class=_SilentHandler)
    t = threading.Thread(target=httpd.serve_forever)
    t.daemon = True
    t.start()

def main():
    os.environ['PROMETHEUS_DISABLE_CREATED_SERIES'] = 'True'

    args = parse_args()
    params = vars(args)
    port = params.pop('port')
    bind_address = params.pop('bind_address')
    debug = params.pop('debug')
    test = params.pop('test')
    resolve_uid = params.pop('resolve_uid')
    collect_top_users = params.pop('collect_top_users')
    logging.basicConfig(format='%(asctime)s %(threadName)s %(levelname)s: %(message)s', level=logging.DEBUG if debug else logging.INFO)
    logger.info(f'VAST Exporter started running')
    create_httpd_server(port=port, addr=bind_address)
    client = VASTClient(**params)
    collector = VASTCollector(client, resolve_uid=resolve_uid, collect_top_users=collect_top_users)
    REGISTRY.register(collector)

    if test:
        success = collector.error_counter._value.get() == 0
        logger.info(f'Collection {"is successful!" if success else "failed!"}')
        sys.exit(0 if success else 1)
    else:
        while True: time.sleep(5)

if __name__ == '__main__':
    main()

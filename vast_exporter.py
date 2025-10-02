#!/usr/bin/env python3
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
from collections import defaultdict
from typing import Optional, Sequence, Union
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, Metric, Sample, Timestamp, Summary, Counter, REGISTRY
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

MISSING_USER_NAME_LABEL = 'NONE'
DELETED_OBJECT_LABEL = 'DELETED'

DEFAULT_PORT = 8000
VMS_CONCURRENT_REQUESTS = 4
MAX_THREADS = 4

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
                 help='Collect performance data for top users (may cause a proliferation of distinct metrics)')
    add_argument('VAST_COLLECTOR_COLLECT_USER_QUOTAS', '--collect-user-quotas', action='store_true',
                 help='Collect quota metrics for users/groups (may cause a proliferation of distinct metrics)')
    add_argument('VAST_COLLECTOR_RESOLVE_UID', '--resolve-uid', action='store_true',
                 help='Resolve user ID using /etc/passwd in case the system is not able to resolve it')
    add_argument('VAST_COLLECTOR_DEBUG', '--debug', action='store_true', help='Drop into a debugger on error')
    add_argument('VAST_COLLECTOR_TEST', '--test', action='store_true',
                 help='Run the collector once and indicate whether it succeeded in the return code')
    add_argument('VAST_COLLECTOR_BLOCKING', '--block', action='store_true',
                 help='Set exporter pool manager to block after set vms-concurrent-requests count is reached')
    add_argument('VMS_CONCURRENT_REQUESTS', '--vms-concurrent-requests', type=int, default=VMS_CONCURRENT_REQUESTS,
                 help="Set exporter pool manager's number of allowed concurrent requests \
                       in a given connection at once before requesting a new connection (Default: 4)")
    return parser.parse_args()

class RESTFailure(Exception): pass

class VASTClient(object):
    def __init__(self, user, password, address, block, vms_concurrent_requests,
                 cert_file=None, cert_server_name=None):
        self._user = user
        self._password = password
        self._address = address
        self._cert_file = cert_file
        self._cert_server_name = cert_server_name
        if self._cert_file:
            self.pm = urllib3.PoolManager(
                ca_certs=self._cert_file, server_hostname=self._cert_server_name,
                maxsize=vms_concurrent_requests, block=block)
        else:
            self.pm = urllib3.PoolManager(cert_reqs='CERT_NONE',
                maxsize=vms_concurrent_requests, block=block)

    vms_latency = Summary('vast_collector_vms_latency', 'VAST VMS Request Time')

    def _request(self, method, url, params):
        headers = urllib3.make_headers(basic_auth=self._user + ':' + self._password)
        with self.vms_latency.time():
            logger.debug(f'Sending request with url={url} and parameters={params}')
            start = time.perf_counter()
            r = self.pm.request(method, 'https://{}/api/{}/'.format(self._address, url), headers=headers, fields=params)
            request_time = time.perf_counter() - start
            if request_time > 15:
                logger.error(f'Response for request {url} with {params} returned status {r.status}, and took longer than 15s to complete, took {request_time} seconds')
        if r.status != http.HTTPStatus.OK:
            logger.error(f'Response for request {url} with {params} failed with error {r.status} and message {r.data}')
        return json.loads(r.data.decode('utf-8')) if r.data else {}

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
    def __init__(self, class_name, properties=None, histograms=None, tags=None, time_frame='2m', scopes=['cnode', 'cluster'], custom_suffix=('num_samples', 'sum')):
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
                                            'md_iops'],
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
               MetricDescriptor(class_name='RpcRdmaMetrics',
                                properties=['active_links'],
                                time_frame='10m'),
               MetricDescriptor(class_name='SchedulerMetrics',
                                time_frame='10m',
                                histograms=['window_runtime']),
               MetricDescriptor(class_name='SchedulerMetrics',
                                time_frame='10m',
                                histograms=['queue_latency_ns_fiber'],
                                tags={'histogram': ['0', '1', '2', '3']}),
               MetricDescriptor(class_name='SchedulerMetrics',
                                time_frame='10m',
                                histograms=['window_runtime'],
                                custom_suffix=['avg']),
               MetricDescriptor(class_name='SchedulerMetrics',
                                time_frame='10m',
                                histograms=['queue_latency_ns_fiber'],
                                tags={'histogram': ['0', '1', '2', '3']},
                                custom_suffix=['avg']),
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
                                scopes=['nic'],
                                tags={'component': ['nic']},
                                properties=['bytes_recv',
                                            'bytes_sent',
                                            'tx_errors',
                                            'rx_errors',
                                            'tx_errors_phy',
                                            'rx_crc_errors_phy',
                                            'rx_buff_alloc_err',
                                            'rx_symbol_err_phy',
                                            'rx_in_range_len_errors_phy']),
               MetricDescriptor(class_name='Hardware',
                                scopes=['dbox'],
                                tags={'component': ['box']},
                                properties=['ambient_temp']),
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
                                scopes=['ssd', 'nvram'],
                                tags={'component': ['disk']},
                                properties=['endurance',
                                            'temperature',
                                            'media_errors',
                                            'r_mbs',
                                            'w_mbs',
                                            'r_await',
                                            'w_await',
                                            'write_count',
                                            'read_count',
                                            'power_on_hours',
                                            'power_cycles']),
               MetricDescriptor(class_name='Hardware',
                                scopes=['fan'],
                                tags={'component': ['fan']},
                                properties=['rpm']),
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
                                histograms=['physical_size', 'dedup_logical_size']),
               MetricDescriptor(class_name='EStoreMigrateMetrics',
                                time_frame='8m',
                                tags={'name': ['migrate']},
                                properties=['write_logical_size', 'similarity_gain_size',
                                           'local_compr_gain_size', 'write_physical_size', 'local_compr_written_logical_size',
                                           'similarity_written_logical_size', 'total_logical_size', 'total_physical_size']),
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

VIEWS_DESCRIPTORS = [MetricDescriptor(class_name='ViewMetrics',
                                      scopes=['view'],
                                      time_frame='13m',
                                      histograms=['write_iops', 'read_iops',
                                                  'write_bw', 'read_bw',
                                                  'write_md_iops', 'read_md_iops',
                                                  'read_md_latency', 'write_md_latency',
                                                  'qos_wait_for_budget_time', 'write_latency',
                                                  'read_latency'])]

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
    def __init__(self, client, resolve_uid=False, collect_top_users=False, collect_user_quotas=False):
        self._client = client
        self._resolve_uid = resolve_uid
        self._should_collect_top_users = collect_top_users
        self._should_collect_user_quotas = collect_user_quotas
        self._cluster_name = None
        self._node_id_to_hostname = {'cnode':{}, 'dnode': {}}
        self._node_ip_to_node_id_and_type = {} # 172.16.3.1 -> (1, 'cnode')
        self._nic_id_to_ip = {}
        self._nic_id_to_display_name = {}
        self._fan_id_to_info = {}
        self._psu_id_to_info = {}
        self._drive_id_to_info = {'ssd': {}, 'nvram': {}}
        self._box_id_to_name = {'cbox': {}, 'dbox': {}}
        self._view_id_to_view = None

    collection_timer = Summary('vast_collector_latency', 'Total collection time')
    error_counter = Counter('vast_collector_errors', 'Errors raised during collection')

    def collect(self):
        with self.collection_timer.time():
            phase_1_collectors = [self._collect_cluster()] # must be first, initializes the cluster name (required by all metrics)
            phase_2_collectors = [self._collect_nodes()] # must be second, for collecting cnode host names and IPs (required by metrics)
            phase_3_collectors = [self._collect_physical(), self._collect_logical(), self._collect_views(), self._collect_quotas(), 
                                  self._collect_top_vippools(), self._collect_top_vips()]
            phase_3_collectors.extend(self._collect_perf_metrics(descriptor) for descriptor in DESCRIPTORS)
            phase_3_collectors.extend(self._collect_perf_metrics(descriptor) for descriptor in VIEWS_DESCRIPTORS)

            if self._should_collect_top_users:
                phase_3_collectors.append(self._collect_top_users())

            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
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
        # take the latest row per per object id
        try:
            rows = result['data']
            index_of_id = result['prop_list'].index('object_id')
        except (KeyError, ValueError):
            return {}
        seen = set()
        unique_rows = []
        for row in rows:
            if row[index_of_id] not in seen:
                seen.add(row[index_of_id])
                unique_rows.append(row)
        columns = zip(*unique_rows)
        return dict(zip(result['prop_list'], columns))

    def _collect_perf_metrics(self, descriptor):
        for scope in descriptor.scopes:
            if scope == 'cnode':
                labels = ['cnode_id', 'hostname']
            elif scope == 'dnode':
                labels = ['dnode_id', 'hostname']
            elif scope in {'cbox', 'dbox'}:
                labels = ['id', 'name']
            elif scope == 'nic':
                labels = ['hostname', 'display_name']
            elif scope in {'ssd', 'nvram'}:
                labels = ['guid', 'sn', 'title']
            elif scope in {'psu', 'fan'}:
                labels = ['box', 'title']
            elif scope == "view":
                labels = ['path', 'name', 'guid']
            else:
                labels = []
            table = self._get_metrics(scope, descriptor.fqns, descriptor.time_frame)
            if not table:
                logger.error(f'Failed requesting metrics on {scope} for {descriptor.class_name}: {descriptor.fqns}')
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
                        elif scope == 'dnode':
                            label_values = [str(object_id), self._node_id_to_hostname['dnode'].get(object_id, DELETED_OBJECT_LABEL)]
                        elif scope in {'cbox', 'dbox'}:
                            label_values = [str(object_id), self._box_id_to_name[scope].get(object_id, None)]
                        elif scope == 'nic':
                            node_ip = self._nic_id_to_ip.get(object_id, DELETED_OBJECT_LABEL)
                            if node_ip not in self._node_ip_to_node_id_and_type:
                                continue
                            node_id, node_type = self._node_ip_to_node_id_and_type.get(node_ip)
                            label_values = [self._node_id_to_hostname[node_type].get(node_id, DELETED_OBJECT_LABEL),
                                            self._nic_id_to_display_name.get(object_id, DELETED_OBJECT_LABEL)]
                        elif scope == 'fan':
                            try:
                                info = self._fan_id_to_info[object_id]
                            except KeyError:
                                continue
                            label_values = [info['box'], info['title']]
                        elif scope == 'psu':
                            try:
                                info = self._psu_id_to_info[object_id]
                            except KeyError:
                                continue
                            label_values = [info['box'], info['title']]
                        elif scope in {'ssd', 'nvram'}:
                            try:
                                info = self._drive_id_to_info[scope][object_id]
                            except KeyError:
                                continue
                            label_values = [info['guid'], info['sn'], info['title']]
                        elif scope == 'view':
                            label_values = self._view_id_to_view[object_id]
                        else:
                            label_values = []
                        try:
                            label_values.append(descriptor.fqn_to_tag_value[fqn])
                        except KeyError: # untagged metric
                            pass
                        if value is not None: # expected for things like NIC metrics
                            metric.add_metric(label_values, value)
                yield metric

    def _collect_cluster(self):
        cluster, = self._client.get('clusters')
        self._cluster_name = cluster['name']
        version_string = cluster['sw_version']
        self._cluster_version = tuple(map(int, version_string.split('.'))) # comes in as 4.3.0.1, stored as (4, 3, 0, 1)
        logger.info(f'Running against {self._cluster_name} with version {version_string}')
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
        version_labels = node_labels + [ 'os_version', 'bios_version', 'bmc_fw_version' ]
        node_to_box_names = {'cnode': 'cbox', 'dnode': 'dbox'}
        for node_type in ['cnode', 'dnode']:
            nodes = self._client.get(node_type + 's')
            box_type = node_to_box_names[node_type]
            node_active = self._create_labeled_gauge(node_type + '_active', node_type.capitalize() + ' Active', labels=node_labels)
            node_inactive = self._create_labeled_gauge(node_type + '_inactive', node_type.capitalize() + ' Inctive', labels=node_labels)
            node_failed = self._create_labeled_gauge(node_type + '_failed', node_type.capitalize() + ' Failed', labels=node_labels)
            node_version = self._create_labeled_gauge(node_type + '_version', node_type.capitalize() + ' OS and Firmware Versions', labels=version_labels)
            for node in nodes:
                try:
                    self._node_ip_to_node_id_and_type[node['ip']] = (node['id'], node_type)
                    self._node_id_to_hostname[node_type][node['id']] = node['hostname']
                    is_mgmt = node['is_mgmt'] if node_type == 'cnode' else False
                    node_active.add_metric(extract_keys(node, node_labels), node['state'] in ('ACTIVE', 'ACTIVATING') or (is_mgmt and node['state'] == 'INACTIVE'))
                    node_inactive.add_metric(extract_keys(node, node_labels), node['state'] in ('INACTIVE', 'DEACTIVATING') and not is_mgmt)
                    node_failed.add_metric(extract_keys(node, node_labels), node['state'] in ('FAILED', 'FAILED'))
                    node_version.add_metric(extract_keys(node, version_labels), True)
                    box_id = node[f'{box_type}_id']
                    self._box_id_to_name[box_type][box_id] = node[box_type]
                except Exception as e:
                    logger.debug("Collect nodes failed to collect %s due to an error: %s", node, e)
                    continue
            yield node_active
            yield node_inactive
            yield node_failed
            yield node_version

    def _collect_physical(self):
        drive_labels = ['guid', 'title', 'sn']
        for drive_type in ['ssd', 'nvram']:
            drives = self._client.get(drive_type + 's')
            drive_active = self._create_labeled_gauge(drive_type + '_active', drive_type.upper() + ' Active', labels=drive_labels)
            drive_inactive = self._create_labeled_gauge(drive_type + '_inactive', drive_type.upper() + ' Inctive', labels=drive_labels)
            drive_failed = self._create_labeled_gauge(drive_type + '_failed', drive_type.upper() + ' Failed', labels=drive_labels)
            for drive in drives:
                self._drive_id_to_info[drive_type][drive['id']] = drive
                drive_active.add_metric(extract_keys(drive, drive_labels), drive['state'] in ('ACTIVE', 'ACTIVATING'))
                drive_inactive.add_metric(extract_keys(drive, drive_labels), drive['state'] in ('INACTIVE', 'DEACTIVATING', 'PHASING_OUT', 'ENTER_PHASING_OUT', 'EXIT_PHASING_OUT'))
                drive_failed.add_metric(extract_keys(drive, drive_labels), drive['state'] in ('FAILED', 'FAILED'))
            yield drive_active
            yield drive_inactive
            yield drive_failed

        nics = self._client.get('nics')
        nic_active = self._create_labeled_gauge('nic_active', 'NIC Active', labels=['hostname', 'display_name'])
        for nic in nics:
            node_id, node_type = self._node_ip_to_node_id_and_type.get(nic['host'], DELETED_OBJECT_LABEL)
            self._nic_id_to_ip[nic['id']] = nic['host']
            self._nic_id_to_display_name[nic['id']] = nic['display_name']
            nic_active.add_metric((self._node_id_to_hostname[node_type].get(node_id, DELETED_OBJECT_LABEL), nic['display_name']), nic['state'] == 'up')
        yield nic_active
        
        fans = self._client.get('fans')
        fan_labels = ['box', 'location', 'title']
        fan_active = self._create_labeled_gauge('fan_active', 'Fan Active', labels=fan_labels)
        for fan in fans:
            fan_active.add_metric(extract_keys(fan, fan_labels), fan['state'] == 'OK')
            self._fan_id_to_info[fan['id']] = fan
        yield fan_active

        psus = self._client.get('psus')
        psu_labels = ['box', 'location', 'title']
        psu_active = self._create_labeled_gauge('psu_active', 'PSU Active', labels=psu_labels)
        for psu in psus:
            psu_active.add_metric(extract_keys(psu, psu_labels), psu['state'] == 'up')
            self._psu_id_to_info[psu['id']] = psu
        yield psu_active

        switch_labels = ['guid', 'ip', 'display_name', 'id', 'fw_version']
        switch_active = self._create_labeled_gauge('switch_active', 'Switch Active', labels=switch_labels)
        for switch in self._client.get('switches'):
            switch_active.add_metric(extract_keys(switch, switch_labels), switch['state'] == 'OK')
        yield switch_active

        if self._cluster_version >= (4, 3) and self._cluster_version < (4, 7):
            subnetmanagers = self._client.get('subnetmanager')    
            if subnetmanagers:
                subnetmanager, = subnetmanagers
                yield self._create_gauge('subnetmanager_active', 'Subnet Manager Active', subnetmanager['state'] == 'ACTIVE')
        elif self._cluster_version >= (4, 7):
            cnodes = self._client.get('cnodes')
            yield self._create_gauge('subnetmanager_active', 'Subnet Manager Active', any(cnode for cnode in cnodes if cnode['host_opensm_master'] is True))

    FLOW_METRICS = ['iops', 'md_iops', 'read_bw', 'read_iops', 'read_md_iops', 'write_bw', 'write_iops', 'write_md_iops', 'bw', 'latency'] # TBD: topn metrics only need bw/iops/latency

    def _collect_top_users(self):
        data = self._client.get('monitors/topn', {'key': 'user'})
        users_data = data.get("data", {}).get("user", {})

        user_labels = ['name', 'uid', 'more_info']
        for flow_metric in self.FLOW_METRICS:
            total_gauge = self._create_labeled_gauge(f'user_total_{flow_metric}',
                                                     f'User total {flow_metric} (MB/s)',
                                                     labels=user_labels)
            read_gauge = self._create_labeled_gauge(f'user_read_{flow_metric}',
                                                    f'User read {flow_metric} (MB/s)',
                                                    labels=user_labels)
            write_gauge = self._create_labeled_gauge(f'user_write_{flow_metric}',
                                                     f'User write {flow_metric} (MB/s)',
                                                     labels=user_labels)
            # Backward compat with 4.6
            backward_gauge = self._create_labeled_gauge(f'user_{flow_metric}', f'User {flow_metric} (MB/s)',
                                                        labels=user_labels)
            for user_data in users_data.get(flow_metric, []):
                title = user_data.get('title')
                if title:
                    # title is a composed string of name, uid and more_info field, sometimes name can contain whitespaces
                    # (name) 1234 [default]
                    # (name)  [default]
                    # (name)  1234
                    label_values = list(re.findall(r'(?:\((.+?)\))?\s?(\d+)?\s+\[(.+?)\]', title)[0])
                    if self._resolve_uid:
                        try:
                            name = pwd.getpwuid(int(label_values[1])).pw_name
                            label_values[0] = name
                        except (KeyError, ValueError):
                            pass
                    try:
                        total_gauge.add_metric(label_values, user_data['total'])
                        backward_gauge.add_metric(label_values, user_data['total'])
                        read_gauge.add_metric(label_values, user_data['read'])
                        write_gauge.add_metric(label_values, user_data['write'])
                    except Exception as e:
                        logger.error(f"Got error when trying to fetch metrics for user {label_values}, {e}")
                        ERROR_COUNTER.inc()
                        continue

            yield total_gauge
            yield read_gauge
            yield write_gauge
            yield backward_gauge

    def _collect_topn(self, key):
        data = self._client.get('monitors/topn', {'key': key})
        data = data.get('data', {}).get(key, {})

        for flow_metric in self.FLOW_METRICS:
            key_labels = ['title']
            total_gauge = self._create_labeled_gauge(f'{key}_total_{flow_metric}',
                                                     f'{key} total {flow_metric} (MB/s)',
                                                     labels=key_labels)
            read_gauge = self._create_labeled_gauge(f'{key}_read_{flow_metric}',
                                                    f'{key} read {flow_metric} (MB/s)',
                                                    labels=key_labels)
            write_gauge = self._create_labeled_gauge(f'{key}_write_{flow_metric}',
                                                     f'{key} write {flow_metric} (MB/s)',
                                                     labels=key_labels)
            for object_data in data.get(flow_metric, []):
                total_gauge.add_metric([object_data['title']], object_data['total'])
                read_gauge.add_metric([object_data['title']], object_data['read'])
                write_gauge.add_metric([object_data['title']], object_data['write'])

            yield total_gauge
            yield read_gauge
            yield write_gauge

    def _collect_top_vippools(self):
        if self._cluster_version < (5, 1):
            return
        yield from self._collect_topn('vippool')

    def _collect_top_vips(self):
        if self._cluster_version < (5, 1):
            return
        yield from self._collect_topn('vip')

    def _collect_views(self):
        views = self._client.get('views')
        view_labels = ['path', 'name', 'guid']
        view_logical_capacity = self._create_labeled_gauge('view_logical_capacity', 'View Logical Capacity', labels=view_labels)
        view_physical_capacity = self._create_labeled_gauge('view_physical_capacity', 'View Physical Capacity', labels=view_labels)
        path_to_view = {}
        self._view_id_to_view = {}
        for view in views:
            extracted_keys = extract_keys(view, view_labels)
            self._view_id_to_view[view['id']] = extracted_keys
            path_to_view[view['path']] = view
            view_logical_capacity.add_metric(extract_keys(view, view_labels), view['logical_capacity'])
            view_physical_capacity.add_metric(extract_keys(view, view_labels), view['physical_capacity']) 
        yield view_logical_capacity
        yield view_physical_capacity

    QUOTA_METRIC_TO_DESCRIPTION = {'used_inodes': 'Quota Used Inodes',
                                   'used_capacity': 'Quota Used Capacity',
                                   'soft_limit': 'Quota Soft Limit',
                                   'soft_limit_inodes': 'Quota Inodes Soft Limit',
                                   'hard_limit': 'Quota Hard Limit',
                                   'hard_limit_inodes': 'Quota Inodes Hard Limit'}
    def _collect_quotas(self):
        quota_metric_to_description = self.QUOTA_METRIC_TO_DESCRIPTION.copy()
        quota_metric_to_description.update({'num_exceeded_users': 'Quota Number Of Exceeded Users',
                                            'num_blocked_users': 'Quota Number Of Blocked Users'})
        
        quotas = self._client.get('quotas')
        quota_labels = ['path', 'title', 'guid']
        quota_ok = self._create_labeled_gauge('quota_ok', 'Quota State Is OK', labels=quota_labels)
        quota_gauges = {}
        for name, description in quota_metric_to_description.items():
            quota_gauges[name] = self._create_labeled_gauge('quota_' + name, description, labels=quota_labels)

        path_to_view = {}
        for quota in quotas:
            quota_ok.add_metric(extract_keys(quota, quota_labels), quota['state'] == 'OK')
            for name, metric in quota_gauges.items():
                if quota[name] is not None:
                    metric.add_metric(extract_keys(quota, quota_labels), quota[name])
        yield quota_ok
        for gauge in quota_gauges.values():
            yield gauge

        if self._should_collect_user_quotas:
            yield from self._collect_user_quotas(quotas)

    def _collect_user_quotas(self, quotas):
        quota_metric_to_description = self.QUOTA_METRIC_TO_DESCRIPTION.copy()
        quota_metric_to_description.update({'percent_capacity': 'Quota Capacity Percent Used',
                                            'percent_inodes': 'Quota Inodes Percent Used'})
        
        entity_labels = ['path', 'identifier']
        user_ok = self._create_labeled_gauge('user_quota_ok', 'User Quota State Is OK', labels=entity_labels)
        group_ok = self._create_labeled_gauge('group_quota_ok', 'Group Quota State Is OK', labels=entity_labels)
        user_gauges = {}
        group_gauges = {}
        for name, description in quota_metric_to_description.items():
            user_gauges[name] = self._create_labeled_gauge('user_quota_' + name, 'User ' + description, labels=entity_labels)
            group_gauges[name] = self._create_labeled_gauge('group_quota_' + name, 'Group ' + description, labels=entity_labels)

        for quota in quotas:
            result = self._client.get('userquotas', {'quota_system_id': quota['system_id']})
            for entity in result['results']:
                if entity['entity']['is_group']:
                    ok_gauge = group_ok
                    gauges = group_gauges
                else:
                    ok_gauge = user_ok
                    gauges = user_gauges
                identifier = entity['entity_identifier'] if 'entity_identifier' in entity else entity['entity_name'] # changed across VMS versions
                labels = (quota['path'], identifier)
                ok_gauge.add_metric(labels, entity['state'] == 'OK')
                for name, metric in gauges.items():
                    if entity[name] is not None:
                        metric.add_metric(labels, entity[name])
        yield user_ok
        yield group_ok
        yield from user_gauges.values()
        yield from group_gauges.values()

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

        vips = self._client.get('vips')
        vip_labels = ['cnode', 'hostname', 'vippool']
        vip_gauge = self._create_labeled_gauge('cnode_vippool', 'CNode-to-VIPPool association', labels=vip_labels)
        dups = set()
        for vip in vips:
            values = tuple(extract_keys(vip, vip_labels))
            if values in dups:
                continue
            dups.add(values)
            vip_gauge.add_metric(values, 1)
        yield vip_gauge

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
    collect_user_quotas = params.pop('collect_user_quotas')
    logging.basicConfig(format='%(asctime)s %(threadName)s %(levelname)s: %(message)s', level=logging.DEBUG if debug else logging.INFO)
    logger.info(f'VAST Exporter started running')
    start_http_server(port=port, addr=bind_address)
    client = VASTClient(**params)
    collector = VASTCollector(client, resolve_uid=resolve_uid, collect_top_users=collect_top_users, collect_user_quotas=collect_user_quotas)
    REGISTRY.register(collector)

    if test:
        success = collector.error_counter._value.get() == 0
        logger.info(f'Collection {"is successful!" if success else "failed!"}')
        sys.exit(0 if success else 1)
    else:
        while True: time.sleep(5)

if __name__ == '__main__':
    main()

"""Collector tests against a fake VMS client (no cluster needed).

Run: python -m pytest tests  (or python -m unittest discover tests)
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import vast_exporter  # noqa: E402


class FakeClient:
    def __init__(self, nics=None, views_delay=0.0, topn_users=None):
        self._nics = nics if nics is not None else [
            {'id': 1, 'host': '172.16.3.1', 'display_name': 'eth0', 'state': 'up'}]
        self._views_delay = views_delay
        self._topn_users = topn_users or {}

    def get(self, url, params=None):
        if url == 'clusters':
            return [{'name': 'c1', 'sw_version': '4.2.0.1', 'physical_space': 1, 'logical_space': 1,
                     'physical_space_in_use': 1, 'logical_space_in_use': 1, 'auxiliary_space_in_use': 1,
                     'drr': 1, 'state': 'ONLINE', 'nvram_raid_state': 'HEALTHY',
                     'ssd_raid_state': 'HEALTHY', 'memory_raid_state': 'HEALTHY'}]
        if url == 'cnodes':
            return [{'id': 1, 'ip': '172.16.3.1', 'hostname': 'cn1', 'name': 'cnode-1', 'guid': 'g1',
                     'is_mgmt': False, 'state': 'ACTIVE', 'os_version': '1', 'bios_version': '1',
                     'bmc_fw_version': '1', 'cbox_id': 1, 'cbox': 'cbox-1'}]
        if url == 'dnodes':
            return []
        if url in ('ssds', 'nvrams'):
            return [{'id': 1, 'guid': 'd1', 'title': 'disk', 'sn': 'sn1', 'state': 'ACTIVE'}]
        if url == 'nics':
            return self._nics
        if url in ('fans', 'psus'):
            return [{'id': 1, 'box': 'cbox-1', 'location': 'l', 'title': 't', 'state': 'OK'}]
        if url == 'switches':
            return []
        if url == 'views':
            time.sleep(self._views_delay)
            return [{'id': 7, 'path': '/v', 'name': 'v', 'guid': 'vg', 'logical_capacity': 1, 'physical_capacity': 1}]
        if url == 'quotas':
            return []
        if url in ('nis', 'ldaps', 'activedirectory', 'nativereplicationremotetargets',
                   'replicationtargets', 'vips'):
            return []
        if url == 'monitors/topn':
            return {'data': {'user': self._topn_users}}
        raise AssertionError(f'unexpected url {url}')


def _ad_hoc_factory(client):
    real_get = client.get

    def get(url, params=None):
        if url != 'monitors/ad_hoc_query':
            return real_get(url, params)
        scope = dict(params)['object_type']
        props = [v for k, v in params if k == 'prop_list']
        object_id = 7 if scope == 'view' else 1
        return {'prop_list': ['object_id'] + props, 'data': [[object_id] + [1.0] * len(props)]}
    client.get = get
    return client


def collect(client, **kw):
    collector = vast_exporter.VASTCollector(_ad_hoc_factory(client), **kw)
    errors_before = collector.error_counter._value.get()
    families = {m.name: m for m in collector.collect()}
    return families, collector.error_counter._value.get() - errors_before


class TestCollector(unittest.TestCase):
    def test_nic_of_unknown_node_does_not_drop_physical_metrics(self):
        nics = [{'id': 1, 'host': '172.16.3.1', 'display_name': 'eth0', 'state': 'up'},
                {'id': 2, 'host': '10.0.0.99', 'display_name': 'eth1', 'state': 'up'}]
        families, _ = collect(FakeClient(nics=nics))
        for name in ('vast_ssd_active', 'vast_nic_active', 'vast_fan_active', 'vast_psu_active'):
            self.assertIn(name, families)
        labels = sorted(s.labels['hostname'] for s in families['vast_nic_active'].samples)
        self.assertEqual(labels, ['DELETED', 'cn1'])

    def test_view_perf_metrics_present_on_first_scrape(self):
        # 'views' answers slower than the perf queries, as it does on a cluster with many views
        families, errors = collect(FakeClient(views_delay=0.3))
        name = 'vast_view_metrics_ViewMetrics_write_iops_count'
        self.assertIn(name, families)
        self.assertEqual([s.labels['name'] for s in families[name].samples], ['v'])

    def test_hardware_perf_metrics_present_on_first_scrape(self):
        families, _ = collect(FakeClient())
        self.assertTrue(families['vast_ssd_metrics_Hardware_temperature'].samples)
        self.assertTrue(families['vast_fan_metrics_Hardware_rpm'].samples)

    def test_bad_top_user_entry_counts_error_and_keeps_others(self):
        users = {'iops': [{'title': '(alice) 1001 [default]', 'total': 5}]}  # no read/write
        families, errors = collect(FakeClient(topn_users=users), collect_top_users=True)
        self.assertIn('vast_user_total_iops', families)
        self.assertGreaterEqual(errors, 1)


if __name__ == '__main__':
    unittest.main()

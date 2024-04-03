#!/usr/bin/env python3
import logging
import socket
import pwd
import re

logger = logging.getLogger(__name__)

def _get_best_family(address, port):
    """Automatically select address family depending on address"""
    # HTTPServer defaults to AF_INET, which will not start properly if
    # binding an ipv6 address is requested.
    # This function is based on what upstream python did for http.server
    # in https://github.com/python/cpython/pull/11767
    infos = socket.getaddrinfo(address, port)
    family, _, _, _, sockaddr = next(iter(infos))
    return family, sockaddr[0]

from wsgiref.simple_server import make_server, WSGIServer, WSGIRequestHandler

class _SilentHandler(WSGIRequestHandler):
    """WSGI handler that does not log requests."""

    def log_message(self, format, *args):
        """Log nothing."""

from socketserver import ThreadingMixIn

class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """Thread per request HTTP server."""
    # Make worker threads "fire and forget". Beginning with Python 3.7 this
    # prevents a memory leak because ``ThreadingMixIn`` starts to gather all
    # non-daemon threads in a list in order to join on them at server close.
    daemon_threads = True

import threading
from urllib.parse import parse_qs
from typing import Callable

def make_wsgi_app(collector) -> Callable:
    def prometheus_app(environ, start_response):
        # Prepare parameters
        accept_header = environ.get('HTTP_ACCEPT')
        accept_encoding_header = environ.get('HTTP_ACCEPT_ENCODING')
        params = parse_qs(environ.get('QUERY_STRING', ''))
        if environ['PATH_INFO'] == '/favicon.ico':
            # Serve empty response for browsers
            status = '200 OK'
            headers = [('', '')]
            output = b''
        else:
            # Bake output
            status, headers, output = _bake_output(collector, accept_header, accept_encoding_header, params, disable_compression=False)
        # Return output
        start_response(status, headers)
        return [output]

    return prometheus_app

def gzip_accepted(accept_encoding_header: str) -> bool:
    accept_encoding_header = accept_encoding_header or ''
    for accepted in accept_encoding_header.split(','):
        if accepted.split(';')[0].strip().lower() == 'gzip':
            return True
    return False

import gzip

def _bake_output(collector, accept_header, accept_encoding_header, params, disable_compression):
    output = collector.get_metrics()
    headers = [('Content-Type', 'text/plain')]
    # If gzip encoding required, gzip the output.
    if not disable_compression and gzip_accepted(accept_encoding_header):
        output = gzip.compress(output)
        headers.append(('Content-Encoding', 'gzip'))
    return '200 OK', headers, output

def start_wsgi_server(collector, port: int, addr: str = '0.0.0.0'):
    class TmpServer(ThreadingWSGIServer):
        """Copy of ThreadingWSGIServer to update address_family locally"""

    TmpServer.address_family, addr = _get_best_family(addr, port)
    app = make_wsgi_app(collector)
    httpd = make_server(addr, port, app, TmpServer, handler_class=_SilentHandler)
    httpd.serve_forever()

import urllib3
import http
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RESTFailure(Exception): pass

class ProxyCollector():
    def __init__(self, user, password, address, cert_file=None, cert_server_name=None):
        self._user = user
        self._password = password
        self._address = address
        self._cert_file = cert_file
        self._cert_server_name = cert_server_name

    def _request(self, method, url, params=None):
        if self._cert_file:
            pm = urllib3.PoolManager(ca_certs=self._cert_file, server_hostname=self._cert_server_name)
        else:
            pm = urllib3.PoolManager(cert_reqs='CERT_NONE')
        headers = urllib3.make_headers(basic_auth=self._user + ':' + self._password)
        logger.debug(f'Sending request with url={url} and parameters={params}')
        r = pm.request(method, 'https://{}/api/{}'.format(self._address, url), headers=headers, fields=params)
        if r.status != http.HTTPStatus.OK:
            raise RESTFailure(f'Response for request {url} with {params} failed with error {r.status} and message {r.data}')
        return r

    def _resolve_uid(self, match):
        uid = match.group(1)
        try:
            numeric = int(uid)
        except ValueError:
            name = uid
        else:
            try:
                name = pwd.getpwuid(numeric).pw_name
            except KeyError:
                name = uid
        return f'uid="{name}"'

    def get_metrics(self):
        response = self._request('GET', '/prometheusmetrics/all')
        output = []
        for line in response.data.decode('utf-8').split('\n'):
            if line.startswith('vast_user_'):
                line = re.sub('uid="(.*?)"', self._resolve_uid, line)
            output.append(line)
        return '\n'.join(output).encode('utf-8')

import os
import argparse

DEFAULT_PORT = 8000

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
    add_argument('VAST_COLLECTOR_DEBUG', '--debug', action='store_true', help='Drop into a debugger on error')
    add_argument('VAST_COLLECTOR_TEST', '--test', action='store_true',
                 help='Run the collector once and indicate whether it succeeded in the return code')
    return parser.parse_args()

def main():
    args = parse_args()
    logging.basicConfig(format='%(asctime)s %(threadName)s %(levelname)s: %(message)s', level=logging.DEBUG if args.debug else logging.INFO)
    logger.info(f'VAST Exporter started running')
    collector = ProxyCollector(args.user,
                               args.password,
                               args.address,
                               args.cert_file,
                               args.cert_server_name)
    if args.test:
        print(collector.get_metrics().decode('utf-8'))
    else:
        start_wsgi_server(collector, port=args.port, addr=args.bind_address)

if __name__ == '__main__':
    main()

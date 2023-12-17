
VAST Prometheus Exporter
========================

The Prometheus exporter connects to VMS and leverages its REST API to extract state and metric information.
It listens to port 8000 by default. This can be changed using the --port parameter.

> **_NOTE:_**  The VMS hosts an internal Prometheus Exporter as of version 4.5 documented [here](https://support.vastdata.com/hc/en-us/articles/9859963180956-Exporting-Metrics-to-Prometheus).
The external Prometheus Exporter is not supported as of version 4.7.

Content
-------

1. Cluster capacity and states.
2. Physical component states (NIC, node, drive, etc').
3. Logical objects: view, quota, replication targets, etc'.
4. Performance metrics (BW/IOPS/latency/etc') for cluster, nodes, views and top users.

Pre-requisities
---------------

Cluster of version 4.2 and up.

Docker Installation
-------------------

    # build a local docker image
    $ ./build.sh
    # run a docker container in the background
    $ ./run.sh --user=<USER> --password=<PASSWORD> --address=<ADDRESS>

Python Installation
-------------------

    $ pip install -r requirements.txt
    $ ./vast_exporter.py --user=<USER> --password=<PASSWORD> --address=<ADDRESS>


Usage
-----

Beyond the user/password/address parameters which are required there are optional parameters.
Optional features inlude specifying a custom SSL certificate and collection of top user performance data.
Run the exporter with --help to see a description.

Testing
-------

To run the exporter once and make sure no errors are raised run the following:

    $ ./vast_exporter.py --user=<USER> --password=<PASSWORD> --address=<ADDRESS> --test
    2022-04-28 11:36:47,045 MainThread INFO: VAST Exporter started running. Listening on port 8001
    2022-04-28 11:36:58,658 MainThread INFO: Collection is successful!

To run the exporter forever remove the --test parameter and get the output using curl:

    $ curl http://localhost:8000 | grep vast_collector
    # HELP vast_collector_latency Total collection time
    # TYPE vast_collector_latency summary
    vast_collector_latency_count 1.0
    vast_collector_latency_sum 7.011876339
    ...


Monitoring
----------

Besides the obious stdout output where errors will land, the following metric will be incremeneted upon an error:

    vast_collector_errors_total

Prometheus Config
-----------------

Full explanation of Prometheus configuration here: https://prometheus.io/docs/prometheus/latest/configuration/configuration/

The following snippet shows how to add the VAST exporter to Prometheus:

    # A scrape configuration containing exactly one endpoint to scrape:
    # Here it's Prometheus itself.
    scrape_configs:
      # The job name is added as a label `job=<job_name>` to any timeseries scraped from this config.
      - job_name: "vast"

        # metrics_path defaults to '/metrics'
        # scheme defaults to 'http'.
        scrape_interval: 1m
        scrape_timeout: 50s
        
        static_configs:
          - targets: ["<EXPORTER HOST>:8000"]

How to run Prometheus using docker:

    docker run -p 9090:9090 -v /path/to/prometheus.yml:/etc/prometheus/prometheus.yml prom/prometheus

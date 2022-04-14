
VAST Prometheus Exporter
========================

The Prometheus exporter connects to VMS and leverages its REST API to extract state and metric information.
It listens to port 8000 by default. This can be changed using the --port parameter.

Installation Using Docker
-------------------------

    # build a local docker image
    $ ./build.sh
    # run a docker container in the background
    $ ./run.sh --user=<USER> --password=<PASSWORD> --address=<ADDRESS>

Installation Using Python
-------------------------

    $ pip install -r requirements.txt
    $ ./vast_exporter.py --user=<USER> --password=<PASSWORD> --address=<ADDRESS>

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

        static_configs:
          - targets: ["<EXPORTER HOST>:8000"]

How to run Prometheus using docker:

    docker run -p 9090:9090 -v /path/to/prometheus.yml:/etc/prometheus/prometheus.yml prom/prometheus
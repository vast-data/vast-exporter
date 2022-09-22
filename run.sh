set -eax

docker run -d --name=vast-exporter -p 8000:8000 --rm vast_exporter /vast_exporter.py "$@"

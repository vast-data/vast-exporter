FROM python:3.9-alpine

EXPOSE 8000/tcp

COPY requirements.txt /
COPY vast_exporter.py /
RUN pip install -r /requirements.txt

CMD ["/vast_exporter.py", "--help"]

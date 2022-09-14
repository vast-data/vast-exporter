FROM python:3.9-alpine

EXPOSE 8000/tcp

COPY requirements.txt /
RUN pip install -r /requirements.txt

COPY vast_exporter.py /

CMD ["/vast_exporter.py", "--help"]

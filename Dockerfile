FROM python:3.9-alpine

EXPOSE 8000/tcp

COPY requirements.txt /
COPY main.py /
RUN pip install -r /requirements.txt

CMD ["/main.py", "--help"]
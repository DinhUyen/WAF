FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir -p /opt/mparser/
COPY requirements.txt /opt/mparser/

RUN apt-get update && apt-get install -y git && \
  apt-get install -y wget && \
  apt-get install -y python3 python3-pip
  #python3-matplotlib python3-numpy python3-pandas python3-openpyxl

RUN pip3 install -r /opt/mparser/requirements.txt

COPY modsecurity_parser.py /opt/mparser/

WORKDIR /opt/mparser/

CMD ["python3", "modsecurity_parser.py"]
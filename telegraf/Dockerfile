FROM telegraf:1.23.3

RUN apt-get update
RUN apt-get install -y build-essential python3-dev python3-setuptools python3-pip
COPY ./requirements.txt /tmp/requirements.txt
RUN pip3 install --upgrade pip
RUN pip3 install -r /tmp/requirements.txt
COPY ./telegraf.conf.j2 /telegraf.conf.j2
COPY ./entrypoint-shim.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

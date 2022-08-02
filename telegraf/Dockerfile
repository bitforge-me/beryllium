FROM telegraf:1.23.3

# install requirements for jinja2-cli
RUN apt-get update
RUN apt-get install -y build-essential python3-dev python3-setuptools python3-pip
COPY ./requirements.txt /tmp/requirements.txt
RUN pip3 install --upgrade pip
RUN pip3 install -r /tmp/requirements.txt

# place telegraf config template (will be converted by entrypoint shim)
COPY ./telegraf.conf.j2 /tmp/telegraf.conf.j2

# run entrypoint shim
COPY ./entrypoint-shim.sh /entrypoint-shim.sh
RUN chmod +x /entrypoint-shim.sh
ENTRYPOINT ["/entrypoint-shim.sh"]
CMD ["telegraf"]
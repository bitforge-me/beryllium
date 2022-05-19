FROM elementsproject/lightningd:v0.11.0.1

RUN apt-get update
RUN apt-get install -y build-essential python3-dev python3-setuptools
COPY ./requirements.txt /tmp/requirements.txt
RUN pip3 install --upgrade pip
RUN pip3 install -r /tmp/requirements.txt
COPY ./rebalance.py /etc/bundledplugins/
### copy docker-entrypoint from https://github.com/ElementsProject/lightning
### and modified entrypoint to include the --wallet switch
COPY ./docker-entrypoint.sh /entrypoint.sh
RUN chmod 777 /entrypoint.sh
### create a backup dir
RUN mkdir /opt/backup

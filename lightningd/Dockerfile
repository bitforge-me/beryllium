FROM elementsproject/lightningd:v0.11.1

RUN apt-get update
RUN apt-get install -y build-essential python3-dev python3-setuptools
COPY ./requirements.txt /tmp/requirements.txt
RUN pip3 install --upgrade pip
RUN pip3 install -r /tmp/requirements.txt
COPY ./rebalance.py /etc/bundledplugins/

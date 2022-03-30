FROM btcpayserver/lightning:v0.10.1-2

RUN apt-get update
RUN apt-get install -y python3-setuptools
COPY ./requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt
COPY ./rebalance.py /etc/bundledplugins/
RUN chmod +x /root/.lightning/plugins/*

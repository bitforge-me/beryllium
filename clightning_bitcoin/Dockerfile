FROM btcpayserver/lightning:v0.10.1-2

COPY ./requirements.txt /tmp/requirements.txt
COPY ./rebalance.py /etc/bundledplugins/
RUN apt-get update && pip3 install -r /tmp/requirements.txt 
RUN chmod +x /root/.lightning/plugins/*

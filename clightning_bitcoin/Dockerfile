FROM btcpayserver/lightning:v0.10.1-2

### 1ml.com node
#ENV NODE_ADDRESS 02312627fdf07fbdd7e5ddb136611bdde9b00d26821d14d94891395452f67af248@23.237.77.12:9735

#COPY ./config /root/.lightning/
COPY ./requirements.txt /tmp/requirements.txt
#COPY ./rebalance.py /root/.lightning/plugins/
#RUN mkdir /opt/lightning_plugins/
### entrypoint.sh is overwriting /root/.lightning/plugins. So adding "rebalance.py" to the source directory before getting copied over
COPY ./rebalance.py /etc/bundledplugins/
#COPY ./rebalance.py /opt/lightning_plugins/
RUN apt-get update && pip3 install -r /tmp/requirements.txt 
RUN chmod +x /root/.lightning/plugins/*

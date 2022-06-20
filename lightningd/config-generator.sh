#!/bin/bash

### GET ENV VARIABLES
bitcoin_datadir=$(printenv|grep bitcoin-datadir|awk -F"=" '{print $3}')
lightning_datadir=$(printenv|grep LIGHTNINGD_DATA|awk -F"=" '{print $2}')
bitcoin_rpcconnect=$(printenv|grep bitcoin-rpcconnect|awk -F"=" '{print $2}')
bind_addr=$(printenv|grep LIGHTNINGD_PORT|awk -F"=" '{print $2}')
network=$(printenv|grep LIGHTNINGD_NETWORK|awk -F"=" '{print $2}')
alias=$(printenv|grep LIGHTNINGD_ALIAS|awk -F"=" '{print $2}')
rpcfile=${lightning_datadir}/lightning-rpc

### CREATE CONFIG FROM ENV VARIABLES
echo "bitcoin-datadir=${bitcoin_datadir}" > $lightning_datadir/config
echo "bitcoin-rpcconnect=${bitcoin_rpcconnect}" >> $lightning_datadir/config
echo  >> $lightning_datadir/config
echo "bind-addr=0.0.0.0:${bind_addr}" >> $lightning_datadir/config
echo "network=${network}" >> $lightning_datadir/config
echo "alias=${alias}" >> $lightning_datadir/config
echo "rpc-file=${rpcfile}" >> $lightning_datadir/config


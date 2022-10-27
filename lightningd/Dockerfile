FROM elementsproject/lightningd:v0.12.1

# we need a staging directory because we cannot modify $LIGHTNINGD_DATA
# directly as the parent image declares 'VOLUME $LIGHTNINGD_DATA' and
# so subsequent changes to that directory (in dockerfiles) are discarded (https://docs.docker.com/engine/reference/builder/#notes-about-specifying-volumes)
ENV LN_WORK=/tmp/ln_working_dir
RUN mkdir $LN_WORK

# install requirements for rebalance plugin and jinja2 cli templates
RUN apt-get update
RUN apt-get install -y build-essential python3-dev python3-setuptools
COPY ./requirements.txt $LN_WORK/requirements.txt
RUN pip3 install --upgrade pip
RUN pip3 install -r $LN_WORK/requirements.txt

# install rebalance plugin in staging directory (will be moved into $LIGHTNINGD_DATA/plugins in entrypoint-shim.sh)
COPY ./rebalance.py $LN_WORK

# copy config template to staging directory (will be converted to config at runtime in entrypoint-shim.sh)
COPY ./config.j2 $LN_WORK/config.j2

# make directory for for lightningd '--wallet' replica
RUN mkdir /root/.lightning_replica

# run our entrypoint shim
COPY ./entrypoint-shim.sh /entrypoint-shim.sh
RUN chmod +x /entrypoint-shim.sh
ENTRYPOINT [ "/usr/bin/tini", "-g", "--", "./entrypoint-shim.sh"]

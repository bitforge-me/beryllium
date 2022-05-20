#!/bin/bash

pylint --version
pylint `ls -R|grep .py$|xargs` \
    --disable=fixme,line-too-long,unused-argument,missing-module-docstring,missing-function-docstring,missing-class-docstring,no-self-use \
    --variable-rgx="[a-z_][a-z0-9_]{0,30}$" \
    --load-plugins=pylint_flask_sqlalchemy,pylint_flask \
    --max-parents=10 --max-args=12 --max-branches=18 --max-returns=12 --max-locals=20 --min-similarity-lines=8 --max-attributes=10 --max-locals=25 --max-statements=60 \
    --extension-pkg-whitelist=pyblake2,axolotl_curve25519,math \
    --ignored-classes=scoped_session \
    --ignore=rebalance.py

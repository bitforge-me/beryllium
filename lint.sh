#!/bin/bash

set -e

echo '# linting html files with djlint..'
djlint --version
djlint --ignore H029,H006,H021,H030,H031,H020 --lint --extension html templates
djlint --check --extension html templates

echo '# linting html/js files with eslint..'
npx eslint 'static/assets/js_custom/*'

# see https://www.flake8rules.com/ for description of rules
echo '# linting python files with pycodestyle..'
pycodestyle --version
# TODO review and remove some ignores
pycodestyle --statistics --ignore E265,E722,E261,E501,E301,E302,E305,E121,E123,E126,E133,E226,E241,E242,E704,W503,W504,W505 `ls|grep .py$|xargs`

echo '# linting python files with mypy..'
mypy --version
mypy app.py --ignore-missing-imports

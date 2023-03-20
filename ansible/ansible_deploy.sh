#!/bin/bash

set -e

DEPLOY_TEST=test
DEPLOY_PRODUCTION=production
DEPLOY_CUSTOM='<user>@<host>'
DEPLOY_TYPE=$1
DEPLOY_LEVEL_BERYLLIUM_ONLY=beryllium_only
DEPLOY_LEVEL=$2
DEPLOY_BRANCH=$3

display_usage() { 
    echo -e "\nUsage:

    ansible_deploy.sh <DEPLOY_TYPE ($DEPLOY_TEST | $DEPLOY_PRODUCTION | $DEPLOY_CUSTOM)> 

    ansible_deploy.sh <DEPLOY_TYPE ($DEPLOY_TEST | $DEPLOY_PRODUCTION | $DEPLOY_CUSTOM)> <DEPLOY_LEVEL ($DEPLOY_LEVEL_BERYLLIUM_ONLY)>

    ansible_deploy.sh <DEPLOY_TYPE ($DEPLOY_TEST | $DEPLOY_PRODUCTION | $DEPLOY_CUSTOM)> <DEPLOY_LEVEL ($DEPLOY_LEVEL_BERYLLIUM_ONLY)> <DEPLOY_BRANCH (any git branch)>

        This is a lesser deploy scenario:

        DEPLOY_LEVEL=$DEPLOY_LEVEL_BERYLLIUM_ONLY: only update the beryllium service
    "
}

function validate_ssh_host() {
    local input="$DEPLOY_TYPE"
    if [[ "$input" =~ ^[^@]+@[^@]+$ ]]; then
        echo 0
    else
        echo 1
    fi
}

function parse_ssh_host() {
  local input="$DEPLOY_TYPE"
  DEPLOY_USER="${input%%@*}"
  DEPLOY_HOST="${input#*@}"
}

# if less than two arguments supplied, display usage 
if [ $# -le 0 ]
then 
    display_usage
    exit 1
fi 

# check whether user had supplied -h or --help . If yes display usage 
if [[ ( $@ == "--help" ) ||  ( $@ == "-h" ) ]] 
then 
    display_usage
    exit 0
fi 

# check whether user has a valid DEPLOY_TYPE
ssh_host_valid=`validate_ssh_host`
if [[ ( $DEPLOY_TYPE != "test" ) &&  ( $DEPLOY_TYPE != "production" )  && ( $ssh_host_valid != 0 ) ]] 
then
    display_usage
    echo !!\"$DEPLOY_TYPE\" is not valid
    exit 2
fi 

# check whether we have a valid deploy level
if [ $# -ge 2 ]
then 
    # a lesser deployment
    if [[ ( "$DEPLOY_LEVEL" != "$DEPLOY_LEVEL_BERYLLIUM_ONLY" ) ]]
    then
        display_usage
        echo !!\"$DEPLOY_LEVEL\" is not valid
        exit 2
    fi
    FULL_DEPLOY=
else
    DEPLOY_LEVEL=full
    FULL_DEPLOY=true
fi 

# check whether we have a valid deploy branch
if [ $# -ge 3 ]
then
    DEPLOY_BRANCH=$3
else
    DEPLOY_BRANCH=master
fi 

ADMIN_EMAIL=admin@zap.me
if [[ ( $DEPLOY_TYPE == $DEPLOY_PRODUCTION)]]
then
    # set deploy variables for production
    DEPLOY_HOST=beryllium.zap.me
    DEPLOY_USER=root
    TESTNET=
    SSH_DISALLOW_ROOT=true
elif [[ ( $DEPLOY_TYPE == "test" ) ]]
then 
    # set deploy variables for test
    DEPLOY_HOST=beryllium-test.zap.me
    DEPLOY_USER=root
    TESTNET=true
    SSH_DISALLOW_ROOT=
else
    # set deploy variables for custom host
    parse_ssh_host
    TESTNET=true
    SSH_DISALLOW_ROOT=  
fi 

# print variables
echo ":: DEPLOYMENT DETAILS ::"
echo "   - DEPLOY_HOST:     $DEPLOY_HOST"
echo "   - DEPLOY_LEVEL:    $DEPLOY_LEVEL"
echo "   - DEPLOY_BRANCH:   $DEPLOY_BRANCH"
echo "   - TESTNET:         $TESTNET"
echo "   - ADMIN_EMAIL:     $ADMIN_EMAIL"
echo "   - DEPLOY_USER:     $DEPLOY_USER"

# ask user to continue
read -p "Are you sure? " -n 1 -r
echo # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
    # do dangerous stuff
    echo ok lets go!!!
    ansible-playbook --inventory "$DEPLOY_HOST," --user "$DEPLOY_USER" -v \
        --extra-vars "admin_email=$ADMIN_EMAIL deploy_host=$DEPLOY_HOST full_deploy=$FULL_DEPLOY testnet=$TESTNET ssh_disallow_root=$SSH_DISALLOW_ROOT DEPLOY_TYPE=$DEPLOY_TYPE deploy_branch=$DEPLOY_BRANCH" \
        deploy.yml
fi

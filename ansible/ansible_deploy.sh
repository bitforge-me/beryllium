#!/bin/bash

set -e

DEPLOY_TEST=test
DEPLOY_PRODUCTION=production
DEPLOY_TYPE=$1
DEPLOY_LEVEL_BERYLLIUM_ONLY=beryllium_only
DEPLOY_LEVEL=$2
DEPLOY_BRANCH=$3

display_usage() { 
    echo -e "\nUsage:

    ansible_deploy.sh <DEPLOY_TYPE ($DEPLOY_TEST | $DEPLOY_PRODUCTION)> 

    ansible_deploy.sh <DEPLOY_TYPE ($DEPLOY_TEST | $DEPLOY_PRODUCTION)> <DEPLOY_LEVEL ($DEPLOY_LEVEL_BERYLLIUM_ONLY)>

    ansible_deploy.sh <DEPLOY_TYPE ($DEPLOY_TEST | $DEPLOY_PRODUCTION)> <DEPLOY_LEVEL ($DEPLOY_LEVEL_BERYLLIUM_ONLY)> <DEPLOY_BRANCH (any git branch)>

        This is a lesser deploy scenario:

        DEPLOY_LEVEL=$DEPLOY_LEVEL_BERYLLIUM_ONLY: only update the beryllium service
    "
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
if [[ ( $DEPLOY_TYPE != "test" ) &&  ( $DEPLOY_TYPE != "production" ) ]] 
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
# set deploy variables for production
DEPLOY_HOST=beryllium.zap.me
DEPLOY_USER=root
TESTNET=

# set deploy variables for test
if [[ ( $DEPLOY_TYPE == "test" ) ]]
then 
    DEPLOY_HOST=beryllium-test.zap.me
    DEPLOY_USER=root
    TESTNET=true
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
        --extra-vars "admin_email=$ADMIN_EMAIL deploy_host=$DEPLOY_HOST full_deploy=$FULL_DEPLOY testnet=$TESTNET DEPLOY_TYPE=$DEPLOY_TYPE deploy_branch=$DEPLOY_BRANCH" \
        deploy.yml
fi

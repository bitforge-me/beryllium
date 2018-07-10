#!/bin/bash

DEPLOY_TEST=test
DEPLOY_PRODUCTION=production
DEPLOY_TYPE=$1

display_usage() { 
    echo -e "\nUsage:\nansible_deploy.sh <DEPLOY_TYPE ($DEPLOY_TEST | $DEPLOY_PRODUCTION)>\n" 
} 

# if less than one arguments supplied, display usage 
if [  $# -le 0 ] 
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
    exit 0
fi 

ADMIN_EMAIL=admin@zap.me
VAGRANT=false
# set deploy variables for production
DEPLOY_HOST=mainnet.zap.me
DEPLOY_USER=root
TESTNET=true
# set deploy variables for test
if [[ ( $DEPLOY_TYPE == "test" ) ]]
then 
    DEPLOY_HOST=testnet.zap.me
    DEPLOY_USER=root
    TESTNET=false
fi 

# print variables
echo ":: DEPLOYMENT DETAILS ::"
echo "   - ADMIN_EMAIL: $ADMIN_EMAIL"
echo "   - DEPLOY_HOST: $DEPLOY_HOST"
echo "   - DEPLOY_USER: $DEPLOY_USER"

# ask user to continue
read -p "Are you sure? " -n 1 -r
echo # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
    # do dangerous stuff
    echo ok lets go!!!
    ansible-playbook --inventory "$DEPLOY_HOST," --user "$DEPLOY_USER" -v \
        --extra-vars "ADMIN_EMAIL=$ADMIN_EMAIL DEPLOY_HOST=$DEPLOY_HOST VAGRANT=$VAGRANT TESTNET=$TESTNET" \
        ansible/deploy.yml
fi

#!/bin/bash

DEPLOY_TEST=test
DEPLOY_PRODUCTION=production
DEPLOY_TYPE=$1
BACKUP_KEY=$2
BACKUP_SSH_KEY=$3

display_usage() { 
    echo -e "\nUsage:

    ansible_deploy.sh <DEPLOY_TYPE ($DEPLOY_TEST | $DEPLOY_PRODUCTION)> <BACKUP_KEY> <BACKUP_SSH_KEY>

        BACKUP_KEY: the **public** GPG key used to encrypt backups
                    (use \"gpg --armor --export <KEY_NAME> > backup_key.asc\" to export public key)

        BACKUP_SSH_KEY: the **private** SSH key used to log in to the backup server

    "
} 

# if less than two arguments supplied, display usage 
if [  $# -le 2 ]
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

# check whether backup key exists
if [ ! -f "$BACKUP_KEY" ]
then
    display_usage
    echo !!\"$BACKUP_KEY\" does not exist
    exit 3
fi
BACKUP_KEY=`realpath $BACKUP_KEY`

# check whether backup ssh key exists
if [ ! -f "$BACKUP_SSH_KEY" ]
then 
    display_usage
    echo !!\"$BACKUP_SSH_KEY\" does not exist
    exit 3
fi 
BACKUP_SSH_KEY=`realpath $BACKUP_SSH_KEY`

ADMIN_EMAIL=admin@zap.me
VAGRANT=false
BACKUP_HOST=backup.zap.me
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
echo "   - BACKUP_KEY: $BACKUP_KEY"
echo "   - BACKUP_SSH_KEY: $BACKUP_KEY"
echo "   - BACKUP_HOST: $BACKUP_HOST"

# ask user to continue
read -p "Are you sure? " -n 1 -r
echo # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
    # do dangerous stuff
    echo ok lets go!!!
    ansible-playbook --inventory "$DEPLOY_HOST," --user "$DEPLOY_USER" -v \
        --extra-vars "ADMIN_EMAIL=$ADMIN_EMAIL DEPLOY_HOST=$DEPLOY_HOST BACKUP_KEY='$BACKUP_KEY' BACKUP_SSH_KEY='$BACKUP_SSH_KEY' BACKUP_HOST=$BACKUP_HOST VAGRANT=$VAGRANT TESTNET=$TESTNET" \
        ansible/deploy.yml
fi

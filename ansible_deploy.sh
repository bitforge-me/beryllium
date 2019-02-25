#!/bin/bash

DEPLOY_TEST=test
DEPLOY_PRODUCTION=production
DEPLOY_TYPE=$1
BACKUP_KEY=$2
BACKUP_SSH_KEY=$3
WEBHOOK_URL=$4
WEBHOOK_KEY=$5

display_usage() { 
    echo -e "\nUsage:

    ansible_deploy.sh <DEPLOY_TYPE ($DEPLOY_TEST | $DEPLOY_PRODUCTION)> <BACKUP_KEY> <BACKUP_SSH_KEY> <WEBHOOK_URL> <WEBHOOK_KEY>

        BACKUP_KEY: the **public** GPG key used to encrypt backups
                    (use \"gpg --armor --export <KEY_NAME> > backup_key.asc\" to export public key)

        BACKUP_SSH_KEY: the **private** SSH key used to log in to the backup server

        WEBHOOK_URL: the URL for incomming transaction notifications

        WEBHOOK_KEY: the key to sign the transaction notifications with

    "
} 

# if less than two arguments supplied, display usage 
if [  $# -le 4 ]
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
ALERT_EMAIL=alerts@zap.me
VAGRANT=false
BACKUP_HOST=backup.zap.me
# set deploy variables for production
DEPLOY_HOST=mainnet.zap.me
DEPLOY_USER=root
REMOTE_WAVES_NODES=nodes.wavesnodes.com
TESTNET=
# set deploy variables for test
if [[ ( $DEPLOY_TYPE == "test" ) ]]
then 
    DEPLOY_HOST=testnet.zap.me
    DEPLOY_USER=root
    REMOTE_WAVES_NODES=testnet1.wavesnodes.com
    TESTNET=true
fi 

# create archive
(cd zapd; git archive --format=zip HEAD > ../zapd.zip)

# print variables
echo ":: DEPLOYMENT DETAILS ::"
echo "   - TESTNET: $TESTNET"
echo "   - ADMIN_EMAIL: $ADMIN_EMAIL"
echo "   - ALERT_EMAIL: $ALERT_EMAIL"
echo "   - DEPLOY_HOST: $DEPLOY_HOST"
echo "   - DEPLOY_USER: $DEPLOY_USER"
echo "   - BACKUP_KEY: $BACKUP_KEY"
echo "   - BACKUP_SSH_KEY: $BACKUP_SSH_KEY"
echo "   - BACKUP_HOST: $BACKUP_HOST"
echo "   - WEBHOOK_URL: $WEBHOOK_URL"
echo "   - WEBHOOK_KEY: $WEBHOOK_KEY"
echo "   - REMOTE_WAVES_NODES: $REMOTE_WAVES_NODES"
echo "   - ZAPD_ARCIVCE: zapd.zip"

# ask user to continue
read -p "Are you sure? " -n 1 -r
echo # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
    # do dangerous stuff
    echo ok lets go!!!
    ansible-playbook --inventory "$DEPLOY_HOST," --user "$DEPLOY_USER" -v \
        --extra-vars "ADMIN_EMAIL=$ADMIN_EMAIL ALERT_EMAIL=$ALERT_EMAIL DEPLOY_HOST=$DEPLOY_HOST BACKUP_KEY='$BACKUP_KEY' BACKUP_SSH_KEY='$BACKUP_SSH_KEY' BACKUP_HOST=$BACKUP_HOST WEBHOOK_URL=$WEBHOOK_URL WEBHOOK_KEY=$WEBHOOK_KEY REMOTE_WAVES_NODES=$REMOTE_WAVES_NODES VAGRANT=$VAGRANT TESTNET=$TESTNET" \
        ansible/deploy.yml
fi

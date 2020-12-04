#!/bin/bash

DEPLOY_TEST=test
DEPLOY_PRODUCTION=production
DEPLOY_TYPE=$1
DEPLOY_LEVEL_ZAPD_ONLY=zapd_only
DEPLOY_LEVEL_NO_KEYS=no_keys
DEPLOY_LEVEL=$2
BACKUP_KEY=$2
BACKUP_SSH_KEY=$3
SENDGRID_API_KEY=$4

display_usage() { 
    echo -e "\nUsage:

    ansible_deploy.sh <DEPLOY_TYPE ($DEPLOY_TEST | $DEPLOY_PRODUCTION)> <BACKUP_KEY> <BACKUP_SSH_KEY> <SENDGRID_API_KEY>

        This is the full deploy scenario, required for initial deployment:

        BACKUP_KEY: the **public** GPG key used to encrypt backups
                    (use \"gpg --armor --export <KEY_NAME> > backup_key.asc\" to export public key)

        BACKUP_SSH_KEY: the **private** SSH key used to log in to the backup server

        SENDGRID_API_KEY: the api key to use with sendgrid for sending emails

    ansible_deploy.sh <DEPLOY_TYPE ($DEPLOY_TEST | $DEPLOY_PRODUCTION)> <DEPLOY_LEVEL ($DEPLOY_LEVEL_ZAPD_ONLY | $DEPLOY_LEVEL_NO_KEYS)>
        
        This is a lesser deploy scenario:

        DEPLOY_LEVEL=$DEPLOY_LEVEL_ZAPD_ONLY: only update the zapd service

        DEPLOY_LEVEL=$DEPLOY_LEVEL_NO_KEYS: almost a full deploy but without the backup keys as those steps are skipped
    "
} 

KEYS_SUPPLIED=true
FULL_DEPLOY=true

if [ $# == 2 ]
then
    ## A lesser deployment

    ## check whether user has a valid DEPLOY_LEVEL
    if [[ ( "$DEPLOY_LEVEL" != "$DEPLOY_LEVEL_NO_KEYS" ) && ( "$DEPLOY_LEVEL" != "$DEPLOY_LEVEL_ZAPD_ONLY" ) ]] 
    then
        display_usage
        echo !!\"$DEPLOY_LEVEL\" is not valid
        exit 2
    fi
    KEYS_SUPPLIED=
    BACKUP_KEY=
    BACKUP_SSH_KEY=
    if [[ "$DEPLOY_LEVEL" == "$DEPLOY_LEVEL_ZAPD_ONLY" ]]; then
        FULL_DEPLOY=
    fi
elif [[ ( $# -le 5 ) || ( $# -gt 6 ) ]]
then
    ## if less than four arguments supplied, display usage 
    display_usage
    exit 1
else
    DEPLOY_LEVEL=full
fi 

## check whether user had supplied -h or --help . If yes display usage 
if [[ ( $@ == "--help" ) ||  ( $@ == "-h" ) ]] 
then 
    display_usage
    exit 0
fi 

## check whether user has a valid DEPLOY_TYPE
if [[ ( $DEPLOY_TYPE != "test" ) &&  ( $DEPLOY_TYPE != "production" ) ]] 
then 
    display_usage
    echo !!\"$DEPLOY_TYPE\" is not valid
    exit 2
fi 

if [[ "$KEYS_SUPPLIED" == "true" ]]
then
    ## check whether backup key exists
    if [[ ! -f "$BACKUP_KEY" ]]
    then
        display_usage
        echo !!\"$BACKUP_KEY\" does not exist
        exit 3
    fi
    BACKUP_KEY=`realpath $BACKUP_KEY`

    ## check whether backup ssh key exists
    if [[ ! -f "$BACKUP_SSH_KEY" ]]
    then
        display_usage
        echo !!\"$BACKUP_SSH_KEY\" does not exist
        exit 3
    fi
    BACKUP_SSH_KEY=`realpath $BACKUP_SSH_KEY`
fi

ADMIN_EMAIL=admin@zap.me
ALERT_EMAIL=alerts@zap.me
VAGRANT=
BACKUP_HOST=backup.zap.me
## set deploy variables for production
DEPLOY_HOST=mainnet.zap.me
DEPLOY_USER=root
REMOTE_WAVES_NODES=nodes.wavesnodes.com
TESTNET=
## set deploy variables for test
if [[ ( $DEPLOY_TYPE == "test" ) ]]
then 
    DEPLOY_HOST=testnet.zap.me
    DEPLOY_USER=root
    REMOTE_WAVES_NODES=testnet1.wavesnodes.com
    TESTNET=true
fi 

## create archive
(cd zapd; git archive --format=zip HEAD > ../zapd.zip)

## print variables
echo ":: DEPLOYMENT DETAILS ::"
echo "   - DEPLOY_HOST:     $DEPLOY_HOST"
echo "   - DEPLOY_LEVEL:    $DEPLOY_LEVEL"
echo "   - TESTNET:         $TESTNET"
echo "   - ADMIN_EMAIL:     $ADMIN_EMAIL"
echo "   - ALERT_EMAIL:     $ALERT_EMAIL"
echo "   - DEPLOY_USER:     $DEPLOY_USER"
echo "   - BACKUP_KEY:      $BACKUP_KEY"
echo "   - BACKUP_SSH_KEY:  $BACKUP_SSH_KEY"
echo "   - BACKUP_HOST:     $BACKUP_HOST"
echo "   - SENDGRID_API_KEY:$SENDGRID_API_KEY"
echo "   - REMOTE_WAVES_NODES: $REMOTE_WAVES_NODES"
echo "   - ZAPD_ARCHIVE:    zapd.zip"

## ask user to continue
read -p "Are you sure? " -n 1 -r
echo # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
    ## do dangerous stuff
    echo ok lets go!!!
    ansible-playbook --inventory "$DEPLOY_HOST," --user "$DEPLOY_USER" -v \
        --extra-vars "ADMIN_EMAIL=$ADMIN_EMAIL ALERT_EMAIL=$ALERT_EMAIL DEPLOY_HOST=$DEPLOY_HOST BACKUP_KEY='$BACKUP_KEY' BACKUP_SSH_KEY='$BACKUP_SSH_KEY' BACKUP_HOST=$BACKUP_HOST SENDGRID_API_KEY=$SENDGRID_API_KEY REMOTE_WAVES_NODES=$REMOTE_WAVES_NODES KEYS_SUPPLIED=$KEYS_SUPPLIED FULL_DEPLOY=$FULL_DEPLOY VAGRANT=$VAGRANT TESTNET=$TESTNET SERVER_NAME=$DEPLOY_HOST" \
        ansible/deploy.yml
fi

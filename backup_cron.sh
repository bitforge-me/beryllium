#!/bin/bash

### source the environment
. <(xargs -0 bash -c 'printf "export %q\n" "$@"' -- < /proc/1/environ)

backup_dir="/opt/backup/temp"
result_dir="/var/log"
date_format=$(date "+%Y%m%dT%H%M%s")

WORKING_DIR=$backup_dir

if [ ! -d ${backup_dir} ]; then
    mkdir -p /opt/backup/temp
fi
if [[ -z ${B2_ACCOUNT_ID} || -v ${B2_ACCOUNT_ID} ]]; then
    echo "${date_format} - HOST ENVIRONMENT - B2_ACCOUNT_ID not configured" >> "${result_dir}/db_backup.log"
    exit 1
fi
if [[ -z ${B2_APPLICATION_KEY} || -v ${B2_APPLICATION_KEY} ]]; then
    echo "${date_format} - HOST ENVIRONMENT - B2_APPLICATION_KEY not configured" >> "${result_dir}/db_backup.log"
    exit 1
fi
if [[ -z ${BUCKET} || -v ${BUCKET} ]]; then
    echo "${date_format} - HOST ENVIRONMENT - BUCKET not configured" >> "${result_dir}/db_backup.log"
    exit 1
fi
if [[ -z ${BUCKET_DIR} || -v ${BUCKET_DIR} ]]; then
    echo "${date_format} - HOST ENVIRONMENT - BUCKET_DIR not configured" >> "${result_dir}/db_backup.log"
    exit 1
fi
#if [[ -z ${ENCRYPT_KEY} || -v ${ENCRYPT_KEY} ]]; then
#    echo "${date_format} - HOST ENVIRONMENT - ENCRYPT_KEY not configured" >> "${result_dir}/db_backup.log"
#    exit 1
#fi
#
if [[ -z ${DATABASE_URL} || -v ${DATABASE_URL} ]]; then
        echo "${date_format} - db backup failed. DATABASE_URL is not configured." >> "${result_dir}/db_backup.log"
else
    ### VARIABLES FROM THE DB CONNECTION STRING
    username=$(echo $DATABASE_URL|awk -F":" '{print $2}'|sed 's/\///g')
    password=$(echo $DATABASE_URL|awk -F":" '{print $3}'|sed 's/@.*//g')
    db_server=$(echo $DATABASE_URL|awk -F":" '{print $3}'|sed 's/.*@//g')
    port=$(echo $DATABASE_URL|awk -F":" '{print $4}'|sed 's/\/.*//g')
    database=$(echo $DATABASE_URL|awk -F":" '{print $4}'|sed 's/.*\///g')
    ### PERFORM THE DB BACKUP
    PGPASSWORD=${password} /usr/bin/pg_dump -h ${db_server} -p ${port} -U ${username} ${database} > "${backup_dir}/${database}.sql"
    ### CHECK THE COMMAND COMPLETED WITHOUT ERROR
    if [ $? = 0 ]; then
        echo "${date_format} - pg_dump backup successful" >> "${result_dir}/db_backup.log"
    else
        echo "${date_format} - pg_dump backup failed" >> "${result_dir}/db_backup.log"
    fi
    #### SEND BACKUP TO B2
    duplicity --full-if-older-than 7D --allow-source-mismatch --no-encryption ${WORKING_DIR} b2://${B2_ACCOUNT_ID}:${B2_APPLICATION_KEY}@${BUCKET}/${BUCKET_DIR}
    if [ $? = 0 ]; then
        echo "${date_format} - duplicity backup successful" >> "${result_dir}/db_backup.log"
    else
        echo "${date_format} - duplicity backup failed" >> "${result_dir}/db_backup.log"
    fi
fi

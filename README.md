## DB Migrations

Note: The first migration file was taken when the DB was at git revision `8acb5f22`. If you already have a database you should ensure your database container schema matches `8acb5f22` and then update to `b99fdbc8`, build images, update containers and run `./flask-cli.sh db stamp head` to tell flask-migrate that your database is starting from that state.

`./flask-cli.sh db upgrade` to apply new migrations to your database container (after updating the containers)

## App commands

`./app-cli.sh seed_db` seed the database with roles and permissions (once the initial migration is applied to the database you should do this)

`./app-cli.sh add_user <EMAIL> <PASSWORD` create a new user

`./app-cli.sh add_role <EMAIL> <ROLE` grant a role to a user

## C Lightning database replica

We use the `--wallet` flag (https://lightning.readthedocs.io/BACKUP.html#sqlite3-wallet-main-backup-and-remote-nfs-mount) in order to make a replica of the database. We can use sshfs to make the replica offsite.

### Setup

 - add `LIGHTNINGD_REPLICA=1` to the `.env` file
 - add the beryllium server ssh pubkey to the backup server authorized ssh keys (`~/.ssh/authorized_keys`)
 - install sshfs on the beryllium server (`apt install sshfs`)

### Test mounting the offsite directory

First setup the mount:
```
BE_SERVER_NAME=`hostname --fqdn`
LOCAL_REPLICA_DIR=`realpath lightningd/replica/`
# this needs to be an absolute directory
REMOTE_REPLICA_DIR={remote_user_home_dir}/$BE_SERVER_NAME
sshfs -o allow_other,default_permissions {remote_user}@{backup_server}:$REMOTE_REPLICA_DIR $REPLICA_DIR
```

Now restart the lightning container:
```
docker stop lightningd
docker compose up -d
```

Now check the replica exists locally and remote and have the same size and modified date:
```
# local
ls -l lightningd/replica/lightningd.sqlite3
# remote
ssh {remote_user}@{backup_server} ls -l $REMOTE_REPLICA_DIR/lightnind.sqlite3
```

### Make the mount permanent

Add the following to `/etc/fstab`:

```
{remote_user}@{backup_server}:{remote_replica_dir} {replica_dir} fuse.sshfs noauto,x-systemd.automount,_netdev,reconnect,identityfile=/{user_home_dir}/.ssh/id_rsa,allow_other,default_permissions 0 0
```

You can test the permenent mount by rebooting

### More info

https://www.digitalocean.com/community/tutorials/how-to-use-sshfs-to-mount-remote-file-systems-over-ssh
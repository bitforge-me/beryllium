# On the backup server
## add the ssh public key to the remote server(backup server)


# On the client server
## Add sshfs to the (client)server. ie. running the ligthningd app
Run the following in the host(not the container):
- sudo apt update
- sudo apt install sshfs

## create the mount dir
- sudo mkdir /mnt/{directory name}

## you should now be able to mount the directory using sshfs:
- sudo sshfs -o allow_other,default_permissions {user}@{backup_server ip}:/{path for shared_direcotry} /mnt/{directory name}

## edit /etc/fuse.conf and add the following line at the end:
user_allow_other

## edit the docker-compose.yml and edit the lightning replica directory and use the /mnt/{directory name}

## permanently by adding the following line via fstab:
sshfs#{user}@{backup_server ip}:/{shared directory} /mnt/{directory name} fuse IdentityFile=/{path to ssh dir}/id_rsa,allow_other,default_permissions 0 0

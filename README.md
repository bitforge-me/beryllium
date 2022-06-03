## DB Migrations

Note: The first migration file was taken when the DB was at git revision 1bad8a09. If you already have a database you should ensure your database container schema matches 1bad8a09 and then run `./flask-cli.sh db stamp head` to tell flask-migrate that your database is starting from that state.

`./flask-cli.sh db upgrade` to apply new migrations to your database container

## App commands

`./app-cli.sh seed_db` seed the database with roles and permissions (once the initial migration is applied to the database you should do this)

`./app-cli.sh add_user <EMAIL> <PASSWORD` create a new user

`./app-cli.sh add_role <EMAIL> <ROLE` grant a role to a user

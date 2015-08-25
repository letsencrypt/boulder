The `sql` files here define the database user relationships between
the various databases and services. Implementors should use these as
starting points for their own configuration. The actual schemas are
managed by [goose](https://bitbucket.org/liamstask/goose) and can be
found in `./ca/_db` and `./sa/_db`.

The currently supported database is MariaDB 10.

The databases that boulder requires to operate in development and
testing can be created using test/create\_db.sh. It uses the root
MariaDB user, so if you have disabled that account you may have to
adjust the file or recreate the commands.

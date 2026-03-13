These files are loaded by the bmariadb container on startup, using
the [/docker-entrypoint-initdb.d/ mechanism][1].

They are also used by the bvitess container, which takes the applicable subset
of them (the `boulder_sa`, `boulder_sa_next`, `incidents_sa`, and
`incidents_sa_next` schemas), greps out the `USE` statements, and incorporates
them into the `--schema-dir`.

[1]: https://hub.docker.com/_/mariadb#initializing-the-database-contents

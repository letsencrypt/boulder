# Boulder with Postgres

This branch adds Postgres support to Boulder. It needs to be cleaned up
significantly before it can be merged. The big diffs are:

 - It uses Postgres-style placeholders in queries: $1, $2, etc.
 - It adapts the QuestionMarks function to use Postgres-style placeholders.
 - The schema files are significantly changed to comply with Postgres syntax.

The schema setup is not automated as nicely as the main integration test, so
you'll need to do a little manual setup:

    docker compose up bpsql
    sudo apt install postgresql-client-16
    ./test/create_psql.sh
    ./t.sh -i

Integration tests currently fail when running expiration-mailer, because it
doesn't find any certificates to mail about. But issuance works correctly.

Log level for the SA is currently set to DEBUG, to be able to see all queries.
Any benchmarking should set a lower log level.

These `.sql` files define the table layout, indicies, relationships, and users default to Boulder. Implementors should use these as starting points for their own configuration.

## Notes

Currently, if you use MySQL / MariaDB with Boulder, you must manually append `?parseTime=true"` onto the end of the `dbConnect` configuration fields for each entry. This is related to [Issue #242](https://github.com/letsencrypt/boulder/issues/242).

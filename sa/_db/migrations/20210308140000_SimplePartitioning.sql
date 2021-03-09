
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

-- These partition statements all set a start value of 0 because these
-- commands are run against an test database with little to no data in it.

ALTER TABLE authz2 DROP INDEX token;
ALTER TABLE authz2 PARTITION BY RANGE(id) (
     PARTITION p_start VALUES LESS THAN MAXVALUE);

ALTER TABLE certificates DROP FOREIGN KEY IF EXISTS regId_certificates;
ALTER TABLE certificates DROP INDEX IF EXISTS serial, ADD INDEX serial (serial);
ALTER TABLE certificates PARTITION BY RANGE(id) (
    PARTITION p_start VALUES LESS THAN MAXVALUE);

ALTER TABLE fqdnSets DROP INDEX IF EXISTS serial, ADD INDEX serial (serial);
ALTER TABLE fqdnSets PARTITION BY RANGE(id) (
    PARTITION p_start VALUES LESS THAN MAXVALUE);

ALTER TABLE precertificates DROP FOREIGN KEY IF EXISTS regId_precertificates;
ALTER TABLE precertificates DROP INDEX IF EXISTS serial, ADD INDEX serial (serial);
ALTER TABLE precertificates PARTITION BY RANGE(id) (
    PARTITION p_start VALUES LESS THAN MAXVALUE);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE authz2 REMOVE PARTITIONING;
ALTER TABLE certificates REMOVE PARTITIONING;
ALTER TABLE fqdnSets REMOVE PARTITIONING;
ALTER TABLE precertificates REMOVE PARTITIONING;

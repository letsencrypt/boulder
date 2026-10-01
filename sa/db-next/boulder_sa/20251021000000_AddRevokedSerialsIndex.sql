-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `revokedCertificates` REMOVE PARTITIONING;
ALTER TABLE `revokedCertificates` ADD UNIQUE INDEX `serial` (`serial`);

-- +migrate Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `revokedCertificates` DROP UNIQUE INDEX `serial`;
ALTER TABLE `revokedCertificates` PARTITION BY RANGE(id)
(PARTITION p_start VALUES LESS THAN (MAXVALUE));

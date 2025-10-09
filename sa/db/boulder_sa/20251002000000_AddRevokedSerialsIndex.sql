-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `revokedCertificates` ADD KEY `serial` (`serial`);

-- +migrate Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `revokedCertificates` DROP KEY `serial`;

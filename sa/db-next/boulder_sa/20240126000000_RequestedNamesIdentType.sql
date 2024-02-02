
-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `requestedNames` ADD COLUMN `IdentType` TINYINT(4) DEFAULT 0 NOT NULL;
ALTER TABLE `issuedNames`ADD COLUMN `IdentType` TINYINT(4) DEFAULT 0 NOT NULL;

-- +migrate Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `requestedNames` DROP COLUMN `IdentType`;
ALTER TABLE `issuedNames` DROP COLUMN `IdentType`;
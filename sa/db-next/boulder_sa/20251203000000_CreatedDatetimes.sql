-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `authz2` ADD COLUMN `created` datetime DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE `orderFqdnSets` ADD COLUMN `created` datetime DEFAULT CURRENT_TIMESTAMP;

-- +migrate Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `authz2` DROP COLUMN `created`;
ALTER TABLE `orderFqdnSets` DROP COLUMN `created`;

-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `orders` ADD COLUMN `certificateProfileName` varchar(32) DEFAULT NULL;

-- +migrate Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `orders` DROP COLUMN `certificateProfileName`;
